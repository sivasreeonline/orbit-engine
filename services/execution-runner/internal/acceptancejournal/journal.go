package acceptancejournal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	formatVersion  = 1
	maxJournalSize = 64 << 20
)

var (
	ErrConflict   = errors.New("acceptance journal conflict")
	ErrNotFound   = errors.New("acceptance receipt not found")
	ErrJournalFull = errors.New("acceptance journal reached its configured size limit")
)

type Receipt struct {
	AcceptanceID string    `json:"acceptanceId"`
	DispatchID   string    `json:"dispatchId"`
	ExecutionID  string    `json:"executionId"`
	AttemptID    string    `json:"attemptId"`
	LeaseToken   string    `json:"leaseToken"`
	PreparedAt   time.Time `json:"preparedAt"`
}

type journalEvent struct {
	Version       int        `json:"version"`
	Type          string     `json:"type"`
	Receipt       *Receipt   `json:"receipt,omitempty"`
	AcceptanceID  string     `json:"acceptanceId,omitempty"`
	EventID       string     `json:"eventId,omitempty"`
	ConfirmedAt   *time.Time `json:"confirmedAt,omitempty"`
}

type Confirmation struct {
	AcceptanceID string
	EventID      string
	ConfirmedAt  time.Time
}

type Journal struct {
	mu          sync.Mutex
	file        *os.File
	path        string
	receipts    map[string]Receipt
	leaseIndex  map[string]string
	confirmations map[string]Confirmation
	closed      bool
}

func Open(path string) (*Journal, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("acceptance journal path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create acceptance journal directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("acceptance journal path must be a regular file, not a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect acceptance journal: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open acceptance journal: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure acceptance journal permissions: %w", err)
	}

	journal := &Journal{
		file: file,
		path: path,
		receipts: make(map[string]Receipt),
		leaseIndex: make(map[string]string),
		confirmations: make(map[string]Confirmation),
	}
	if err := journal.recoverLocked(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

// Prepare fsyncs a receipt before returning. Callers must not send the receipt
// to the control plane unless this method succeeds.
func (j *Journal) Prepare(receipt Receipt) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ensureOpen(); err != nil {
		return false, err
	}
	receipt.PreparedAt = receipt.PreparedAt.UTC()
	if err := validateReceipt(receipt); err != nil {
		return false, err
	}
	if existing, ok := j.receipts[receipt.AcceptanceID]; ok {
		if !sameReceipt(existing, receipt) {
			return false, ErrConflict
		}
		return true, nil
	}
	leaseKey := receipt.DispatchID + ":" + receipt.LeaseToken
	if existingID, ok := j.leaseIndex[leaseKey]; ok && existingID != receipt.AcceptanceID {
		return false, ErrConflict
	}

	event := journalEvent{
		Version: formatVersion,
		Type:    "PREPARED",
		Receipt: &receipt,
	}
	if err := j.appendLocked(event); err != nil {
		return false, err
	}
	j.receipts[receipt.AcceptanceID] = receipt
	j.leaseIndex[leaseKey] = receipt.AcceptanceID
	return false, nil
}

// Confirm records the control-plane acceptance event after the runner has
// received a successful response. Confirmation is append-only and idempotent.
func (j *Journal) Confirm(acceptanceID, eventID string, confirmedAt time.Time) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ensureOpen(); err != nil {
		return false, err
	}
	if !isUUID(acceptanceID) || !isUUID(eventID) || confirmedAt.IsZero() {
		return false, errors.New("invalid acceptance confirmation")
	}
	if _, ok := j.receipts[acceptanceID]; !ok {
		return false, ErrNotFound
	}
	confirmedAt = confirmedAt.UTC()
	if existing, ok := j.confirmations[acceptanceID]; ok {
		if existing.EventID != eventID || !existing.ConfirmedAt.Equal(confirmedAt) {
			return false, ErrConflict
		}
		return true, nil
	}
	event := journalEvent{
		Version:      formatVersion,
		Type:         "CONFIRMED",
		AcceptanceID: acceptanceID,
		EventID:      eventID,
		ConfirmedAt:  &confirmedAt,
	}
	if err := j.appendLocked(event); err != nil {
		return false, err
	}
	j.confirmations[acceptanceID] = Confirmation{
		AcceptanceID: acceptanceID,
		EventID:      eventID,
		ConfirmedAt:  confirmedAt,
	}
	return false, nil
}

// Pending returns prepared receipts whose durable control-plane confirmation
// has not yet been journaled. The caller may safely retry each with a fresh
// signed HTTP nonce and the same acceptanceId/body.
func (j *Journal) Pending() ([]Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.ensureOpen(); err != nil {
		return nil, err
	}
	pending := make([]Receipt, 0, len(j.receipts))
	for id, receipt := range j.receipts {
		if _, confirmed := j.confirmations[id]; !confirmed {
			pending = append(pending, receipt)
		}
	}
	sort.Slice(pending, func(i, k int) bool {
		if pending[i].PreparedAt.Equal(pending[k].PreparedAt) {
			return pending[i].AcceptanceID < pending[k].AcceptanceID
		}
		return pending[i].PreparedAt.Before(pending[k].PreparedAt)
	})
	return pending, nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if err := j.file.Sync(); err != nil {
		_ = j.file.Close()
		return fmt.Errorf("sync acceptance journal on close: %w", err)
	}
	return j.file.Close()
}

func (j *Journal) appendLocked(event journalEvent) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode acceptance journal event: %w", err)
	}
	line = append(line, '\n')
	info, err := j.file.Stat()
	if err != nil {
		return fmt.Errorf("stat acceptance journal: %w", err)
	}
	if info.Size()+int64(len(line)) > maxJournalSize {
		return ErrJournalFull
	}
	written, err := j.file.Write(line)
	if err != nil || written != len(line) {
		_ = j.recoverLocked()
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("append acceptance journal event: %w", err)
	}
	if err := j.file.Sync(); err != nil {
		_ = j.recoverLocked()
		return fmt.Errorf("sync acceptance journal event: %w", err)
	}
	return nil
}

func (j *Journal) recoverLocked() error {
	if _, err := j.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek acceptance journal: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(j.file, maxJournalSize+1))
	if err != nil {
		return fmt.Errorf("read acceptance journal: %w", err)
	}
	if len(contents) > maxJournalSize {
		return ErrJournalFull
	}

	lastNewline := bytes.LastIndexByte(contents, '\n')
	validLength := lastNewline + 1
	if validLength != len(contents) {
		// A process may crash during a write. Only an incomplete final line is
		// discarded; malformed complete records are treated as corruption.
		if err := j.file.Truncate(int64(validLength)); err != nil {
			return fmt.Errorf("truncate incomplete acceptance journal tail: %w", err)
		}
		if err := j.file.Sync(); err != nil {
			return fmt.Errorf("sync recovered acceptance journal: %w", err)
		}
		contents = contents[:validLength]
	}

	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return fmt.Errorf("acceptance journal contains an empty record at line %d", lineNumber)
		}
		var event journalEvent
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return fmt.Errorf("decode acceptance journal line %d: %w", lineNumber, err)
		}
		if err := applyEvent(j, event); err != nil {
			return fmt.Errorf("validate acceptance journal line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan acceptance journal: %w", err)
	}
	_, err = j.file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek acceptance journal end: %w", err)
	}
	return nil
}

func applyEvent(j *Journal, event journalEvent) error {
	if event.Version != formatVersion {
		return errors.New("unsupported acceptance journal version")
	}
	switch event.Type {
	case "PREPARED":
		if event.Receipt == nil || event.AcceptanceID != "" ||
			event.EventID != "" || event.ConfirmedAt != nil {
			return errors.New("invalid PREPARED journal event")
		}
		receipt := *event.Receipt
		receipt.PreparedAt = receipt.PreparedAt.UTC()
		if err := validateReceipt(receipt); err != nil {
			return err
		}
		if existing, ok := j.receipts[receipt.AcceptanceID]; ok {
			if !sameReceipt(existing, receipt) {
				return ErrConflict
			}
			return nil
		}
		leaseKey := receipt.DispatchID + ":" + receipt.LeaseToken
		if existingID, ok := j.leaseIndex[leaseKey]; ok && existingID != receipt.AcceptanceID {
			return ErrConflict
		}
		j.receipts[receipt.AcceptanceID] = receipt
		j.leaseIndex[leaseKey] = receipt.AcceptanceID
	case "CONFIRMED":
		if event.Receipt != nil || !isUUID(event.AcceptanceID) ||
			!isUUID(event.EventID) || event.ConfirmedAt == nil ||
			event.ConfirmedAt.IsZero() {
			return errors.New("invalid CONFIRMED journal event")
		}
		if _, ok := j.receipts[event.AcceptanceID]; !ok {
			return ErrNotFound
		}
		confirmation := Confirmation{
			AcceptanceID: event.AcceptanceID,
			EventID: event.EventID,
			ConfirmedAt: event.ConfirmedAt.UTC(),
		}
		if existing, ok := j.confirmations[event.AcceptanceID]; ok {
			if existing.EventID != confirmation.EventID ||
				!existing.ConfirmedAt.Equal(confirmation.ConfirmedAt) {
				return ErrConflict
			}
			return nil
		}
		j.confirmations[event.AcceptanceID] = confirmation
	default:
		return errors.New("unknown acceptance journal event type")
	}
	return nil
}

func (j *Journal) ensureOpen() error {
	if j.closed || j.file == nil {
		return errors.New("acceptance journal is closed")
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if !isUUID(receipt.AcceptanceID) || !isUUID(receipt.DispatchID) ||
		!isUUID(receipt.ExecutionID) || !isUUID(receipt.AttemptID) ||
		!isUUID(receipt.LeaseToken) || receipt.PreparedAt.IsZero() {
		return errors.New("invalid acceptance receipt")
	}
	return nil
}

func sameReceipt(left, right Receipt) bool {
	return left.AcceptanceID == right.AcceptanceID &&
		left.DispatchID == right.DispatchID &&
		left.ExecutionID == right.ExecutionID &&
		left.AttemptID == right.AttemptID &&
		left.LeaseToken == right.LeaseToken &&
		left.PreparedAt.Equal(right.PreparedAt)
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F')) {
				return false
			}
		}
	}
	return true
}
