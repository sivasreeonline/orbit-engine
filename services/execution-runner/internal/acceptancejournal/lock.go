package acceptancejournal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrJournalLocked = errors.New("acceptance journal already has an owner")

const journalLockVersion = 1

type journalLockOwner struct {
	Version   int       `json:"version"`
	PID       int       `json:"pid"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"createdAt"`
}

type journalLock struct {
	path  string
	token string
	mu    sync.Mutex
	done  bool
}

// acquireJournalLock uses atomic directory creation as a portable,
// fail-closed single-process ownership gate. A lock left by a crash is never
// removed automatically; an operator must verify that no runner owns the
// journal before deleting the stale lock directory.
func acquireJournalLock(journalPath string) (*journalLock, error) {
	lockPath := journalPath + ".lock"
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrJournalLocked, lockPath)
		}
		return nil, fmt.Errorf("create acceptance journal ownership lock: %w", err)
	}

	tokenBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		_ = os.Remove(lockPath)
		return nil, fmt.Errorf("generate acceptance journal lock token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	owner := journalLockOwner{
		Version:   journalLockVersion,
		PID:       os.Getpid(),
		Token:     token,
		CreatedAt: time.Now().UTC(),
	}
	payload, err := json.Marshal(owner)
	if err != nil {
		_ = os.Remove(lockPath)
		return nil, fmt.Errorf("encode acceptance journal lock owner: %w", err)
	}
	ownerPath := filepath.Join(lockPath, "owner.json")
	file, err := os.OpenFile(ownerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create acceptance journal lock owner: %w", err)
	}
	written, writeErr := file.Write(payload)
	if writeErr == nil && written != len(payload) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		// Preserve the lock on uncertain persistence. Removing it could allow a
		// second process to open the journal while this process's state is
		// ambiguous; operator recovery is intentionally required.
		return nil, errors.Join(
			wrapIfErr("write acceptance journal lock owner", writeErr),
			wrapIfErr("close acceptance journal lock owner", closeErr),
		)
	}
	if err := syncDirectory(lockPath); err != nil {
		return nil, fmt.Errorf("sync acceptance journal lock owner: %w", err)
	}
	if err := syncDirectory(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("sync acceptance journal lock directory entry: %w", err)
	}
	return &journalLock{path: lockPath, token: token}, nil
}

func (lock *journalLock) Release() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.done {
		return nil
	}

	info, err := os.Lstat(lock.path)
	if err != nil {
		return fmt.Errorf("inspect acceptance journal lock before release: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("acceptance journal lock path changed ownership type")
	}

	entries, err := os.ReadDir(lock.path)
	if err != nil {
		return fmt.Errorf("read acceptance journal lock before release: %w", err)
	}
	if len(entries) != 1 || entries[0].Name() != "owner.json" || entries[0].IsDir() {
		return errors.New("acceptance journal lock contains unexpected entries; refusing release")
	}

	ownerPath := filepath.Join(lock.path, "owner.json")
	ownerInfo, err := os.Lstat(ownerPath)
	if err != nil {
		return fmt.Errorf("inspect acceptance journal lock owner: %w", err)
	}
	if ownerInfo.Mode()&os.ModeSymlink != 0 || !ownerInfo.Mode().IsRegular() ||
		ownerInfo.Mode().Perm() != 0o600 {
		return errors.New("acceptance journal lock owner file is not a private regular file")
	}
	payload, err := os.ReadFile(ownerPath)
	if err != nil {
		return fmt.Errorf("read acceptance journal lock owner: %w", err)
	}
	var owner journalLockOwner
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&owner); err != nil {
		return fmt.Errorf("decode acceptance journal lock owner: %w", err)
	}
	if owner.Version != journalLockVersion || owner.Token != lock.token ||
		owner.PID != os.Getpid() || owner.CreatedAt.IsZero() {
		return errors.New("acceptance journal lock owner changed; refusing release")
	}

	if err := os.Remove(ownerPath); err != nil {
		return fmt.Errorf("remove acceptance journal lock owner: %w", err)
	}
	if err := os.Remove(lock.path); err != nil {
		return fmt.Errorf("remove acceptance journal lock directory: %w", err)
	}
	if err := syncDirectory(filepath.Dir(lock.path)); err != nil {
		return fmt.Errorf("sync acceptance journal lock release: %w", err)
	}
	lock.done = true
	return nil
}

func wrapIfErr(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
