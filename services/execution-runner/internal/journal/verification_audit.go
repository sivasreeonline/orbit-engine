package journal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VerificationAuditHead is the compare-and-append cursor for an audit ledger.
// The zero head is Sequence=0 with an empty RecordSHA256.
type VerificationAuditHead struct {
	Sequence     uint64 `json:"sequence"`
	RecordSHA256 string `json:"record_sha256"`
}

// VerificationAuditRecord is a hash-linked snapshot of one verification
// decision. It records failed as well as successful decisions.
type VerificationAuditRecord struct {
	Sequence       uint64                     `json:"sequence"`
	RecordID       string                     `json:"record_id"`
	PreviousSHA256 string                     `json:"previous_sha256"`
	RecordedAt     string                     `json:"recorded_at"`
	Report         EvidenceVerificationReport `json:"report"`
	RecordSHA256   string                     `json:"record_sha256"`
}

// VerificationAuditLedger is a storage contract, not a storage adapter.
// Append must compare the complete expected head and persist exactly one
// record atomically, or persist nothing.
type VerificationAuditLedger interface {
	ReadHead() (VerificationAuditHead, error)
	Append(record VerificationAuditRecord, expected VerificationAuditHead) error
}

func auditRecordBytes(record VerificationAuditRecord) ([]byte, error) {
	record.RecordSHA256 = ""
	return json.Marshal(record)
}

// SealVerificationAuditRecord assigns the next sequence and predecessor hash,
// then computes the record digest. It does not sign the record or make storage
// immutable.
func SealVerificationAuditRecord(record VerificationAuditRecord, previous VerificationAuditHead) (VerificationAuditRecord, error) {
	if strings.TrimSpace(record.RecordID) == "" || previous.Sequence == ^uint64(0) {
		return VerificationAuditRecord{}, fmt.Errorf("%w: audit record ID or sequence is invalid", ErrCorrupt)
	}
	if previous.Sequence == 0 && previous.RecordSHA256 != "" {
		return VerificationAuditRecord{}, fmt.Errorf("%w: empty audit head must have an empty digest", ErrCorrupt)
	}
	if previous.Sequence > 0 && !validAuditDigest(previous.RecordSHA256) {
		return VerificationAuditRecord{}, fmt.Errorf("%w: previous audit head digest is invalid", ErrCorrupt)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.RecordedAt); err != nil {
		return VerificationAuditRecord{}, fmt.Errorf("%w: audit record timestamp is invalid", ErrCorrupt)
	}
	if strings.TrimSpace(record.Report.PolicyID) == "" || strings.TrimSpace(record.Report.PolicyVersion) == "" ||
		strings.TrimSpace(record.Report.QualificationID) == "" || strings.TrimSpace(record.Report.VerifiedAt) == "" {
		return VerificationAuditRecord{}, fmt.Errorf("%w: verification report identity is incomplete", ErrCorrupt)
	}
	record.Sequence = previous.Sequence + 1
	record.PreviousSHA256 = previous.RecordSHA256
	record.RecordSHA256 = ""
	data, err := auditRecordBytes(record)
	if err != nil {
		return VerificationAuditRecord{}, fmt.Errorf("%w: cannot encode audit record", ErrCorrupt)
	}
	record.RecordSHA256 = digestHex(data)
	return record, nil
}

func validAuditDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ValidateVerificationAuditChain checks sequence continuity, predecessor
// links, record digests, and required identities. A valid chain detects
// modification/reordering relative to a trusted checkpoint; it cannot detect
// truncation or a rewritten fork without an independently retained checkpoint.
func ValidateVerificationAuditChain(records []VerificationAuditRecord) error {
	var previous VerificationAuditHead
	for index, record := range records {
		if record.Sequence != uint64(index)+1 {
			return fmt.Errorf("%w: audit sequence at index %d is not contiguous", ErrCorrupt, index)
		}
		if record.PreviousSHA256 != previous.RecordSHA256 {
			return fmt.Errorf("%w: audit predecessor mismatch at sequence %d", ErrCorrupt, record.Sequence)
		}
		if !validAuditDigest(record.RecordSHA256) {
			return fmt.Errorf("%w: audit record digest is invalid at sequence %d", ErrCorrupt, record.Sequence)
		}
		sealed, err := SealVerificationAuditRecord(record, previous)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sealed.RecordSHA256, record.RecordSHA256) {
			return fmt.Errorf("%w: audit record digest mismatch at sequence %d", ErrCorrupt, record.Sequence)
		}
		previous = VerificationAuditHead{Sequence: record.Sequence, RecordSHA256: record.RecordSHA256}
	}
	return nil
}

// ValidateVerificationAuditChainAgainstHead validates the supplied chain and
// requires its final head to match an independently retained checkpoint. This
// detects a valid-prefix rollback when the checkpoint is authentic and current.
func ValidateVerificationAuditChainAgainstHead(records []VerificationAuditRecord, expected VerificationAuditHead) error {
	if err := ValidateVerificationAuditChain(records); err != nil {
		return err
	}
	var actual VerificationAuditHead
	if len(records) > 0 {
		last := records[len(records)-1]
		actual = VerificationAuditHead{Sequence: last.Sequence, RecordSHA256: last.RecordSHA256}
	}
	if actual != expected {
		return fmt.Errorf("%w: audit chain head does not match trusted checkpoint", ErrCorrupt)
	}
	return nil
}
