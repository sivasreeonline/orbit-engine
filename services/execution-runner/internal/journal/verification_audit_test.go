package journal

import (
	"errors"
	"testing"
	"time"
)

func auditFixture(id string, ready bool) VerificationAuditRecord {
	return VerificationAuditRecord{
		RecordID:id, RecordedAt:"2026-11-11T10:00:00Z",
		Report:EvidenceVerificationReport{
			PolicyID:"policy", PolicyVersion:"v1", QualificationID:"qualification",
			ManifestSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ReviewerIdentity:"reviewer", ReviewerKeyID:"key-1",
			VerifiedAt:"2026-11-11T09:59:00Z", Ready:ready, Findings:[]string{},
		},
	}
}

func TestSealAndValidateVerificationAuditChain(t *testing.T) {
	t.Parallel()
	first, err := SealVerificationAuditRecord(auditFixture("record-1", true), VerificationAuditHead{})
	if err != nil { t.Fatalf("seal first: %v", err) }
	head := VerificationAuditHead{Sequence:first.Sequence, RecordSHA256:first.RecordSHA256}
	second, err := SealVerificationAuditRecord(auditFixture("record-2", false), head)
	if err != nil { t.Fatalf("seal second: %v", err) }
	if err := ValidateVerificationAuditChain([]VerificationAuditRecord{first, second}); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestVerificationAuditChainRejectsModifiedReport(t *testing.T) {
	t.Parallel()
	record, err := SealVerificationAuditRecord(auditFixture("record-1", true), VerificationAuditHead{})
	if err != nil { t.Fatal(err) }
	record.Report.Ready = false
	if err := ValidateVerificationAuditChain([]VerificationAuditRecord{record}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerificationAuditChainRejectsReordering(t *testing.T) {
	t.Parallel()
	first, _ := SealVerificationAuditRecord(auditFixture("record-1", true), VerificationAuditHead{})
	second, _ := SealVerificationAuditRecord(auditFixture("record-2", false), VerificationAuditHead{Sequence:1, RecordSHA256:first.RecordSHA256})
	if err := ValidateVerificationAuditChain([]VerificationAuditRecord{second, first}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerificationAuditChainRejectsTruncationOnlyWithCheckpoint(t *testing.T) {
	t.Parallel()
	first, _ := SealVerificationAuditRecord(auditFixture("record-1", true), VerificationAuditHead{})
	second, _ := SealVerificationAuditRecord(auditFixture("record-2", true), VerificationAuditHead{Sequence:1, RecordSHA256:first.RecordSHA256})
	if err := ValidateVerificationAuditChain([]VerificationAuditRecord{first}); err != nil {
		t.Fatalf("prefix itself is internally valid: %v", err)
	}
	if second.Sequence != 2 || second.PreviousSHA256 != first.RecordSHA256 {
		t.Fatal("fixture must represent a second externally checkpointed record")
	}
}

func TestSealVerificationAuditRecordRejectsMalformedPreviousHead(t *testing.T) {
	t.Parallel()
	_, err := SealVerificationAuditRecord(auditFixture("record-1", true), VerificationAuditHead{Sequence:3, RecordSHA256:"bad"})
	if !errors.Is(err, ErrCorrupt) { t.Fatalf("error = %v, want ErrCorrupt", err) }
}

func TestSealVerificationAuditRecordRejectsInvalidTimestamp(t *testing.T) {
	t.Parallel()
	record := auditFixture("record-1", true)
	record.RecordedAt = "not-a-time"
	if _, err := SealVerificationAuditRecord(record, VerificationAuditHead{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

// memoryVerificationLedger models compare-and-append semantics for contract
// tests only; it does not establish durable or immutable storage behavior.
type memoryVerificationLedger struct { records []VerificationAuditRecord }
func (m *memoryVerificationLedger) ReadHead() (VerificationAuditHead, error) {
	if len(m.records)==0 { return VerificationAuditHead{}, nil }
	last:=m.records[len(m.records)-1]
	return VerificationAuditHead{Sequence:last.Sequence,RecordSHA256:last.RecordSHA256},nil
}
func (m *memoryVerificationLedger) Append(record VerificationAuditRecord, expected VerificationAuditHead) error {
	head,_:=m.ReadHead()
	if head!=expected { return ErrConflict }
	if record.Sequence!=head.Sequence+1 || record.PreviousSHA256!=head.RecordSHA256 { return ErrConflict }
	if err:=ValidateVerificationAuditChain(append(append([]VerificationAuditRecord{},m.records...),record)); err!=nil { return err }
	m.records=append(m.records,record)
	return nil
}
func TestVerificationAuditLedgerRejectsStaleAppendHead(t *testing.T) {
	t.Parallel()
	ledger:=&memoryVerificationLedger{}
	first,err:=SealVerificationAuditRecord(auditFixture("record-1",true),VerificationAuditHead{})
	if err!=nil { t.Fatal(err) }
	if err:=ledger.Append(first,VerificationAuditHead{}); err!=nil { t.Fatal(err) }
	second,err:=SealVerificationAuditRecord(auditFixture("record-2",true),VerificationAuditHead{Sequence:1,RecordSHA256:first.RecordSHA256})
	if err!=nil { t.Fatal(err) }
	if err:=ledger.Append(second,VerificationAuditHead{}); !errors.Is(err,ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict",err)
	}
}
