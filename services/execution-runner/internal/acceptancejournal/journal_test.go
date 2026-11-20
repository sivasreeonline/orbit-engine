package acceptancejournal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testReceipt() Receipt {
	return Receipt{
		AcceptanceID: "90000000-0000-4000-8000-000000000001",
		DispatchID:   "50000000-0000-4000-8000-000000000001",
		ExecutionID:  "60000000-0000-4000-8000-000000000001",
		AttemptID:    "70000000-0000-4000-8000-000000000001",
		LeaseToken:   "80000000-0000-4000-8000-000000000001",
		PreparedAt:   time.Date(2026, 11, 13, 3, 0, 0, 0, time.UTC),
	}
}

func TestPreparePersistsBeforeReturnAndSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "acceptance.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt()

	replayed, err := journal.Prepare(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if replayed {
		t.Fatal("first prepare must not be marked as a replay")
	}

	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].AcceptanceID != receipt.AcceptanceID {
		t.Fatalf("unexpected pending receipts: %#v", pending)
	}

	// The prepared timestamp is local metadata, not part of the signed receipt.
	// Reconstructing the same identity after a restart remains idempotent.
	retry := receipt
	retry.PreparedAt = retry.PreparedAt.Add(time.Minute)
	replayed, err = journal.Prepare(retry)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed {
		t.Fatal("same acceptance identity should be an idempotent replay")
	}

	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	recovered, ok, err := journal.Find(receipt.DispatchID, receipt.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || recovered.AcceptanceID != receipt.AcceptanceID {
		t.Fatalf("receipt was not recovered: %#v, found=%v", recovered, ok)
	}
}

func TestConfirmationIsAppendOnlyAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acceptance.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	receipt := testReceipt()
	if _, err := journal.Prepare(receipt); err != nil {
		t.Fatal(err)
	}
	eventID := "a0000000-0000-4000-8000-000000000001"
	confirmedAt := time.Date(2026, 11, 13, 3, 1, 0, 0, time.UTC)

	replayed, err := journal.Confirm(receipt.AcceptanceID, eventID, confirmedAt)
	if err != nil || replayed {
		t.Fatalf("first confirmation: replayed=%v err=%v", replayed, err)
	}
	replayed, err = journal.Confirm(receipt.AcceptanceID, eventID, confirmedAt.Add(time.Minute))
	if err != nil || !replayed {
		t.Fatalf("duplicate confirmation: replayed=%v err=%v", replayed, err)
	}
	if _, err := journal.Confirm(receipt.AcceptanceID, "b0000000-0000-4000-8000-000000000001", confirmedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflicting event ID, got %v", err)
	}

	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("confirmed receipt still pending: %#v", pending)
	}
}

func TestIncompleteFinalRecordIsTruncatedOnRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acceptance.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt()
	if _, err := journal.Prepare(receipt); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"version":1,"type":"PREPARED"`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	journal, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].AcceptanceID != receipt.AcceptanceID {
		t.Fatalf("recovery lost the last complete receipt: %#v", pending)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		t.Fatal("incomplete tail was not truncated to the last complete record")
	}
}

func TestRejectsConflictingReceiptForSameDispatchLease(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "acceptance.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	receipt := testReceipt()
	if _, err := journal.Prepare(receipt); err != nil {
		t.Fatal(err)
	}
	conflict := receipt
	conflict.AcceptanceID = "90000000-0000-4000-8000-000000000002"
	if _, err := journal.Prepare(conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected lease conflict, got %v", err)
	}
}

func TestJournalUsesPrivateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acceptance.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestInvalidReceiptAndMissingConfirmationFailClosed(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "acceptance.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	receipt := testReceipt()
	receipt.LeaseToken = "not-a-uuid"
	if _, err := journal.Prepare(receipt); err == nil {
		t.Fatal("invalid receipt was accepted")
	}
	if _, err := journal.Confirm(
		"90000000-0000-4000-8000-000000000001",
		"a0000000-0000-4000-8000-000000000001",
		time.Now(),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing receipt error, got %v", err)
	}
}


func TestAbandonedStaleReceiptRemainsAuditableButIsNotPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acceptance.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt()
	if _, err := journal.Prepare(receipt); err != nil {
		t.Fatal(err)
	}
	abandonedAt := time.Date(2026, 11, 13, 3, 2, 0, 0, time.UTC)
	replayed, err := journal.Abandon(receipt.AcceptanceID, "RUNNER_LEASE_STALE", abandonedAt)
	if err != nil || replayed {
		t.Fatalf("first abandonment: replayed=%v err=%v", replayed, err)
	}
	replayed, err = journal.Abandon(receipt.AcceptanceID, "RUNNER_LEASE_STALE", abandonedAt.Add(time.Minute))
	if err != nil || !replayed {
		t.Fatalf("idempotent abandonment: replayed=%v err=%v", replayed, err)
	}
	if _, err := journal.Confirm(
		receipt.AcceptanceID,
		"a0000000-0000-4000-8000-000000000001",
		abandonedAt,
	); !errors.Is(err, ErrAbandoned) {
		t.Fatalf("abandoned receipt must not be confirmed: %v", err)
	}
	if _, err := journal.Prepare(receipt); !errors.Is(err, ErrAbandoned) {
		t.Fatalf("abandoned receipt must not be prepared again: %v", err)
	}
	pending, err := journal.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("abandoned receipt still pending: pending=%d err=%v", len(pending), err)
	}
	abandoned, err := journal.IsAbandoned(receipt.AcceptanceID)
	if err != nil || !abandoned {
		t.Fatalf("receipt abandonment missing: abandoned=%v err=%v", abandoned, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	abandoned, err = journal.IsAbandoned(receipt.AcceptanceID)
	if err != nil || !abandoned {
		t.Fatalf("abandonment did not survive restart: abandoned=%v err=%v", abandoned, err)
	}
	pending, err = journal.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatalf("recovered abandoned receipt became pending: pending=%d err=%v", len(pending), err)
	}
}

func TestAbandonmentRejectsUnknownReasonsAndConfirmedReceipts(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "acceptance.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	receipt := testReceipt()
	if _, err := journal.Prepare(receipt); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := journal.Abandon(receipt.AcceptanceID, "NETWORK_TIMEOUT", now); err == nil {
		t.Fatal("temporary transport error was accepted as a terminal abandonment reason")
	}
	if _, err := journal.Confirm(
		receipt.AcceptanceID,
		"a0000000-0000-4000-8000-000000000001",
		now,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Abandon(receipt.AcceptanceID, "RUNNER_LEASE_STALE", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("confirmed receipt was abandonable: %v", err)
	}
}
