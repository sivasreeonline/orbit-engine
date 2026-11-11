// Package conformance provides reusable test-only checks for implementations
// of journal.CheckpointCustodyStore. Import it from adapter test packages;
// production code must not use this package.
package conformance

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/journal"
)

// StoreFactory creates a fresh, isolated store for one conformance subtest.
// Adapter tests should register external-resource cleanup with t.Cleanup.
type StoreFactory func(t *testing.T) journal.CheckpointCustodyStore

// RunCheckpointCustodyStoreConformance exercises the portable behavioral
// contract shared by all checkpoint-custody adapters. It does not prove crash
// durability, provider-enforced retention, external-host fencing, or
// organizational independence; those require adapter-specific qualification.
func RunCheckpointCustodyStoreConformance(t *testing.T, newStore StoreFactory) {
	t.Helper()
	if newStore == nil {
		t.Fatal("store factory is required")
	}

	t.Run("checkpoint and receipt are an atomic matching pair", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		checkpoint := makeCheckpoint(t, "ledger-atomic", "epoch-a", 1, "", "a", time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
		otherCheckpoint := makeCheckpoint(t, "ledger-atomic", "epoch-a", 1, "", "b", time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
		mismatchedReceipt := makeReceipt(t, otherCheckpoint)

		if err := store.StoreIfCurrent(ctx, checkpoint, mismatchedReceipt, ""); err == nil {
			t.Fatal("store accepted a receipt bound to a different checkpoint")
		}
		if _, _, err := store.ReadLatest(ctx, "ledger-atomic", "epoch-a"); !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("mismatched pair left a partial record: read error = %v, want ErrNotFound", err)
		}

		receipt := makeReceipt(t, checkpoint)
		if err := store.StoreIfCurrent(ctx, checkpoint, receipt, ""); err != nil {
			t.Fatalf("store initial checkpoint/receipt pair: %v", err)
		}
		gotCheckpoint, gotReceipt, err := store.ReadLatest(ctx, "ledger-atomic", "epoch-a")
		if err != nil {
			t.Fatalf("read stored pair: %v", err)
		}
		assertPair(t, gotCheckpoint, gotReceipt, checkpoint, receipt)
	})

	t.Run("compare-and-store rejects stale writers and forks", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		previous := makeCheckpoint(t, "ledger-cas", "epoch-a", 1, "", "c", time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
		if err := store.StoreIfCurrent(ctx, previous, makeReceipt(t, previous), ""); err != nil {
			t.Fatalf("store initial checkpoint: %v", err)
		}
		previousDigest := journal.VerificationAuditCheckpointDigest(previous)
		first := makeCheckpoint(t, "ledger-cas", "epoch-a", 2, previousDigest, "d", time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC))
		second := makeCheckpoint(t, "ledger-cas", "epoch-a", 2, previousDigest, "e", time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC))

		type result struct {
			checkpoint journal.SignedVerificationAuditCheckpoint
			err        error
		}
		type candidatePair struct {
			checkpoint journal.SignedVerificationAuditCheckpoint
			receipt    journal.CheckpointCustodyReceipt
		}
		candidates := []candidatePair{
			{checkpoint: first, receipt: makeReceipt(t, first)},
			{checkpoint: second, receipt: makeReceipt(t, second)},
		}
		results := make(chan result, 2)
		var ready sync.WaitGroup
		ready.Add(2)
		start := make(chan struct{})
		for _, candidate := range candidates {
			candidate := candidate
			go func() {
				ready.Done()
				<-start
				results <- result{checkpoint: candidate.checkpoint, err: store.StoreIfCurrent(ctx, candidate.checkpoint, candidate.receipt, previousDigest)}
			}()
		}
		ready.Wait()
		close(start)

		var winner *journal.SignedVerificationAuditCheckpoint
		conflicts := 0
		for range 2 {
			outcome := <-results
			switch {
			case outcome.err == nil:
				copy := outcome.checkpoint
				winner = &copy
			case errors.Is(outcome.err, journal.ErrConflict):
				conflicts++
			default:
				t.Fatalf("concurrent successor returned unexpected error: %v", outcome.err)
			}
		}
		if winner == nil || conflicts != 1 {
			t.Fatalf("concurrent compare-and-store: winner=%t conflicts=%d, want one winner and one conflict", winner != nil, conflicts)
		}

		loser := first
		if journal.VerificationAuditCheckpointDigest(first) == journal.VerificationAuditCheckpointDigest(*winner) {
			loser = second
		}
		if err := store.StoreIfCurrent(ctx, loser, makeReceipt(t, loser), previousDigest); !errors.Is(err, journal.ErrConflict) {
			t.Fatalf("stale fork error = %v, want ErrConflict", err)
		}
		gotCheckpoint, gotReceipt, err := store.ReadLatest(ctx, "ledger-cas", "epoch-a")
		if err != nil {
			t.Fatalf("read winning head: %v", err)
		}
		assertPair(t, gotCheckpoint, gotReceipt, *winner, makeReceipt(t, *winner))
	})

	t.Run("ledger and epoch namespaces are isolated", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		first := makeCheckpoint(t, "ledger-one", "epoch-one", 1, "", "f", time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
		second := makeCheckpoint(t, "ledger-two", "epoch-two", 1, "", "1", time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC))
		if err := store.StoreIfCurrent(ctx, first, makeReceipt(t, first), ""); err != nil {
			t.Fatalf("store first ledger: %v", err)
		}
		if err := store.StoreIfCurrent(ctx, second, makeReceipt(t, second), ""); err != nil {
			t.Fatalf("store second ledger/epoch: %v", err)
		}
		gotFirst, receiptFirst, err := store.ReadLatest(ctx, "ledger-one", "epoch-one")
		if err != nil {
			t.Fatalf("read first ledger: %v", err)
		}
		assertPair(t, gotFirst, receiptFirst, first, makeReceipt(t, first))
		gotSecond, receiptSecond, err := store.ReadLatest(ctx, "ledger-two", "epoch-two")
		if err != nil {
			t.Fatalf("read second ledger: %v", err)
		}
		assertPair(t, gotSecond, receiptSecond, second, makeReceipt(t, second))
		if _, _, err := store.ReadLatest(ctx, "ledger-one", "epoch-two"); !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("cross-epoch lookup error = %v, want ErrNotFound", err)
		}
	})
}


func deterministicKey(seed byte) ed25519.PrivateKey {
	material := make([]byte, ed25519.SeedSize)
	for i := range material {
		material[i] = seed
	}
	return ed25519.NewKeyFromSeed(material)
}

func makeCheckpoint(t *testing.T, ledgerID, epoch string, sequence uint64, previous, recordMarker string, createdAt time.Time) journal.SignedVerificationAuditCheckpoint {
	t.Helper()
	privateKey := deterministicKey(31)
	checkpoint, err := journal.SealVerificationAuditCheckpoint(journal.VerificationAuditCheckpointPayload{
		LedgerID: ledgerID, LedgerEpoch: epoch, Sequence: sequence,
		RecordSHA256: strings.Repeat(recordMarker, 64),
		CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
		PreviousCheckpointSHA256: previous, PolicyVersion: "conformance-policy-v1",
	}, "conformance-checkpoint-signer", journal.VerificationCheckpointSignerRole, "conformance-checkpoint-key", privateKey)
	if err != nil {
		t.Fatalf("seal conformance checkpoint: %v", err)
	}
	return checkpoint
}

func makeReceipt(t *testing.T, checkpoint journal.SignedVerificationAuditCheckpoint) journal.CheckpointCustodyReceipt {
	t.Helper()
	privateKey := deterministicKey(32)
	createdAt, err := time.Parse(time.RFC3339Nano, checkpoint.Payload.CreatedAt)
	if err != nil {
		t.Fatalf("parse conformance checkpoint time: %v", err)
	}
	retainedAt := createdAt.Add(time.Minute)
	receipt, err := journal.SealCheckpointCustodyReceipt(
		checkpoint, "conformance-custody-domain", "conformance-retention-policy", "v1",
		retainedAt.Format(time.RFC3339Nano), retainedAt.Add(90*24*time.Hour).Format(time.RFC3339Nano),
		"conformance-custodian", "conformance-custodian-key", privateKey,
	)
	if err != nil {
		t.Fatalf("seal conformance custody receipt: %v", err)
	}
	return receipt
}

func assertPair(t *testing.T, checkpoint journal.SignedVerificationAuditCheckpoint, receipt journal.CheckpointCustodyReceipt, expected journal.SignedVerificationAuditCheckpoint, expectedReceipt journal.CheckpointCustodyReceipt) {
	t.Helper()
	if journal.VerificationAuditCheckpointDigest(checkpoint) != journal.VerificationAuditCheckpointDigest(expected) {
		t.Fatal("stored checkpoint digest does not match expected checkpoint")
	}
	if receipt.CheckpointSHA256 != journal.VerificationAuditCheckpointDigest(checkpoint) {
		t.Fatal("stored receipt is not bound to the stored checkpoint")
	}
	if receipt.ReceiptSHA256 != expectedReceipt.ReceiptSHA256 || receipt.SignatureHex != expectedReceipt.SignatureHex {
		t.Fatal("stored custody receipt differs from the committed receipt")
	}
}
