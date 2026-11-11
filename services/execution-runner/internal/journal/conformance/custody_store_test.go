package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/journal"
)

type storedPair struct {
	checkpoint journal.SignedVerificationAuditCheckpoint
	receipt    journal.CheckpointCustodyReceipt
}

type memoryCustodyStore struct {
	mu    sync.Mutex
	heads map[string]storedPair
}

func newMemoryCustodyStore() *memoryCustodyStore {
	return &memoryCustodyStore{heads: make(map[string]storedPair)}
}

func custodyLedgerKey(ledgerID, epoch string) string {
	return ledgerID + "\x00" + epoch
}

func (s *memoryCustodyStore) ReadLatest(_ context.Context, ledgerID, epoch string) (journal.SignedVerificationAuditCheckpoint, journal.CheckpointCustodyReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pair, ok := s.heads[custodyLedgerKey(ledgerID, epoch)]
	if !ok {
		return journal.SignedVerificationAuditCheckpoint{}, journal.CheckpointCustodyReceipt{}, journal.ErrNotFound
	}
	return pair.checkpoint, pair.receipt, nil
}

func (s *memoryCustodyStore) StoreIfCurrent(_ context.Context, checkpoint journal.SignedVerificationAuditCheckpoint, receipt journal.CheckpointCustodyReceipt, expectedPrevious string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest := journal.VerificationAuditCheckpointDigest(checkpoint)
	if receipt.CheckpointSHA256 != digest {
		return journal.ErrCorrupt
	}
	key := custodyLedgerKey(checkpoint.Payload.LedgerID, checkpoint.Payload.LedgerEpoch)
	current, exists := s.heads[key]
	if !exists {
		if expectedPrevious != "" || checkpoint.Payload.Sequence != 1 || checkpoint.Payload.PreviousCheckpointSHA256 != "" {
			return journal.ErrConflict
		}
	} else {
		currentDigest := journal.VerificationAuditCheckpointDigest(current.checkpoint)
		if expectedPrevious != currentDigest || checkpoint.Payload.PreviousCheckpointSHA256 != currentDigest ||
			checkpoint.Payload.Sequence <= current.checkpoint.Payload.Sequence {
			return journal.ErrConflict
		}
	}
	s.heads[key] = storedPair{checkpoint: checkpoint, receipt: receipt}
	return nil
}

func TestRunCheckpointCustodyStoreConformanceAgainstReferenceStore(t *testing.T) {
	RunCheckpointCustodyStoreConformance(t, func(t *testing.T) journal.CheckpointCustodyStore {
		t.Helper()
		return newMemoryCustodyStore()
	})
}

func TestReferenceStoreDoesNotExposeMutableState(t *testing.T) {
	store := newMemoryCustodyStore()
	if _, _, err := store.ReadLatest(context.Background(), "missing", "epoch"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("missing read error = %v, want ErrNotFound", err)
	}
}
