package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func checkpointFixture(t *testing.T, principal, keyID string, privateKey ed25519.PrivateKey, sequence uint64, previousDigest string, createdAt string) SignedVerificationAuditCheckpoint {
	t.Helper()
	checkpoint, err := SealVerificationAuditCheckpoint(VerificationAuditCheckpointPayload{
		LedgerID: "ledger-a", LedgerEpoch: "epoch-1", Sequence: sequence,
		RecordSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CreatedAt: createdAt, PreviousCheckpointSHA256: previousDigest, PolicyVersion: "policy-v1",
	}, principal, VerificationCheckpointSignerRole, keyID, privateKey)
	if err != nil {
		t.Fatalf("seal checkpoint: %v", err)
	}
	return checkpoint
}

func checkpointKeyPair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func checkpointPolicy(publicKey ed25519.PublicKey, principal, keyID string) VerificationCheckpointTrustPolicy {
	return VerificationCheckpointTrustPolicy{
		PolicyVersion: "policy-v1",
		TrustedKeys: []TrustedCheckpointSigningKey{{
			KeyID: keyID, Principal: principal, Role: VerificationCheckpointSignerRole,
			PublicKey: publicKey,
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}},
	}
}

func TestSignedVerificationAuditCheckpoint(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(1)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, checkpointPolicy(publicKey, "custodian-a", "key-a"), time.Date(2026, 11, 11, 10, 1, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
}

func TestSignedVerificationAuditCheckpointRejectsTampering(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(2)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	checkpoint.Payload.Sequence++
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, checkpointPolicy(publicKey, "custodian-a", "key-a"), time.Date(2026, 11, 11, 10, 1, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestSignedVerificationAuditCheckpointRejectsUntrustedSigner(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(3)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	policy := checkpointPolicy(publicKey, "different-principal", "key-a")
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, policy, time.Date(2026, 11, 11, 10, 1, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestSignedVerificationAuditCheckpointRejectsRevokedKey(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(4)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	policy := checkpointPolicy(publicKey, "custodian-a", "key-a")
	revokedAt := time.Date(2026, 11, 11, 10, 0, 30, 0, time.UTC)
	policy.TrustedKeys[0].RevokedAt = &revokedAt
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, policy, time.Date(2026, 11, 11, 10, 1, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestSignedVerificationAuditCheckpointAcceptsHistoricalSignatureAfterExpiry(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(5)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	policy := checkpointPolicy(publicKey, "custodian-a", "key-a")
	policy.TrustedKeys[0].NotAfter = time.Date(2026, 11, 11, 10, 0, 30, 0, time.UTC)
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, policy, time.Date(2026, 12, 1, 10, 1, 0, 0, time.UTC)); err != nil {
		t.Fatalf("historical signature rejected after key expiry: %v", err)
	}
}

func TestSignedVerificationAuditCheckpointRejectsStaleCheckpoint(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(6)
	checkpoint := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	policy := checkpointPolicy(publicKey, "custodian-a", "key-a")
	policy.MaxCheckpointAge = time.Hour
	if err := ValidateSignedVerificationAuditCheckpoint(checkpoint, nil, policy, time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestSignedVerificationAuditCheckpointRejectsForkAndRollback(t *testing.T) {
	t.Parallel()
	publicA, privateA := checkpointKeyPair(7)
	publicB, privateB := checkpointKeyPair(8)
	first := checkpointFixture(t, "custodian-a", "key-a", privateA, 10, "", "2026-11-11T10:00:00Z")
	policy := checkpointPolicy(publicB, "custodian-b", "key-b")
	policy.TrustedKeys = append(policy.TrustedKeys, checkpointPolicy(publicA, "custodian-a", "key-a").TrustedKeys...)
	validNext := checkpointFixture(t, "custodian-b", "key-b", privateB, 20, VerificationAuditCheckpointDigest(first), "2026-11-11T10:05:00Z")
	if err := ValidateSignedVerificationAuditCheckpoint(validNext, &first, policy, time.Date(2026, 11, 11, 10, 6, 0, 0, time.UTC)); err != nil {
		t.Fatalf("valid successor rejected: %v", err)
	}
	fork := checkpointFixture(t, "custodian-b", "key-b", privateB, 20, hex.EncodeToString(make([]byte, sha256.Size)), "2026-11-11T10:05:00Z")
	if err := ValidateSignedVerificationAuditCheckpoint(fork, &first, policy, time.Date(2026, 11, 11, 10, 6, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("fork error = %v, want ErrCorrupt", err)
	}
	rollback := checkpointFixture(t, "custodian-b", "key-b", privateB, 9, VerificationAuditCheckpointDigest(first), "2026-11-11T10:05:00Z")
	if err := ValidateSignedVerificationAuditCheckpoint(rollback, &first, policy, time.Date(2026, 11, 11, 10, 6, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("rollback error = %v, want ErrCorrupt", err)
	}
}

func TestSignedVerificationAuditCheckpointRequiresDistinctSigner(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := checkpointKeyPair(9)
	first := checkpointFixture(t, "custodian-a", "key-a", privateKey, 10, "", "2026-11-11T10:00:00Z")
	next := checkpointFixture(t, "custodian-a", "key-a", privateKey, 20, VerificationAuditCheckpointDigest(first), "2026-11-11T10:05:00Z")
	policy := checkpointPolicy(publicKey, "custodian-a", "key-a")
	policy.RequireDistinctSigner = true
	if err := ValidateSignedVerificationAuditCheckpoint(next, &first, policy, time.Date(2026, 11, 11, 10, 6, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}
