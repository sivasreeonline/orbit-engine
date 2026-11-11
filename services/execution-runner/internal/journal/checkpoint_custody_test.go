package journal

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func custodyKeyPair(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func custodyPolicy(publicKey ed25519.PublicKey, principal, keyID string) CheckpointCustodyPolicy {
	return CheckpointCustodyPolicy{
		PolicyID: "custody-policy", PolicyVersion: "v1",
		MinimumRetention: 30 * 24 * time.Hour, RequireIndependentCustodian: true,
		TrustedKeys: []TrustedCheckpointCustodianKey{{
			KeyID: keyID, Principal: principal, Role: CheckpointCustodianRole,
			PublicKey: publicKey,
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}},
	}
}

func custodyFixture(t *testing.T, signer string, custodian string, keyID string, privateKey ed25519.PrivateKey) (SignedVerificationAuditCheckpoint, CheckpointCustodyReceipt) {
	t.Helper()
	_, checkpointPrivateKey := checkpointKeyPair(99)
	checkpoint := checkpointFixture(t, signer, "checkpoint-key", checkpointPrivateKey, 15, "", "2026-11-11T10:00:00Z")
	receipt, err := SealCheckpointCustodyReceipt(
		checkpoint, "independent-vault-a", "custody-policy", "v1",
		"2026-11-11T10:01:00Z", "2027-01-01T10:01:00Z",
		custodian, keyID, privateKey,
	)
	if err != nil {
		t.Fatalf("seal custody receipt: %v", err)
	}
	return checkpoint, receipt
}

func TestValidateCheckpointCustodyReceipt(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := custodyKeyPair(21)
	checkpoint, receipt := custodyFixture(t, "checkpoint-author", "vault-custodian", "custody-key", privateKey)
	policy := custodyPolicy(publicKey, "vault-custodian", "custody-key")
	verifiedAt := time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC)
	if err := ValidateCheckpointCustodyReceipt(checkpoint, receipt, policy, verifiedAt); err != nil {
		t.Fatalf("valid custody receipt rejected: %v", err)
	}
}

func TestValidateCheckpointCustodyReceiptRejectsTamperingAndWrongCheckpoint(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := custodyKeyPair(22)
	checkpoint, receipt := custodyFixture(t, "checkpoint-author", "vault-custodian", "custody-key", privateKey)
	policy := custodyPolicy(publicKey, "vault-custodian", "custody-key")
	verifiedAt := time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC)

	tampered := receipt
	tampered.CustodyDomain = "untrusted-domain"
	if err := ValidateCheckpointCustodyReceipt(checkpoint, tampered, policy, verifiedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampering error = %v, want ErrCorrupt", err)
	}

	otherCheckpoint := checkpoint
	otherCheckpoint.Payload.Sequence++
	if err := ValidateCheckpointCustodyReceipt(otherCheckpoint, receipt, policy, verifiedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong checkpoint error = %v, want ErrCorrupt", err)
	}
}

func TestValidateCheckpointCustodyReceiptRejectsInsufficientRetention(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := custodyKeyPair(23)
	checkpoint, receipt := custodyFixture(t, "checkpoint-author", "vault-custodian", "custody-key", privateKey)
	receipt, err := SealCheckpointCustodyReceipt(
		checkpoint, "independent-vault-a", "custody-policy", "v1",
		"2026-11-11T10:01:00Z", "2026-11-12T10:01:00Z",
		"vault-custodian", "custody-key", privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCheckpointCustodyReceipt(checkpoint, receipt, custodyPolicy(publicKey, "vault-custodian", "custody-key"), time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("retention error = %v, want ErrCorrupt", err)
	}
}

func TestValidateCheckpointCustodyReceiptRejectsRevokedOrUntrustedCustodian(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := custodyKeyPair(24)
	checkpoint, receipt := custodyFixture(t, "checkpoint-author", "vault-custodian", "custody-key", privateKey)
	policy := custodyPolicy(publicKey, "vault-custodian", "custody-key")
	revokedAt := time.Date(2026, 11, 11, 10, 1, 30, 0, time.UTC)
	policy.TrustedKeys[0].RevokedAt = &revokedAt
	verifiedAt := time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC)
	if err := ValidateCheckpointCustodyReceipt(checkpoint, receipt, policy, verifiedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("revocation error = %v, want ErrCorrupt", err)
	}

	untrusted := custodyPolicy(publicKey, "different-custodian", "custody-key")
	if err := ValidateCheckpointCustodyReceipt(checkpoint, receipt, untrusted, verifiedAt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("untrusted error = %v, want ErrCorrupt", err)
	}
}

func TestValidateCheckpointCustodyReceiptRequiresIndependentCustodian(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := custodyKeyPair(25)
	checkpoint, receipt := custodyFixture(t, "checkpoint-author", "checkpoint-author", "custody-key", privateKey)
	policy := custodyPolicy(publicKey, "checkpoint-author", "custody-key")
	if err := ValidateCheckpointCustodyReceipt(checkpoint, receipt, policy, time.Date(2026, 11, 11, 10, 2, 0, 0, time.UTC)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("same-principal error = %v, want ErrCorrupt", err)
	}
}
