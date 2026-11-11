package journal

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const CheckpointCustodianRole = "VERIFICATION_CHECKPOINT_CUSTODIAN"

// CheckpointCustodyReceipt is a custodian-signed assertion that a specific
// signed checkpoint was accepted under a named retention policy.
type CheckpointCustodyReceipt struct {
	CheckpointSHA256       string       `json:"checkpoint_sha256"`
	CustodyDomain          string       `json:"custody_domain"`
	RetentionPolicyID      string      `json:"retention_policy_id"`
	RetentionPolicyVersion string `json:"retention_policy_version"`
	RetainedAt             string       `json:"retained_at"`
	ImmutableUntil         string       `json:"immutable_until"`
	CustodianPrincipal     string     `json:"custodian_principal"`
	CustodianRole          string       `json:"custodian_role"`
	CustodianKeyID         string       `json:"custodian_key_id"`
	SignatureHex           string       `json:"signature_hex"`
	ReceiptSHA256          string       `json:"receipt_sha256"`
}

// TrustedCheckpointCustodianKey is supplied by an independently governed
// custody trust policy. Private keys are never represented here.
type TrustedCheckpointCustodianKey struct {
	KeyID     string
	Principal string
	Role      string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
}

type CheckpointCustodyPolicy struct {
	PolicyID                    string
	PolicyVersion               string
	MinimumRetention            time.Duration
	RequireIndependentCustodian bool
	TrustedKeys                 []TrustedCheckpointCustodianKey
}

func custodyReceiptSigningBytes(receipt CheckpointCustodyReceipt) ([]byte, error) {
	return json.Marshal(struct {
		CheckpointSHA256      string  `json:"checkpoint_sha256"`
		CustodyDomain         string  `json:"custody_domain"`
		RetentionPolicyID     string  `json:"retention_policy_id"`
		RetentionPolicyVersion string `json:"retention_policy_version"`
		RetainedAt            string  `json:"retained_at"`
		ImmutableUntil        string  `json:"immutable_until"`
		CustodianPrincipal    string  `json:"custodian_principal"`
		CustodianRole         string  `json:"custodian_role"`
		CustodianKeyID        string  `json:"custodian_key_id"`
	}{
		CheckpointSHA256: receipt.CheckpointSHA256, CustodyDomain: receipt.CustodyDomain,
		RetentionPolicyID: receipt.RetentionPolicyID, RetentionPolicyVersion: receipt.RetentionPolicyVersion,
		RetainedAt: receipt.RetainedAt, ImmutableUntil: receipt.ImmutableUntil,
		CustodianPrincipal: receipt.CustodianPrincipal, CustodianRole: receipt.CustodianRole,
		CustodianKeyID: receipt.CustodianKeyID,
	})
}

func custodyReceiptDigestBytes(receipt CheckpointCustodyReceipt) []byte {
	receipt.ReceiptSHA256 = ""
	data, _ := json.Marshal(receipt)
	return data
}

// SealCheckpointCustodyReceipt creates a detached Ed25519 custody receipt.
// It is an assertion by the custodian, not proof that storage is actually
// immutable or independently administered.
func SealCheckpointCustodyReceipt(checkpoint SignedVerificationAuditCheckpoint, custodyDomain, policyID, policyVersion, retainedAt, immutableUntil, principal, keyID string, privateKey ed25519.PrivateKey) (CheckpointCustodyReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize || strings.TrimSpace(custodyDomain) == "" ||
		strings.TrimSpace(policyID) == "" || strings.TrimSpace(policyVersion) == "" ||
		strings.TrimSpace(principal) == "" || strings.TrimSpace(keyID) == "" {
		return CheckpointCustodyReceipt{}, fmt.Errorf("%w: invalid checkpoint custody input", ErrCorrupt)
	}
	receipt := CheckpointCustodyReceipt{
		CheckpointSHA256:       VerificationAuditCheckpointDigest(checkpoint),
		CustodyDomain:          custodyDomain, RetentionPolicyID: policyID, RetentionPolicyVersion: policyVersion,
		RetainedAt:             retainedAt, ImmutableUntil: immutableUntil,
		CustodianPrincipal:     principal, CustodianRole: CheckpointCustodianRole, CustodianKeyID: keyID,
	}
	message, err := custodyReceiptSigningBytes(receipt)
	if err != nil {
		return CheckpointCustodyReceipt{}, fmt.Errorf("%w: encode custody receipt", ErrCorrupt)
	}
	receipt.SignatureHex = hex.EncodeToString(ed25519.Sign(privateKey, message))
	receipt.ReceiptSHA256 = digestHex(custodyReceiptDigestBytes(receipt))
	return receipt, nil
}

// ValidateCheckpointCustodyReceipt validates the custodian's signed retention
// assertion against a separately supplied trust policy and checkpoint.
func ValidateCheckpointCustodyReceipt(checkpoint SignedVerificationAuditCheckpoint, receipt CheckpointCustodyReceipt, policy CheckpointCustodyPolicy, verifiedAt time.Time) error {
	if strings.TrimSpace(policy.PolicyID) == "" || strings.TrimSpace(policy.PolicyVersion) == "" ||
		policy.MinimumRetention <= 0 || receipt.RetentionPolicyID != policy.PolicyID ||
		receipt.RetentionPolicyVersion != policy.PolicyVersion {
		return fmt.Errorf("%w: custody policy identity mismatch", ErrCorrupt)
	}
	if receipt.CheckpointSHA256 != VerificationAuditCheckpointDigest(checkpoint) ||
		!validAuditDigest(receipt.CheckpointSHA256) || strings.TrimSpace(receipt.CustodyDomain) == "" {
		return fmt.Errorf("%w: custody receipt checkpoint or domain mismatch", ErrCorrupt)
	}
	if receipt.CustodianRole != CheckpointCustodianRole || strings.TrimSpace(receipt.CustodianPrincipal) == "" {
		return fmt.Errorf("%w: custody signer identity or role is invalid", ErrCorrupt)
	}
	var trusted *TrustedCheckpointCustodianKey
	for i := range policy.TrustedKeys {
		if policy.TrustedKeys[i].KeyID == receipt.CustodianKeyID {
			trusted = &policy.TrustedKeys[i]
			break
		}
	}
	if trusted == nil || trusted.Principal != receipt.CustodianPrincipal ||
		trusted.Role != CheckpointCustodianRole || len(trusted.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: checkpoint custodian is not trusted", ErrCorrupt)
	}
	retainedAt, err := time.Parse(time.RFC3339Nano, receipt.RetainedAt)
	if err != nil || retainedAt.Before(trusted.NotBefore) || retainedAt.After(trusted.NotAfter) {
		return fmt.Errorf("%w: custody signing time is outside key validity", ErrCorrupt)
	}
	immutableUntil, err := time.Parse(time.RFC3339Nano, receipt.ImmutableUntil)
	if err != nil || !immutableUntil.After(retainedAt) ||
		immutableUntil.Sub(retainedAt) < policy.MinimumRetention {
		return fmt.Errorf("%w: custody retention interval is insufficient", ErrCorrupt)
	}
	checkpointAt, err := time.Parse(time.RFC3339Nano, checkpoint.Payload.CreatedAt)
	if err != nil || retainedAt.Before(checkpointAt) || verifiedAt.Before(retainedAt) {
		return fmt.Errorf("%w: custody receipt time is inconsistent", ErrCorrupt)
	}
	if trusted.RevokedAt != nil && !verifiedAt.Before(*trusted.RevokedAt) {
		return fmt.Errorf("%w: checkpoint custodian key is revoked", ErrCorrupt)
	}
	signature, err := hex.DecodeString(receipt.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: custody signature encoding is invalid", ErrCorrupt)
	}
	message, err := custodyReceiptSigningBytes(receipt)
	if err != nil || !ed25519.Verify(trusted.PublicKey, message, signature) {
		return fmt.Errorf("%w: custody signature verification failed", ErrCorrupt)
	}
	if receipt.ReceiptSHA256 != digestHex(custodyReceiptDigestBytes(receipt)) {
		return fmt.Errorf("%w: custody receipt digest mismatch", ErrCorrupt)
	}
	if policy.RequireIndependentCustodian && receipt.CustodianPrincipal == checkpoint.SignerPrincipal {
		return fmt.Errorf("%w: checkpoint signer cannot attest its own custody", ErrCorrupt)
	}
	return nil
}

// CheckpointCustodyStore is a backend-neutral compare-and-store contract.
// Implementations must atomically verify the expected current checkpoint,
// retain the checkpoint and receipt together, and reject stale/forked writes.
type CheckpointCustodyStore interface {
	ReadLatest(ctx context.Context, ledgerID, ledgerEpoch string) (SignedVerificationAuditCheckpoint, CheckpointCustodyReceipt, error)
	StoreIfCurrent(ctx context.Context, checkpoint SignedVerificationAuditCheckpoint, receipt CheckpointCustodyReceipt, expectedPreviousCheckpointSHA256 string) error
}
