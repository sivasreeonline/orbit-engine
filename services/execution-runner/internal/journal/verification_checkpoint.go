package journal

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const VerificationCheckpointSignerRole = "VERIFICATION_CHECKPOINT_SIGNER"

// VerificationAuditCheckpointPayload binds a checkpoint to one ledger
// incarnation and one exact audit-chain head. Field order is canonicalized by
// the Go struct encoding used below; cross-language implementations must
// implement the documented canonical JSON representation.
type VerificationAuditCheckpointPayload struct {
	LedgerID             string `json:"ledger_id"`
	LedgerEpoch          string `json:"ledger_epoch"`
	Sequence             uint64 `json:"sequence"`
	RecordSHA256          string `json:"record_sha256"`
	CreatedAt             string `json:"created_at"`
	PreviousCheckpointSHA256 string `json:"previous_checkpoint_sha256"`
	PolicyVersion         string `json:"policy_version"`
}

// SignedVerificationAuditCheckpoint is a detached Ed25519 attestation over
// the canonical payload. The private key is never part of this contract.
type SignedVerificationAuditCheckpoint struct {
	Payload          VerificationAuditCheckpointPayload `json:"payload"`
	SignerPrincipal  string                              `json:"signer_principal"`
	SignerRole       string                              `json:"signer_role"`
	SignerKeyID      string                              `json:"signer_key_id"`
	SignatureHex     string                              `json:"signature_hex"`
	CheckpointSHA256 string                              `json:"checkpoint_sha256"`
}

// TrustedCheckpointSigningKey is supplied by an independently governed trust
// policy. Revocation is immediate at/after RevokedAt; expiry is evaluated at
// signing time so historical signatures remain verifiable after key expiry.
type TrustedCheckpointSigningKey struct {
	KeyID       string
	Principal   string
	Role        string
	PublicKey   ed25519.PublicKey
	NotBefore   time.Time
	NotAfter    time.Time
	RevokedAt   *time.Time
}

type VerificationCheckpointTrustPolicy struct {
	PolicyVersion          string
	TrustedKeys            []TrustedCheckpointSigningKey
	RequireDistinctSigner  bool
	MaxCheckpointAge       time.Duration
}

func checkpointPayloadBytes(payload VerificationAuditCheckpointPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func checkpointSigningBytes(checkpoint SignedVerificationAuditCheckpoint) ([]byte, error) {
	return json.Marshal(struct {
		Payload         VerificationAuditCheckpointPayload `json:"payload"`
		SignerPrincipal string                              `json:"signer_principal"`
		SignerRole      string                              `json:"signer_role"`
		SignerKeyID     string                              `json:"signer_key_id"`
	}{
		Payload: checkpoint.Payload, SignerPrincipal: checkpoint.SignerPrincipal,
		SignerRole: checkpoint.SignerRole, SignerKeyID: checkpoint.SignerKeyID,
	})
}

// SealVerificationAuditCheckpoint signs a checkpoint using a caller-provided
// key. It does not persist the checkpoint or establish trust in the key.
func SealVerificationAuditCheckpoint(payload VerificationAuditCheckpointPayload, principal, role, keyID string, privateKey ed25519.PrivateKey) (SignedVerificationAuditCheckpoint, error) {
	if len(privateKey) != ed25519.PrivateKeySize || strings.TrimSpace(principal) == "" ||
		strings.TrimSpace(keyID) == "" || role != VerificationCheckpointSignerRole {
		return SignedVerificationAuditCheckpoint{}, fmt.Errorf("%w: invalid checkpoint signer input", ErrCorrupt)
	}
	if err := validateCheckpointPayload(payload); err != nil {
		return SignedVerificationAuditCheckpoint{}, err
	}
	checkpoint := SignedVerificationAuditCheckpoint{
		Payload: payload, SignerPrincipal: principal, SignerRole: role, SignerKeyID: keyID,
	}
	message, err := checkpointSigningBytes(checkpoint)
	if err != nil {
		return SignedVerificationAuditCheckpoint{}, fmt.Errorf("%w: encode checkpoint", ErrCorrupt)
	}
	checkpoint.SignatureHex = hex.EncodeToString(ed25519.Sign(privateKey, message))
	checkpoint.CheckpointSHA256 = digestHex(checkpointDigestBytes(checkpoint))
	return checkpoint, nil
}

func checkpointDigestBytes(checkpoint SignedVerificationAuditCheckpoint) []byte {
	checkpoint.CheckpointSHA256 = ""
	data, _ := json.Marshal(checkpoint)
	return data
}

func validateCheckpointPayload(payload VerificationAuditCheckpointPayload) error {
	if strings.TrimSpace(payload.LedgerID) == "" || strings.TrimSpace(payload.LedgerEpoch) == "" ||
		strings.TrimSpace(payload.PolicyVersion) == "" || payload.Sequence == 0 ||
		!validAuditDigest(payload.RecordSHA256) {
		return fmt.Errorf("%w: checkpoint payload identity or head is invalid", ErrCorrupt)
	}
	if payload.PreviousCheckpointSHA256 != "" && !validAuditDigest(payload.PreviousCheckpointSHA256) {
		return fmt.Errorf("%w: previous checkpoint digest is invalid", ErrCorrupt)
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.CreatedAt); err != nil {
		return fmt.Errorf("%w: checkpoint timestamp is invalid", ErrCorrupt)
	}
	return nil
}

func checkpointKey(policy VerificationCheckpointTrustPolicy, keyID string) (TrustedCheckpointSigningKey, bool) {
	for _, key := range policy.TrustedKeys {
		if key.KeyID == keyID {
			return key, true
		}
	}
	return TrustedCheckpointSigningKey{}, false
}

// VerificationAuditCheckpointDigest returns the digest used as the next
// checkpoint's predecessor link.
func VerificationAuditCheckpointDigest(checkpoint SignedVerificationAuditCheckpoint) string {
	return digestHex(checkpointDigestBytes(checkpoint))
}

// ValidateSignedVerificationAuditCheckpoint verifies payload, trusted signer,
// signature, checkpoint digest, age, and monotonic linkage to a previously
// independently retained checkpoint. previous must itself have been verified
// against the applicable trust policy before it is supplied here.
func ValidateSignedVerificationAuditCheckpoint(checkpoint SignedVerificationAuditCheckpoint, previous *SignedVerificationAuditCheckpoint, policy VerificationCheckpointTrustPolicy, verifiedAt time.Time) error {
	if err := validateCheckpointPayload(checkpoint.Payload); err != nil {
		return err
	}
	if strings.TrimSpace(policy.PolicyVersion) == "" || checkpoint.Payload.PolicyVersion != policy.PolicyVersion {
		return fmt.Errorf("%w: checkpoint policy version mismatch", ErrCorrupt)
	}
	if checkpoint.SignerRole != VerificationCheckpointSignerRole || strings.TrimSpace(checkpoint.SignerPrincipal) == "" {
		return fmt.Errorf("%w: checkpoint signer identity or role is invalid", ErrCorrupt)
	}
	key, ok := checkpointKey(policy, checkpoint.SignerKeyID)
	if !ok || key.Principal != checkpoint.SignerPrincipal || key.Role != VerificationCheckpointSignerRole ||
		len(key.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: checkpoint signer is not trusted", ErrCorrupt)
	}
	signedAt, err := time.Parse(time.RFC3339Nano, checkpoint.Payload.CreatedAt)
	if err != nil || signedAt.Before(key.NotBefore) || signedAt.After(key.NotAfter) {
		return fmt.Errorf("%w: checkpoint signing time is outside key validity", ErrCorrupt)
	}
	if key.RevokedAt != nil && !verifiedAt.Before(*key.RevokedAt) {
		return fmt.Errorf("%w: checkpoint signing key is revoked", ErrCorrupt)
	}
	if verifiedAt.Before(signedAt) {
		return fmt.Errorf("%w: checkpoint timestamp is in the future", ErrCorrupt)
	}
	if policy.MaxCheckpointAge > 0 && verifiedAt.Sub(signedAt) > policy.MaxCheckpointAge {
		return fmt.Errorf("%w: checkpoint is stale", ErrCorrupt)
	}
	signature, err := hex.DecodeString(checkpoint.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: checkpoint signature encoding is invalid", ErrCorrupt)
	}
	message, err := checkpointSigningBytes(checkpoint)
	if err != nil || !ed25519.Verify(key.PublicKey, message, signature) {
		return fmt.Errorf("%w: checkpoint signature verification failed", ErrCorrupt)
	}
	if checkpoint.CheckpointSHA256 != VerificationAuditCheckpointDigest(checkpoint) {
		return fmt.Errorf("%w: checkpoint digest mismatch", ErrCorrupt)
	}
	if previous == nil {
		if checkpoint.Payload.PreviousCheckpointSHA256 != "" {
			return fmt.Errorf("%w: initial checkpoint has a predecessor", ErrCorrupt)
		}
		return nil
	}
	if previous.Payload.LedgerID != checkpoint.Payload.LedgerID ||
		previous.Payload.LedgerEpoch != checkpoint.Payload.LedgerEpoch {
		return fmt.Errorf("%w: checkpoint ledger identity or epoch changed", ErrCorrupt)
	}
	if checkpoint.Payload.Sequence <= previous.Payload.Sequence ||
		checkpoint.Payload.PreviousCheckpointSHA256 != VerificationAuditCheckpointDigest(*previous) {
		return fmt.Errorf("%w: checkpoint rollback, fork, or predecessor mismatch", ErrCorrupt)
	}
	previousAt, parseErr := time.Parse(time.RFC3339Nano, previous.Payload.CreatedAt)
	if parseErr != nil || signedAt.Before(previousAt) {
		return fmt.Errorf("%w: checkpoint timestamp moved backwards", ErrCorrupt)
	}
	if policy.RequireDistinctSigner && checkpoint.SignerPrincipal == previous.SignerPrincipal {
		return fmt.Errorf("%w: checkpoint signer is not independent of predecessor signer", ErrCorrupt)
	}
	return nil
}
