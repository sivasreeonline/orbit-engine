package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// EvidenceSource supplies bytes by a manifest-relative path. Implementations
// must enforce a read-only, confined evidence root; the verifier also rejects
// unsafe paths before calling the source.
type EvidenceSource interface {
	ReadEvidence(path string) ([]byte, error)
}

type TrustedReviewerKey struct {
	KeyID      string
	Principal  string
	Role       string
	PublicKey  ed25519.PublicKey
	NotBefore  time.Time
	NotAfter   time.Time
	RevokedAt  *time.Time
}

type EvidenceVerificationPolicy struct {
	PolicyID                 string
	Version                  string
	ImplementerIdentity      string
	RequireDistinctReviewer  bool
	MaximumEvidenceAge       time.Duration
	TrustedReviewerKeys      []TrustedReviewerKey
}

type QualificationAttestationPayload struct {
	QualificationID string `json:"qualification_id"`
	ManifestSHA256  string `json:"manifest_sha256"`
	ReviewerIdentity string `json:"reviewer_identity"`
	KeyID           string `json:"key_id"`
	SignedAt        string `json:"signed_at"`
}

type QualificationAttestation struct {
	Payload   QualificationAttestationPayload `json:"payload"`
	Algorithm string                           `json:"algorithm"`
	Signature string                           `json:"signature"`
}

type EvidenceVerificationReport struct {
	PolicyID          string   `json:"policy_id"`
	PolicyVersion     string   `json:"policy_version"`
	QualificationID   string   `json:"qualification_id"`
	ManifestSHA256    string   `json:"manifest_sha256"`
	EvidenceChecked   int      `json:"evidence_checked"`
	ReviewerIdentity  string   `json:"reviewer_identity"`
	ReviewerKeyID     string   `json:"reviewer_key_id"`
	VerifiedAt        string   `json:"verified_at"`
	Ready             bool     `json:"ready"`
	Findings          []string `json:"findings"`
}

const QualificationReviewerRole = "JOURNAL_QUALIFICATION_REVIEWER"

// manifestSigningBytes binds all manifest fields, including the attestation
// path and media type, while excluding only the attestation file's own digest
// (which would create a signature/hash cycle).
func manifestSigningBytes(manifest QualificationEvidenceManifest) ([]byte, error) {
	manifest.Review.Attestation.SHA256 = ""
	return json.Marshal(manifest)
}

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VerifyQualificationEvidence checks every referenced byte, verifies the
// detached Ed25519 attestation against caller-supplied trust policy, and
// enforces reviewer separation and key validity. It does not establish that
// the supplied policy itself came from a trusted distribution channel.
func VerifyQualificationEvidence(manifest QualificationEvidenceManifest, source EvidenceSource, policy EvidenceVerificationPolicy, verifiedAt time.Time) (EvidenceVerificationReport, error) {
	report := EvidenceVerificationReport{
		PolicyID: policy.PolicyID, PolicyVersion: policy.Version,
		QualificationID: manifest.QualificationID, ReviewerIdentity: manifest.Review.ReviewerIdentity,
		VerifiedAt: verifiedAt.UTC().Format(time.RFC3339Nano), Findings: []string{},
	}
	fail := func(reason string) (EvidenceVerificationReport, error) {
		report.Findings = append(report.Findings, reason)
		report.Ready = false
		return report, fmt.Errorf("%w: evidence verification: %s", ErrCorrupt, reason)
	}
	if source == nil || verifiedAt.IsZero() || strings.TrimSpace(policy.PolicyID) == "" ||
		strings.TrimSpace(policy.Version) == "" || strings.TrimSpace(policy.ImplementerIdentity) == "" ||
		policy.MaximumEvidenceAge <= 0 {
		return fail("verification source, timestamp, policy identity, implementer, and positive evidence age are required")
	}
	if err := ValidateQualificationEvidenceManifest(manifest); err != nil {
		return fail("manifest structure is invalid: " + err.Error())
	}
	if !QualificationEvidenceReady(manifest) {
		return fail("manifest is not structurally ready with all scenarios PASS and review APPROVED")
	}
	reviewedAt, _ := time.Parse(time.RFC3339, manifest.Review.ReviewedAt)
	if reviewedAt.After(verifiedAt) || verifiedAt.Sub(reviewedAt) > policy.MaximumEvidenceAge {
		return fail("independent review is future-dated or older than policy maximum evidence age")
	}

	refs := make([]EvidenceReference, 0, len(manifest.Tests)+1)
	for _, test := range manifest.Tests {
		started, _ := time.Parse(time.RFC3339, test.StartedAt)
		completed, _ := time.Parse(time.RFC3339, test.CompletedAt)
		if completed.After(verifiedAt) || verifiedAt.Sub(completed) > policy.MaximumEvidenceAge || started.After(completed) {
			return fail("scenario " + test.ScenarioID + " evidence is future-dated or stale")
		}
		refs = append(refs, test.Evidence...)
	}
	refs = append(refs, manifest.Review.Attestation)
	for _, ref := range refs {
		data, err := source.ReadEvidence(ref.Path)
		if err != nil {
			return fail("cannot read evidence " + ref.Path)
		}
		if !strings.EqualFold(digestHex(data), ref.SHA256) {
			return fail("SHA-256 mismatch for evidence " + ref.Path)
		}
		report.EvidenceChecked++
	}

	attestationBytes, err := source.ReadEvidence(manifest.Review.Attestation.Path)
	if err != nil {
		return fail("cannot read reviewer attestation")
	}
	var attestation QualificationAttestation
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return fail("reviewer attestation is not valid JSON")
	}
	payloadBytes, err := manifestSigningBytes(manifest)
	if err != nil {
		return fail("cannot canonicalize manifest")
	}
	payload := attestation.Payload
	if payload.QualificationID != manifest.QualificationID ||
		!strings.EqualFold(payload.ManifestSHA256, digestHex(payloadBytes)) ||
		payload.ReviewerIdentity != manifest.Review.ReviewerIdentity ||
		payload.SignedAt != manifest.Review.ReviewedAt ||
		attestation.Algorithm != "Ed25519" {
		return fail("attestation payload does not bind this manifest and reviewer")
	}
	signedAt, err := time.Parse(time.RFC3339, payload.SignedAt)
	if err != nil || signedAt.After(verifiedAt) {
		return fail("attestation signing time is invalid")
	}

	var trusted *TrustedReviewerKey
	for i := range policy.TrustedReviewerKeys {
		key := &policy.TrustedReviewerKeys[i]
		if key.KeyID == payload.KeyID {
			if trusted != nil {
				return fail("trust policy contains duplicate reviewer key IDs")
			}
			trusted = key
		}
	}
	if trusted == nil || trusted.Principal != payload.ReviewerIdentity ||
		trusted.Role != QualificationReviewerRole || len(trusted.PublicKey) != ed25519.PublicKeySize {
		return fail("reviewer key is not trusted for the required qualification role")
	}
	if policy.RequireDistinctReviewer && trusted.Principal == policy.ImplementerIdentity {
		return fail("implementer and independent reviewer identities are not distinct")
	}
	if signedAt.Before(trusted.NotBefore) || signedAt.After(trusted.NotAfter) ||
		(!trusted.NotAfter.IsZero() && verifiedAt.After(trusted.NotAfter)) {
		return fail("reviewer key is outside its validity window")
	}
	if trusted.RevokedAt != nil && !signedAt.Before(*trusted.RevokedAt) {
		return fail("reviewer key was revoked at or before signing time")
	}
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil || !ed25519.Verify(trusted.PublicKey, mustJSON(payload), signature) {
		return fail("reviewer Ed25519 signature is invalid")
	}

	report.ManifestSHA256 = digestHex(payloadBytes)
	report.ReviewerKeyID = trusted.KeyID
	report.Ready = true
	return report, nil
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}
