package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type memoryEvidence map[string][]byte

func (m memoryEvidence) ReadEvidence(path string) ([]byte, error) {
	data, ok := m[path]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

func signedFixture(t *testing.T) (QualificationEvidenceManifest, memoryEvidence, EvidenceVerificationPolicy, time.Time) {
	t.Helper()
	manifest := validEvidenceManifest()
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	manifest.Review.ReviewedAt = now.Add(-time.Minute).Format(time.RFC3339)
	evidence := memoryEvidence{}
	for i := range manifest.Tests {
		ref := &manifest.Tests[i].Evidence[0]
		data := []byte("evidence:" + ref.Path)
		evidence[ref.Path] = data
		ref.SHA256 = digestHex(data)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	manifest.Review.Attestation = EvidenceReference{Path: "evidence/review.json", MediaType: "application/json"}
	signingBytes, err := manifestSigningBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload := QualificationAttestationPayload{
		QualificationID: manifest.QualificationID, ManifestSHA256: digestHex(signingBytes),
		ReviewerIdentity: manifest.Review.ReviewerIdentity, KeyID: "reviewer-key-1", SignedAt: manifest.Review.ReviewedAt,
	}
	signature := ed25519.Sign(private, mustJSON(payload))
	attestationBytes, err := json.Marshal(QualificationAttestation{Payload: payload, Algorithm: "Ed25519", Signature: base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	evidence[manifest.Review.Attestation.Path] = attestationBytes
	manifest.Review.Attestation.SHA256 = digestHex(attestationBytes)
	policy := EvidenceVerificationPolicy{
		PolicyID: "test-policy", Version: "1", ImplementerIdentity: "implementer",
		RequireDistinctReviewer: true, MaximumEvidenceAge: 24 * time.Hour,
		TrustedReviewerKeys: []TrustedReviewerKey{{KeyID: "reviewer-key-1", Principal: manifest.Review.ReviewerIdentity,
			Role: QualificationReviewerRole, PublicKey: public, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}},
	}
	return manifest, evidence, policy, now
}

func TestVerifyQualificationEvidenceAcceptsTrustedSignedPackage(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	report, err := VerifyQualificationEvidence(manifest, evidence, policy, now)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if !report.Ready || report.EvidenceChecked != 26 || report.ReviewerKeyID != "reviewer-key-1" {
		t.Fatalf("unexpected verification report: %+v", report)
	}
}

func TestVerifyQualificationEvidenceRejectsTamperedEvidence(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	evidence[manifest.Tests[0].Evidence[0].Path] = []byte("tampered")
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsUntrustedReviewer(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	policy.TrustedReviewerKeys = nil
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsImplementerAsReviewer(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	policy.ImplementerIdentity = manifest.Review.ReviewerIdentity
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsWrongReviewerRole(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	policy.TrustedReviewerKeys[0].Role = "IMPLEMENTER"
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsNotYetValidKey(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	policy.TrustedReviewerKeys[0].NotBefore = now.Add(time.Minute)
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsRevokedKey(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	revoked := now.Add(-2 * time.Minute)
	policy.TrustedReviewerKeys[0].RevokedAt = &revoked
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsStalePackage(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	policy.MaximumEvidenceAge = time.Minute
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}

func TestVerifyQualificationEvidenceRejectsInvalidSignature(t *testing.T) {
	manifest, evidence, policy, now := signedFixture(t)
	var attestation QualificationAttestation
	if err := json.Unmarshal(evidence[manifest.Review.Attestation.Path], &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Signature = base64.StdEncoding.EncodeToString([]byte("invalid"))
	evidence[manifest.Review.Attestation.Path], _ = json.Marshal(attestation)
	manifest.Review.Attestation.SHA256 = digestHex(evidence[manifest.Review.Attestation.Path])
	if _, err := VerifyQualificationEvidence(manifest, evidence, policy, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
}
