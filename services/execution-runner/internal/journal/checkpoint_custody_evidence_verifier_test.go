package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type custodyEvidenceMemory map[string][]byte

func (m custodyEvidenceMemory) ReadEvidence(name string) ([]byte, error) {
	data, ok := m[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func custodyEvidenceDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestVerifyCheckpointCustodyEvidenceAcceptsBoundSignedBundle(t *testing.T) {
	manifest := custodyQualificationFixture()
	evidence := make(custodyEvidenceMemory)
	add := func(reference *CheckpointCustodyEvidenceReference, name string, data []byte) {
		reference.Path = name
		reference.SHA256 = custodyEvidenceDigest(data)
		reference.MediaType = "application/json"
		evidence[name] = data
	}
	for i := range manifest.Scenarios {
		for j := range manifest.Scenarios[i].Evidence {
			name := manifest.Scenarios[i].Evidence[j].Path
			add(&manifest.Scenarios[i].Evidence[j], name, []byte("scenario:"+manifest.Scenarios[i].ScenarioID))
		}
		for j := range manifest.Scenarios[i].IndependentWitnessEvidence {
			name := manifest.Scenarios[i].IndependentWitnessEvidence[j].Path
			add(&manifest.Scenarios[i].IndependentWitnessEvidence[j], name, []byte("witness:"+manifest.Scenarios[i].ScenarioID))
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Review.ReviewerIdentity = "reviewer-2026"
	manifest.Review.Status = "APPROVED"
	manifest.Review.ReviewedAt = "2026-11-11T10:00:00Z"
	manifest.Review.Attestation = CheckpointCustodyEvidenceReference{
		Path: "evidence/review-signature.json", MediaType: "application/json",
		SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	canonical, err := canonicalCustodyManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(canonical)
	payload, err := json.Marshal(custodyReviewAttestation{
		SchemaVersion: "1.0",
		QualificationID: manifest.QualificationID,
		ManifestDigest: hex.EncodeToString(manifestHash[:]),
		Reviewer: manifest.Review.ReviewerIdentity,
		ReviewedAt: manifest.Review.ReviewedAt,
		Decision: manifest.Review.Status,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	envelope, err := json.Marshal(custodyDetachedSignature{
		SchemaVersion: "1.0",
		Reviewer: manifest.Review.ReviewerIdentity,
		Algorithm: "Ed25519",
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	add(&manifest.Review.Attestation, manifest.Review.Attestation.Path, envelope)

	report, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys: map[string]ed25519.PublicKey{manifest.Review.ReviewerIdentity: publicKey},
		Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if report.VerifiedReferences != 15 {
		t.Fatalf("verified references = %d, want 15", report.VerifiedReferences)
	}
	if report.ReviewerIdentity != manifest.Review.ReviewerIdentity {
		t.Fatalf("reviewer = %q, want %q", report.ReviewerIdentity, manifest.Review.ReviewerIdentity)
	}
	if report.ReviewDecision != manifest.Review.Status {
		t.Fatalf("review decision = %q, want %q", report.ReviewDecision, manifest.Review.Status)
	}
	if report.ManifestDeclaresReady != CheckpointCustodyQualificationReady(manifest) {
		t.Fatalf("manifest-declared readiness = %t, want %t", report.ManifestDeclaresReady, CheckpointCustodyQualificationReady(manifest))
	}

	// Re-hash a tampered signature envelope so this exercises signature
	// verification rather than failing earlier on the artifact digest.
	tamperedEvidence := make(custodyEvidenceMemory, len(evidence))
	for name, data := range evidence {
		tamperedEvidence[name] = append([]byte(nil), data...)
	}
	var tamperedEnvelope custodyDetachedSignature
	if err := json.Unmarshal(tamperedEvidence[manifest.Review.Attestation.Path], &tamperedEnvelope); err != nil {
		t.Fatal(err)
	}
	tamperedEnvelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	tamperedBytes, err := json.Marshal(tamperedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	tamperedEvidence[manifest.Review.Attestation.Path] = tamperedBytes
	tamperedManifest := manifest
	tamperedManifest.Review.Attestation.SHA256 = custodyEvidenceDigest(tamperedBytes)
	if _, err := VerifyCheckpointCustodyEvidence(tamperedManifest, tamperedEvidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys: map[string]ed25519.PublicKey{manifest.Review.ReviewerIdentity: publicKey},
		Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("invalid detached signature was accepted")
	}

	if _, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys: map[string]ed25519.PublicKey{manifest.Review.ReviewerIdentity: publicKey},
		Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 30 * time.Minute,
	}); err == nil {
		t.Fatal("stale review attestation was accepted")
	}
	originalEnvelope := string(evidence[manifest.Review.Attestation.Path])
	for _, malformed := range []string{
		strings.TrimSuffix(originalEnvelope, "}") + `, "unexpected": true}`,
		originalEnvelope + ` {}`,
		strings.TrimSuffix(originalEnvelope, "}") + `, "reviewer": "reviewer-2026"}`,
	} {
		tamperedEvidence := make(custodyEvidenceMemory, len(evidence))
		for name, data := range evidence {
			tamperedEvidence[name] = append([]byte(nil), data...)
		}
		encoded := []byte(malformed)
		tamperedEvidence[manifest.Review.Attestation.Path] = encoded
		tamperedManifest := manifest
		tamperedManifest.Review.Attestation.SHA256 = custodyEvidenceDigest(encoded)
		if _, err := VerifyCheckpointCustodyEvidence(tamperedManifest, tamperedEvidence, CheckpointCustodyEvidenceVerifierTrust{
			ReviewerKeys: map[string]ed25519.PublicKey{manifest.Review.ReviewerIdentity: publicKey},
			Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
			MaxEvidenceAge: 24 * time.Hour,
		}); err == nil {
			t.Fatalf("malformed signature envelope was accepted: %q", malformed)
		}
	}

}

func TestVerifyCheckpointCustodyEvidenceRejectsModifiedEvidence(t *testing.T) {
	manifest := custodyQualificationFixture()
	evidence := make(custodyEvidenceMemory)
	for i := range manifest.Scenarios {
		for j := range manifest.Scenarios[i].Evidence {
			evidence[manifest.Scenarios[i].Evidence[j].Path] = []byte("tampered")
		}
	}
	_, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys: map[string]ed25519.PublicKey{"independent-reviewer": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: time.Hour,
	})
	if err == nil {
		t.Fatal("modified evidence was accepted")
	}
}

func TestFilesystemCustodyEvidenceSourceRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "evidence", "target.json")
	if err := os.WriteFile(target, []byte("proof"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "evidence", "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	source := FilesystemCheckpointCustodyEvidenceSource{Root: root}
	if _, err := source.ReadEvidence("evidence/link.json"); err == nil {
		t.Fatal("symlink evidence was accepted")
	}
}

func TestCustodyEvidencePathRejectsTraversalAndPlatformPaths(t *testing.T) {
	for _, value := range []string{"../outside", "/absolute", "C:/outside", "a//b", "a/../b", ""} {
		if err := validateCustodyRelativePath(value); err == nil {
			t.Errorf("unsafe path %q was accepted", value)
		}
	}
}
