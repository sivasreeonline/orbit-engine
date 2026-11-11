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
	"sort"
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
	witnessKeys := make(map[string]TrustedCheckpointCustodyWitnessKey)
	for i := range manifest.Scenarios {
		scenario := &manifest.Scenarios[i]
		for j := range scenario.Evidence {
			name := scenario.Evidence[j].Path
			add(&scenario.Evidence[j], name, []byte("scenario:"+scenario.ScenarioID))
		}
		for j := range scenario.IndependentWitnessEvidence {
			name := scenario.IndependentWitnessEvidence[j].Path
			add(&scenario.IndependentWitnessEvidence[j], name, []byte("witness:"+scenario.ScenarioID))
		}
		if len(scenario.IndependentWitnessEvidence) == 0 {
			continue
		}
		witnessPublicKey, witnessPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		witnessPrincipal := "witness-" + scenario.ScenarioID
		witnessKeyID := "witness-key-" + scenario.ScenarioID
		evidenceDigests := make([]string, 0, len(scenario.IndependentWitnessEvidence))
		for _, reference := range scenario.IndependentWitnessEvidence {
			evidenceDigests = append(evidenceDigests, reference.SHA256)
		}
		sort.Strings(evidenceDigests)
		witnessPayload := custodyWitnessAttestation{
			SchemaVersion: "1.0", QualificationID: manifest.QualificationID,
			ScenarioID:       scenario.ScenarioID,
			RunID:            scenario.RunID,
			ScenarioStatus:   string(scenario.Status),
			Command:          scenario.Command,
			StartedAt:        scenario.StartedAt,
			CompletedAt:      scenario.CompletedAt,
			WitnessPrincipal: witnessPrincipal,
			WitnessRole:      CheckpointCustodyWitnessRole,
			WitnessKeyID:     witnessKeyID,
			ObservedAt:       "2026-11-11T10:59:00Z",
			Decision:         "ATTESTED",
			EvidenceSHA256:   evidenceDigests,
		}
		witnessPayloadBytes, err := json.Marshal(witnessPayload)
		if err != nil {
			t.Fatal(err)
		}
		witnessEnvelope, err := json.Marshal(custodyWitnessSignatureEnvelope{
			SchemaVersion: "1.0",
			Algorithm:     "Ed25519",
			Attestation:   witnessPayload,
			Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(witnessPrivateKey, witnessPayloadBytes)),
		})
		if err != nil {
			t.Fatal(err)
		}
		attestationPath := scenario.IndependentWitnessAttestation.Path
		add(&scenario.IndependentWitnessAttestation, attestationPath, witnessEnvelope)
		witnessKeys[witnessKeyID] = TrustedCheckpointCustodyWitnessKey{
			KeyID:     witnessKeyID,
			Principal: witnessPrincipal,
			Role:      CheckpointCustodyWitnessRole,
			PublicKey: witnessPublicKey,
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Review.ReviewerIdentity = "reviewer-2026"
	reviewerKeyID := "reviewer-key-2026"
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
		SchemaVersion:   "1.0",
		QualificationID: manifest.QualificationID,
		ManifestDigest:  hex.EncodeToString(manifestHash[:]),
		Reviewer:        manifest.Review.ReviewerIdentity,
		ReviewerKeyID:   reviewerKeyID,
		ReviewedAt:      manifest.Review.ReviewedAt,
		Decision:        manifest.Review.Status,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	envelope, err := json.Marshal(custodyDetachedSignature{
		SchemaVersion: "1.0",
		Reviewer:      manifest.Review.ReviewerIdentity,
		ReviewerKeyID: reviewerKeyID,
		Algorithm:     "Ed25519",
		Signature:     base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	add(&manifest.Review.Attestation, manifest.Review.Attestation.Path, envelope)
	reviewerKeys := map[string]TrustedCheckpointCustodyReviewerKey{reviewerKeyID: {KeyID: reviewerKeyID, Principal: manifest.Review.ReviewerIdentity, Role: CheckpointCustodyReviewerRole, PublicKey: publicKey, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}}

	report, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if report.VerifiedReferences != 17 {
		t.Fatalf("verified references = %d, want 17", report.VerifiedReferences)
	}

	// A key-ID alias with the same principal and public key must not be able to
	// relabel the signature: the selected key ID is part of the signed payload.
	aliasEnvelope := custodyDetachedSignature{}
	if err := json.Unmarshal(envelope, &aliasEnvelope); err != nil {
		t.Fatal(err)
	}
	aliasEnvelope.ReviewerKeyID = "reviewer-key-alias"
	aliasBytes, err := json.Marshal(aliasEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	aliasManifest := manifest
	aliasManifest.Review.Attestation.SHA256 = custodyEvidenceDigest(aliasBytes)
	aliasEvidence := make(custodyEvidenceMemory, len(evidence))
	for name, data := range evidence {
		aliasEvidence[name] = data
	}
	aliasEvidence[manifest.Review.Attestation.Path] = aliasBytes
	aliasKeys := map[string]TrustedCheckpointCustodyReviewerKey{
		"reviewer-key-alias": {KeyID: "reviewer-key-alias", Principal: manifest.Review.ReviewerIdentity, Role: CheckpointCustodyReviewerRole, PublicKey: publicKey, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	if _, err := VerifyCheckpointCustodyEvidence(aliasManifest, aliasEvidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys: aliasKeys, WitnessKeys: witnessKeys,
		Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC), MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("reviewer key-ID alias was accepted without a matching signature")
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

	for name, mutate := range map[string]func(*TrustedCheckpointCustodyReviewerKey){
		"revoked": func(key *TrustedCheckpointCustodyReviewerKey) {
			revokedAt := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
			key.RevokedAt = &revokedAt
		},
		"expired": func(key *TrustedCheckpointCustodyReviewerKey) {
			key.NotAfter = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
		},
		"wrong-role": func(key *TrustedCheckpointCustodyReviewerKey) { key.Role = CheckpointCustodyWitnessRole },
	} {
		invalidReviewerKeys := map[string]TrustedCheckpointCustodyReviewerKey{}
		for keyID, key := range reviewerKeys {
			mutate(&key)
			invalidReviewerKeys[keyID] = key
		}
		if _, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
			ReviewerKeys: invalidReviewerKeys, WitnessKeys: witnessKeys,
			Now: time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC), MaxEvidenceAge: 24 * time.Hour,
		}); err == nil {
			t.Fatalf("%s reviewer key was accepted", name)
		}
	}

	// Tamper a witness signature and update its artifact digest so verification
	// reaches the Ed25519 check instead of stopping at the SHA-256 check.
	witnessTamper := make(custodyEvidenceMemory, len(evidence))
	for name, data := range evidence {
		witnessTamper[name] = append([]byte(nil), data...)
	}
	tamperedWitnessManifest := manifest
	for i := range tamperedWitnessManifest.Scenarios {
		scenario := &tamperedWitnessManifest.Scenarios[i]
		if scenario.IndependentWitnessAttestation.Path == "" {
			continue
		}
		var witnessEnvelope custodyWitnessSignatureEnvelope
		if err := json.Unmarshal(witnessTamper[scenario.IndependentWitnessAttestation.Path], &witnessEnvelope); err != nil {
			t.Fatal(err)
		}
		witnessEnvelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		witnessBytes, err := json.Marshal(witnessEnvelope)
		if err != nil {
			t.Fatal(err)
		}
		witnessTamper[scenario.IndependentWitnessAttestation.Path] = witnessBytes
		scenario.IndependentWitnessAttestation.SHA256 = custodyEvidenceDigest(witnessBytes)
		break
	}
	if _, err := VerifyCheckpointCustodyEvidence(tamperedWitnessManifest, witnessTamper, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("invalid independent witness signature was accepted")
	}

	revokedWitnessKeys := make(map[string]TrustedCheckpointCustodyWitnessKey, len(witnessKeys))
	for keyID, key := range witnessKeys {
		revokedAt := time.Date(2026, 11, 11, 10, 59, 30, 0, time.UTC)
		key.RevokedAt = &revokedAt
		revokedWitnessKeys[keyID] = key
	}
	if _, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    revokedWitnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("revoked independent witness key was accepted")
	}

	if _, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 30 * time.Second,
	}); err == nil {
		t.Fatal("stale independent witness attestation was accepted")
	}

	// Re-hash a malformed envelope so strict decoding is exercised before
	// signature verification.
	malformedWitnessEvidence := make(custodyEvidenceMemory, len(evidence))
	for name, data := range evidence {
		malformedWitnessEvidence[name] = append([]byte(nil), data...)
	}
	malformedWitnessManifest := manifest
	for i := range malformedWitnessManifest.Scenarios {
		scenario := &malformedWitnessManifest.Scenarios[i]
		if scenario.IndependentWitnessAttestation.Path == "" {
			continue
		}
		original := string(malformedWitnessEvidence[scenario.IndependentWitnessAttestation.Path])
		encoded := []byte(strings.TrimSuffix(original, "}") + `, "unexpected": true}`)
		malformedWitnessEvidence[scenario.IndependentWitnessAttestation.Path] = encoded
		scenario.IndependentWitnessAttestation.SHA256 = custodyEvidenceDigest(encoded)
		break
	}
	if _, err := VerifyCheckpointCustodyEvidence(malformedWitnessManifest, malformedWitnessEvidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("unknown witness envelope field was accepted")
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
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
		MaxEvidenceAge: 24 * time.Hour,
	}); err == nil {
		t.Fatal("invalid detached signature was accepted")
	}

	if _, err := VerifyCheckpointCustodyEvidence(manifest, evidence, CheckpointCustodyEvidenceVerifierTrust{
		ReviewerKeys:   reviewerKeys,
		WitnessKeys:    witnessKeys,
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
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
			ReviewerKeys:   reviewerKeys,
			WitnessKeys:    witnessKeys,
			Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
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
		ReviewerKeys:   map[string]TrustedCheckpointCustodyReviewerKey{"reviewer-key": {KeyID: "reviewer-key", Principal: "independent-reviewer", Role: CheckpointCustodyReviewerRole, PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		Now:            time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC),
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
