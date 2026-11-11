package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CheckpointCustodyEvidenceSource resolves evidence paths beneath one explicit
// bundle root. Implementations must not follow symlinks outside that root.
type CheckpointCustodyEvidenceSource interface {
	ReadEvidence(relativePath string) ([]byte, error)
}

// FilesystemCheckpointCustodyEvidenceSource is a local, read-only evidence
// source. It rejects symlinks and non-regular files before reading bytes.
type FilesystemCheckpointCustodyEvidenceSource struct {
	Root string
}

func (s FilesystemCheckpointCustodyEvidenceSource) ReadEvidence(relativePath string) ([]byte, error) {
	if err := validateCustodyRelativePath(relativePath); err != nil {
		return nil, err
	}
	rootPath, err := filepath.Abs(s.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	// os.Root confines opens to the configured bundle, preventing path traversal
	// and symlink escapes outside it. The preceding Lstat checks reject symlink
	// entries observed during inspection; this is not an atomic no-symlink-open
	// guarantee against concurrent replacement within the bundle root.
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	defer root.Close()

	current := ""
	parts := strings.Split(relativePath, "/")
	for i, part := range parts {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, statErr := root.Lstat(current)
		if statErr != nil {
			return nil, fmt.Errorf("inspect evidence path %q: %w", relativePath, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: evidence path contains a symlink", ErrCorrupt)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("%w: evidence path parent is not a directory", ErrCorrupt)
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: evidence is not a regular file", ErrCorrupt)
		}
	}

	file, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		return nil, fmt.Errorf("open evidence %q: %w", relativePath, err)
	}
	defer file.Close()
	const maxEvidenceBytes = 64 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxEvidenceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read evidence %q: %w", relativePath, err)
	}
	if len(data) > maxEvidenceBytes {
		return nil, fmt.Errorf("%w: evidence exceeds 64 MiB limit", ErrCorrupt)
	}
	return data, nil
}

func validateCustodyRelativePath(value string) error {
	if strings.TrimSpace(value) == "" || filepath.IsAbs(value) ||
		strings.Contains(value, "\\") || hasWindowsCustodyDrivePrefix(value) ||
		strings.ContainsRune(value, 0) || pathCleanSlash(value) != value ||
		value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("%w: custody evidence path is unsafe", ErrCorrupt)
	}
	return nil
}

func pathCleanSlash(value string) string {
	// Paths in manifests are portable slash-separated names, regardless of host OS.
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))), "./")
}

// CheckpointCustodyEvidenceVerifierTrust is injected by the caller. This
// package does not discover trust roots, establish reviewer independence, or
// provide trusted time.
const CheckpointCustodyWitnessRole = "INDEPENDENT_CUSTODY_WITNESS"

type TrustedCheckpointCustodyWitnessKey struct {
	KeyID     string
	Principal string
	Role      string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
}

type CheckpointCustodyEvidenceVerifierTrust struct {
	ReviewerKeys   map[string]ed25519.PublicKey
	WitnessKeys    map[string]TrustedCheckpointCustodyWitnessKey
	Now            time.Time
	MaxEvidenceAge time.Duration
}

// CheckpointCustodyEvidenceVerificationReport is a result of reading and
// cryptographically checking evidence bytes. It is not provider qualification.
type CheckpointCustodyEvidenceVerificationReport struct {
	VerifiedReferences    int
	VerifiedScenarios     []string
	ReviewerIdentity      string
	ReviewDecision        string
	ManifestDeclaresReady bool
	ManifestDigest        string
	VerifiedAt            time.Time
}

type custodyReviewAttestation struct {
	SchemaVersion   string `json:"schema_version"`
	QualificationID string `json:"qualification_id"`
	ManifestDigest  string `json:"manifest_digest"`
	Reviewer        string `json:"reviewer"`
	ReviewedAt      string `json:"reviewed_at"`
	Decision        string `json:"decision"`
}

type custodyDetachedSignature struct {
	SchemaVersion string `json:"schema_version"`
	Reviewer      string `json:"reviewer"`
	Algorithm     string `json:"algorithm"`
	Signature     string `json:"signature"`
}

type custodyWitnessAttestation struct {
	SchemaVersion    string   `json:"schema_version"`
	QualificationID  string   `json:"qualification_id"`
	ScenarioID       string   `json:"scenario_id"`
	RunID            string   `json:"run_id"`
	ScenarioStatus   string   `json:"scenario_status"`
	Command          string   `json:"command"`
	StartedAt        string   `json:"started_at"`
	CompletedAt      string   `json:"completed_at"`
	WitnessPrincipal string   `json:"witness_principal"`
	WitnessRole      string   `json:"witness_role"`
	WitnessKeyID     string   `json:"witness_key_id"`
	ObservedAt       string   `json:"observed_at"`
	Decision         string   `json:"decision"`
	EvidenceSHA256   []string `json:"evidence_sha256"`
}

type custodyWitnessSignatureEnvelope struct {
	SchemaVersion string                    `json:"schema_version"`
	Algorithm     string                    `json:"algorithm"`
	Attestation   custodyWitnessAttestation `json:"attestation"`
	Signature     string                    `json:"signature"`
}

func VerifyCheckpointCustodyEvidence(
	manifest CheckpointCustodyQualificationManifest,
	source CheckpointCustodyEvidenceSource,
	trust CheckpointCustodyEvidenceVerifierTrust,
) (CheckpointCustodyEvidenceVerificationReport, error) {
	var report CheckpointCustodyEvidenceVerificationReport
	if source == nil {
		return report, fmt.Errorf("%w: evidence source is required", ErrCorrupt)
	}
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); err != nil {
		return report, err
	}
	if trust.Now.IsZero() || trust.MaxEvidenceAge <= 0 {
		return report, fmt.Errorf("%w: verification time and positive evidence age limit are required", ErrCorrupt)
	}
	if len(trust.ReviewerKeys) == 0 {
		return report, fmt.Errorf("%w: external reviewer trust keys are required", ErrCorrupt)
	}
	manifestBytes, err := canonicalCustodyManifestBytes(manifest)
	if err != nil {
		return report, err
	}
	manifestHash := sha256.Sum256(manifestBytes)
	report.ManifestDigest = hex.EncodeToString(manifestHash[:])
	report.VerifiedAt = trust.Now.UTC()

	seenPaths := make(map[string]struct{})
	verifyReference := func(reference CheckpointCustodyEvidenceReference) ([]byte, error) {
		if _, exists := seenPaths[reference.Path]; exists {
			return nil, fmt.Errorf("%w: evidence reference path is repeated", ErrCorrupt)
		}
		seenPaths[reference.Path] = struct{}{}
		data, readErr := source.ReadEvidence(reference.Path)
		if readErr != nil {
			return nil, readErr
		}
		digest := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(digest[:]), reference.SHA256) {
			return nil, fmt.Errorf("%w: evidence digest mismatch for %q", ErrCorrupt, reference.Path)
		}
		report.VerifiedReferences++
		return data, nil
	}
	for _, scenario := range manifest.Scenarios {
		for _, reference := range scenario.Evidence {
			if _, err := verifyReference(reference); err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
		}
		for _, reference := range scenario.IndependentWitnessEvidence {
			if _, err := verifyReference(reference); err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
		}
		if len(scenario.IndependentWitnessEvidence) > 0 {
			if len(trust.WitnessKeys) == 0 {
				return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: independent witness trust keys are required", ErrCorrupt)
			}
			witnessBytes, err := verifyReference(scenario.IndependentWitnessAttestation)
			if err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
			if err := verifyCustodyWitnessAttestation(manifest, scenario, witnessBytes, trust); err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
		}
		report.VerifiedScenarios = append(report.VerifiedScenarios, scenario.ScenarioID)
	}

	attestationBytes, err := verifyReference(manifest.Review.Attestation)
	if err != nil {
		return CheckpointCustodyEvidenceVerificationReport{}, err
	}

	// The review attestation is a canonical, typed payload signed by the
	// independently configured reviewer key. JSON input itself is not signed;
	// the signature covers the deterministic bytes below.
	var signatureEnvelope custodyDetachedSignature
	decoder := json.NewDecoder(bytes.NewReader(attestationBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signatureEnvelope); err != nil {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature envelope is invalid", ErrCorrupt)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature envelope has trailing data", ErrCorrupt)
	}
	canonicalEnvelope, err := json.Marshal(signatureEnvelope)
	if err != nil || !bytes.Equal(canonicalEnvelope, attestationBytes) {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature envelope is not canonical JSON", ErrCorrupt)
	}
	if signatureEnvelope.SchemaVersion != "1.0" || signatureEnvelope.Algorithm != "Ed25519" ||
		signatureEnvelope.Reviewer != manifest.Review.ReviewerIdentity {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature identity or algorithm mismatch", ErrCorrupt)
	}
	publicKey, ok := trust.ReviewerKeys[signatureEnvelope.Reviewer]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: reviewer key is not trusted", ErrCorrupt)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureEnvelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature encoding is invalid", ErrCorrupt)
	}
	payload := custodyReviewAttestation{
		SchemaVersion: "1.0", QualificationID: manifest.QualificationID,
		ManifestDigest: report.ManifestDigest, Reviewer: signatureEnvelope.Reviewer,
		ReviewedAt: manifest.Review.ReviewedAt, Decision: manifest.Review.Status,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return CheckpointCustodyEvidenceVerificationReport{}, err
	}
	if !ed25519.Verify(publicKey, payloadBytes, signature) {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review attestation signature is invalid", ErrCorrupt)
	}
	reviewedAt, err := time.Parse(time.RFC3339Nano, manifest.Review.ReviewedAt)
	if err != nil || reviewedAt.After(trust.Now) || trust.Now.Sub(reviewedAt) > trust.MaxEvidenceAge {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review attestation is outside the accepted age window", ErrCorrupt)
	}
	report.ReviewerIdentity = signatureEnvelope.Reviewer
	report.ReviewDecision = manifest.Review.Status
	// This is only the manifest's declared readiness. Cryptographic byte
	// verification does not prove that provider behavior or evidence semantics
	// satisfy the underlying custody invariants.
	report.ManifestDeclaresReady = CheckpointCustodyQualificationReady(manifest)
	sort.Strings(report.VerifiedScenarios)
	return report, nil
}

func verifyCustodyWitnessAttestation(
	manifest CheckpointCustodyQualificationManifest,
	scenario CheckpointCustodyScenarioEvidence,
	data []byte,
	trust CheckpointCustodyEvidenceVerifierTrust,
) error {
	var envelope custodyWitnessSignatureEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("%w: witness signature envelope is invalid", ErrCorrupt)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: witness signature envelope has trailing data", ErrCorrupt)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("%w: witness signature envelope is not canonical JSON", ErrCorrupt)
	}

	attestation := envelope.Attestation
	if envelope.SchemaVersion != "1.0" || envelope.Algorithm != "Ed25519" ||
		attestation.SchemaVersion != "1.0" || attestation.WitnessRole != CheckpointCustodyWitnessRole ||
		attestation.Decision != "ATTESTED" || attestation.QualificationID != manifest.QualificationID ||
		attestation.ScenarioID != scenario.ScenarioID || attestation.RunID != scenario.RunID ||
		attestation.ScenarioStatus != string(scenario.Status) || attestation.Command != scenario.Command ||
		attestation.StartedAt != scenario.StartedAt || attestation.CompletedAt != scenario.CompletedAt ||
		strings.TrimSpace(attestation.WitnessPrincipal) == "" ||
		attestation.WitnessPrincipal == manifest.Review.ReviewerIdentity {
		return fmt.Errorf("%w: witness attestation identity, role, or scenario binding is invalid", ErrCorrupt)
	}

	trusted, ok := trust.WitnessKeys[attestation.WitnessKeyID]
	if !ok || trusted.KeyID != attestation.WitnessKeyID ||
		trusted.Principal != attestation.WitnessPrincipal || trusted.Role != CheckpointCustodyWitnessRole ||
		len(trusted.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: independent witness key is not trusted", ErrCorrupt)
	}
	observedAt, err := time.Parse(time.RFC3339Nano, attestation.ObservedAt)
	if err != nil || observedAt.Before(trusted.NotBefore) || observedAt.After(trusted.NotAfter) ||
		observedAt.After(trust.Now) || trust.Now.Sub(observedAt) > trust.MaxEvidenceAge {
		return fmt.Errorf("%w: witness observation time is outside the accepted window", ErrCorrupt)
	}
	completedAt, err := time.Parse(time.RFC3339Nano, scenario.CompletedAt)
	if err != nil || observedAt.Before(completedAt) {
		return fmt.Errorf("%w: witness observation predates scenario completion", ErrCorrupt)
	}
	if trusted.RevokedAt != nil && !trust.Now.Before(*trusted.RevokedAt) {
		return fmt.Errorf("%w: independent witness key is revoked", ErrCorrupt)
	}

	expectedDigests := make([]string, 0, len(scenario.IndependentWitnessEvidence))
	for _, reference := range scenario.IndependentWitnessEvidence {
		expectedDigests = append(expectedDigests, strings.ToLower(reference.SHA256))
	}
	sort.Strings(expectedDigests)
	actualDigests := append([]string(nil), attestation.EvidenceSHA256...)
	for _, digest := range actualDigests {
		if !validAuditDigest(digest) {
			return fmt.Errorf("%w: witness evidence digest is invalid", ErrCorrupt)
		}
	}
	sort.Strings(actualDigests)
	if len(actualDigests) != len(expectedDigests) {
		return fmt.Errorf("%w: witness attestation evidence set is incomplete", ErrCorrupt)
	}
	for i := range expectedDigests {
		if actualDigests[i] != expectedDigests[i] {
			return fmt.Errorf("%w: witness attestation evidence set does not match the manifest", ErrCorrupt)
		}
	}

	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: witness signature encoding is invalid", ErrCorrupt)
	}
	payload, err := json.Marshal(attestation)
	if err != nil || !ed25519.Verify(trusted.PublicKey, payload, signature) {
		return fmt.Errorf("%w: witness signature verification failed", ErrCorrupt)
	}
	return nil
}

func canonicalCustodyManifestBytes(manifest CheckpointCustodyQualificationManifest) ([]byte, error) {
	// The detached review signature cannot sign an envelope that contains its
	// own digest. Normalize only that digest field; all other manifest fields,
	// including the attestation path and media type, remain signed.
	manifest.Review.Attestation.SHA256 = strings.Repeat("0", 64)
	return json.Marshal(manifest)
}
