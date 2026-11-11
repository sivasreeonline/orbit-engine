package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"\n\t"encoding/base64"\n\t"encoding/json"\n\t"path"\n\t"time"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	candidate := filepath.Join(root, filepath.FromSlash(relativePath))
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: evidence path escapes bundle root", ErrCorrupt)
	}
	current := root
	parts := strings.Split(filepath.FromSlash(relativePath), string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return nil, fmt.Errorf("inspect evidence path %q: %w", relativePath, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: evidence path contains a symlink", ErrCorrupt)
		}
		if current != candidate && !info.IsDir() {
			return nil, fmt.Errorf("%w: evidence path parent is not a directory", ErrCorrupt)
		}
		if current == candidate && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: evidence is not a regular file", ErrCorrupt)
		}
	}
	file, err := os.Open(candidate)
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
type CheckpointCustodyEvidenceVerifierTrust struct {
	ReviewerKeys map[string]ed25519.PublicKey
	Now          time.Time
	MaxEvidenceAge time.Duration
}

// CheckpointCustodyEvidenceVerificationReport is a result of reading and
// cryptographically checking evidence bytes. It is not provider qualification.
type CheckpointCustodyEvidenceVerificationReport struct {
	VerifiedReferences int
	VerifiedScenarios  []string
	ReviewerIdentity   string
	ManifestDigest     string
	VerifiedAt         time.Time
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
	verifyReference := func(reference CheckpointCustodyEvidenceReference) error {
		if _, exists := seenPaths[reference.Path]; exists {
			return fmt.Errorf("%w: evidence reference path is repeated", ErrCorrupt)
		}
		seenPaths[reference.Path] = struct{}{}
		data, readErr := source.ReadEvidence(reference.Path)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(digest[:]), reference.SHA256) {
			return fmt.Errorf("%w: evidence digest mismatch for %q", ErrCorrupt, reference.Path)
		}
		report.VerifiedReferences++
		return nil
	}
	for _, scenario := range manifest.Scenarios {
		for _, reference := range scenario.Evidence {
			if err := verifyReference(reference); err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
		}
		for _, reference := range scenario.IndependentWitnessEvidence {
			if err := verifyReference(reference); err != nil {
				return CheckpointCustodyEvidenceVerificationReport{}, err
			}
		}
		report.VerifiedScenarios = append(report.VerifiedScenarios, scenario.ScenarioID)
	}

	attestationBytes, err := source.ReadEvidence(manifest.Review.Attestation.Path)
	if err != nil {
		return CheckpointCustodyEvidenceVerificationReport{}, err
	}
	attestationHash := sha256.Sum256(attestationBytes)
	if !strings.EqualFold(hex.EncodeToString(attestationHash[:]), manifest.Review.Attestation.SHA256) {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review attestation digest mismatch", ErrCorrupt)
	}
	report.VerifiedReferences++

	// The review attestation is a canonical, typed payload signed by the
	// independently configured reviewer key. JSON input itself is not signed;
	// the signature covers the deterministic bytes below.
	var signatureEnvelope custodyDetachedSignature
	if err := json.Unmarshal(attestationBytes, &signatureEnvelope); err != nil {
		return CheckpointCustodyEvidenceVerificationReport{}, fmt.Errorf("%w: review signature envelope is invalid", ErrCorrupt)
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
	sort.Strings(report.VerifiedScenarios)
	return report, nil
}

func canonicalCustodyManifestBytes(manifest CheckpointCustodyQualificationManifest) ([]byte, error) {
	// The detached review signature cannot sign an envelope that contains its
	// own digest. Normalize only that digest field; all other manifest fields,
	// including the attestation path and media type, remain signed.
	manifest.Review.Attestation.SHA256 = strings.Repeat("0", 64)
	return json.Marshal(manifest)
}
