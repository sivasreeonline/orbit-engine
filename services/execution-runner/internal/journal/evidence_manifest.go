package journal

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

type EvidenceStatus string

const (
	EvidencePass    EvidenceStatus = "PASS"
	EvidenceFail    EvidenceStatus = "FAIL"
	EvidenceBlocked EvidenceStatus = "BLOCKED"
	EvidenceSkipped EvidenceStatus = "SKIPPED"
)

type EvidenceReference struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type QualificationTestEvidence struct {
	ScenarioID  string              `json:"scenario_id"`
	Status      EvidenceStatus      `json:"status"`
	TestRunID   string              `json:"test_run_id"`
	Command     string              `json:"command"`
	StartedAt   string              `json:"started_at"`
	CompletedAt string              `json:"completed_at"`
	Evidence    []EvidenceReference `json:"evidence"`
	Notes       string              `json:"notes,omitempty"`
}

type JournalAdapterIdentity struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Driver        string `json:"driver"`
	DriverVersion string `json:"driver_version"`
}

type QualificationEnvironment struct {
	OperatingSystem string `json:"operating_system"`
	Kernel          string `json:"kernel"`
	Architecture    string `json:"architecture"`
	Filesystem      string `json:"filesystem"`
	MountOptions    string `json:"mount_options"`
	StorageTopology string `json:"storage_topology"`
}

type DurabilityProfile struct {
	AcknowledgementBarrier string `json:"acknowledgement_barrier"`
	PowerLossModel         string `json:"power_loss_model"`
	SyncPolicy             string `json:"sync_policy"`
	WALCheckpointPolicy    string `json:"wal_checkpoint_policy"`
}

type IndependentReview struct {
	Status           string            `json:"status"`
	ReviewerIdentity string            `json:"reviewer_identity"`
	ReviewedAt       string            `json:"reviewed_at"`
	Attestation      EvidenceReference `json:"attestation"`
}

type QualificationEvidenceManifest struct {
	SchemaVersion   string                      `json:"schema_version"`
	QualificationID string                      `json:"qualification_id"`
	CatalogVersion  string                      `json:"catalog_version"`
	Adapter         JournalAdapterIdentity      `json:"adapter"`
	Environment     QualificationEnvironment    `json:"environment"`
	Durability      DurabilityProfile           `json:"durability_profile"`
	Tests           []QualificationTestEvidence `json:"tests"`
	Review          IndependentReview           `json:"independent_review"`
}

var evidenceSHA256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func validateEvidenceReference(ref EvidenceReference) error {
	if strings.TrimSpace(ref.Path) == "" || path.IsAbs(ref.Path) || strings.Contains(ref.Path, "\\") || strings.ContainsRune(ref.Path, 0) || path.Clean(ref.Path) != ref.Path || ref.Path == "." || strings.HasPrefix(ref.Path, "../") || ref.Path == ".." {
		return fmt.Errorf("%w: evidence path must be a clean relative path", ErrCorrupt)
	}
	if !evidenceSHA256Pattern.MatchString(ref.SHA256) {
		return fmt.Errorf("%w: evidence %s has invalid SHA-256", ErrCorrupt, ref.Path)
	}
	if strings.TrimSpace(ref.MediaType) == "" {
		return fmt.Errorf("%w: evidence %s has no media type", ErrCorrupt, ref.Path)
	}
	return nil
}

// ValidateQualificationEvidenceManifest validates structure and complete scenario
// coverage. It does not fetch evidence files, verify their hashes/signatures, or
// establish reviewer independence; those require an external verifier.
func ValidateQualificationEvidenceManifest(manifest QualificationEvidenceManifest) error {
	if manifest.SchemaVersion != "1.0" || strings.TrimSpace(manifest.QualificationID) == "" || strings.TrimSpace(manifest.CatalogVersion) == "" {
		return fmt.Errorf("%w: manifest identity or schema version is missing", ErrCorrupt)
	}
	requiredStrings := []string{
		manifest.Adapter.Name, manifest.Adapter.Version, manifest.Adapter.Driver, manifest.Adapter.DriverVersion,
		manifest.Environment.OperatingSystem, manifest.Environment.Kernel, manifest.Environment.Architecture,
		manifest.Environment.Filesystem, manifest.Environment.MountOptions, manifest.Environment.StorageTopology,
		manifest.Durability.AcknowledgementBarrier, manifest.Durability.PowerLossModel,
		manifest.Durability.SyncPolicy, manifest.Durability.WALCheckpointPolicy,
	}
	for _, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: adapter, environment, and durability profile fields are mandatory", ErrCorrupt)
		}
	}
	if len(manifest.Tests) != len(RequiredQualificationScenarios) {
		return fmt.Errorf("%w: got %d test records, want exactly %d", ErrCorrupt, len(manifest.Tests), len(RequiredQualificationScenarios))
	}
	required := make(map[string]bool, len(RequiredQualificationScenarios))
	for _, scenario := range RequiredQualificationScenarios {
		required[scenario.ID] = true
	}
	seen := make(map[string]bool, len(manifest.Tests))
	for _, test := range manifest.Tests {
		if !required[test.ScenarioID] || seen[test.ScenarioID] {
			return fmt.Errorf("%w: unknown or duplicate scenario ID %q", ErrCorrupt, test.ScenarioID)
		}
		seen[test.ScenarioID] = true
		switch test.Status {
		case EvidencePass, EvidenceFail, EvidenceBlocked, EvidenceSkipped:
		default:
			return fmt.Errorf("%w: scenario %s has invalid status %q", ErrCorrupt, test.ScenarioID, test.Status)
		}
		if strings.TrimSpace(test.TestRunID) == "" || strings.TrimSpace(test.Command) == "" {
			return fmt.Errorf("%w: scenario %s lacks test run identity or command", ErrCorrupt, test.ScenarioID)
		}
		started, startErr := time.Parse(time.RFC3339, test.StartedAt)
		completed, completeErr := time.Parse(time.RFC3339, test.CompletedAt)
		if startErr != nil || completeErr != nil || completed.Before(started) {
			return fmt.Errorf("%w: scenario %s has invalid test timestamps", ErrCorrupt, test.ScenarioID)
		}
		if len(test.Evidence) == 0 {
			return fmt.Errorf("%w: scenario %s has no evidence references", ErrCorrupt, test.ScenarioID)
		}
		for _, ref := range test.Evidence {
			if err := validateEvidenceReference(ref); err != nil {
				return fmt.Errorf("scenario %s: %w", test.ScenarioID, err)
			}
		}
	}
	if manifest.Review.Status != "APPROVED" && manifest.Review.Status != "PENDING" && manifest.Review.Status != "REJECTED" {
		return fmt.Errorf("%w: invalid independent review status %q", ErrCorrupt, manifest.Review.Status)
	}
	if strings.TrimSpace(manifest.Review.ReviewerIdentity) == "" {
		return fmt.Errorf("%w: independent reviewer identity is missing", ErrCorrupt)
	}
	if _, err := time.Parse(time.RFC3339, manifest.Review.ReviewedAt); err != nil {
		return fmt.Errorf("%w: independent review timestamp is invalid", ErrCorrupt)
	}
	return validateEvidenceReference(manifest.Review.Attestation)
}

// QualificationEvidenceReady is true only when every catalog scenario passed
// and an independent reviewer marked the evidence package approved. This is a
// readiness predicate, not cryptographic verification or deployment authority.
func QualificationEvidenceReady(manifest QualificationEvidenceManifest) bool {
	if ValidateQualificationEvidenceManifest(manifest) != nil || manifest.Review.Status != "APPROVED" {
		return false
	}
	for _, test := range manifest.Tests {
		if test.Status != EvidencePass {
			return false
		}
	}
	return true
}
