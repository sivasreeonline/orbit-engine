package journal

import (
	"fmt"
	"path"
	"strings"
	"time"
)

type CheckpointCustodyScenario struct {
	ID                         string
	Category                   string
	FailureInjection           string
	RequiredInvariant          string
	RequiredEvidence           []string
	RequiresIndependentWitness bool
}

var checkpointCustodyScenarios = []CheckpointCustodyScenario{
	{ID: "CUSTODY-001", Category: "atomicity", FailureInjection: "Crash before initial checkpoint and receipt commit", RequiredInvariant: "Neither artifact is visible unless both are durably committed", RequiredEvidence: []string{"transaction trace", "post-crash store inspection"}},
	{ID: "CUSTODY-002", Category: "compare-and-store", FailureInjection: "Submit a checkpoint against the exact current predecessor", RequiredInvariant: "A valid successor advances exactly from the expected checkpoint", RequiredEvidence: []string{"before and after checkpoint heads", "store acknowledgement"}},
	{ID: "CUSTODY-003", Category: "concurrency", FailureInjection: "Race two writers using the same expected predecessor", RequiredInvariant: "At most one successor commits and the losing writer observes a conflict", RequiredEvidence: []string{"concurrent request trace", "final stored head"}},
	{ID: "CUSTODY-004", Category: "fork-rejection", FailureInjection: "Submit a different checkpoint at an already claimed sequence", RequiredInvariant: "A fork or same-sequence replay is rejected without changing the accepted head", RequiredEvidence: []string{"rejected request", "unchanged head proof"}},
	{ID: "CUSTODY-005", Category: "receipt-binding", FailureInjection: "Attempt to store a receipt bound to a different checkpoint digest", RequiredInvariant: "Checkpoint and receipt are validated and persisted as one matching pair", RequiredEvidence: []string{"mismatch test trace", "post-rejection pair inspection"}},
	{ID: "CUSTODY-006", Category: "lost-acknowledgement", FailureInjection: "Drop the client acknowledgement after the provider commit", RequiredInvariant: "Read-after-uncertain-outcome recovers the original checkpoint and receipt without creating a new sequence", RequiredEvidence: []string{"fault injection trace", "reconciliation read"}},
	{ID: "CUSTODY-007", Category: "retention-lock", FailureInjection: "Attempt overwrite or deletion before immutable_until", RequiredInvariant: "Provider-enforced retention prevents unauthorized mutation", RequiredEvidence: []string{"provider retention configuration", "denied mutation audit"}},
	{ID: "CUSTODY-008", Category: "retention-lock", FailureInjection: "Attempt to shorten the retention horizon", RequiredInvariant: "The accepted retention horizon cannot be weakened by an ordinary writer", RequiredEvidence: []string{"policy before and after", "provider audit event"}},
	{ID: "CUSTODY-009", Category: "backup-restore", FailureInjection: "Restore a backup that predates the independently retained checkpoint", RequiredInvariant: "Recovery detects rollback and refuses to treat the restored prefix as current", RequiredEvidence: []string{"backup identity", "external checkpoint comparison"}},
	{ID: "CUSTODY-010", Category: "availability", FailureInjection: "Make the primary custody endpoint unavailable", RequiredInvariant: "No unqualified fallback is treated as equivalent custody and no acknowledgement is fabricated", RequiredEvidence: []string{"outage trace", "fail-closed decision record"}},
	{ID: "CUSTODY-011", Category: "independence", FailureInjection: "Present a receipt from the checkpoint signer or an untrusted custody principal", RequiredInvariant: "Custody trust policy rejects same-principal or untrusted custodian assertions", RequiredEvidence: []string{"identity policy", "rejected receipt trace"}, RequiresIndependentWitness: true},
	{ID: "CUSTODY-012", Category: "cross-domain-recovery", FailureInjection: "Recover from a separately administered custody domain", RequiredInvariant: "Independent custodian evidence binds the same ledger epoch and latest checkpoint digest", RequiredEvidence: []string{"domain ownership evidence", "cross-domain recovery trace"}, RequiresIndependentWitness: true},
}

func CheckpointCustodyQualificationCatalog() []CheckpointCustodyScenario {
	result := make([]CheckpointCustodyScenario, len(checkpointCustodyScenarios))
	for i, scenario := range checkpointCustodyScenarios {
		result[i] = scenario
		result[i].RequiredEvidence = append([]string(nil), scenario.RequiredEvidence...)
	}
	return result
}

type CheckpointCustodyEvidenceReference struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	MediaType string `json:"media_type"`
}

type CheckpointCustodyScenarioEvidence struct {
	ScenarioID                    string `json:"scenario_id"`
	Status                        EvidenceStatus `json:"status"`
	RunID                         string `json:"run_id"`
	Command                       string `json:"command"`
	StartedAt                     string `json:"started_at"`
	CompletedAt                   string `json:"completed_at"`
	Evidence                      []CheckpointCustodyEvidenceReference `json:"evidence"`
	IndependentWitnessEvidence    []CheckpointCustodyEvidenceReference `json:"independent_witness_evidence,omitempty"`
	IndependentWitnessAttestation CheckpointCustodyEvidenceReference `json:"independent_witness_attestation,omitempty"`
}

type CheckpointCustodyAdapterIdentity struct {
	Provider        string `json:"provider"`
	Product         string `json:"product"`
	APIOrSDKVersion string `json:"api_or_sdk_version"`
	AccountScope    string `json:"account_scope"`
	Region          string `json:"region"`
	StorageClass    string `json:"storage_class"`
	RetentionMode   string `json:"retention_mode"`
}

type CheckpointCustodyEnvironment struct {
	OS                     string `json:"os"`
	Kernel                 string `json:"kernel"`
	Architecture           string `json:"architecture"`
	Endpoint               string `json:"endpoint"`
	EncryptionAtRest       string `json:"encryption_at_rest"`
	Versioning             string `json:"versioning"`
	Replication             string `json:"replication"`
	RetentionConfiguration string `json:"retention_configuration"`
}

type CheckpointCustodyReview struct {
	Status           string `json:"status"`
	ReviewerIdentity string `json:"reviewer_identity"`
	ReviewedAt       string `json:"reviewed_at"`
	Attestation      CheckpointCustodyEvidenceReference `json:"attestation"`
}

type CheckpointCustodyQualificationManifest struct {
	SchemaVersion   string `json:"schema_version"`
	QualificationID string `json:"qualification_id"`
	Adapter         CheckpointCustodyAdapterIdentity `json:"adapter"`
	Environment     CheckpointCustodyEnvironment `json:"environment"`
	Scenarios       []CheckpointCustodyScenarioEvidence `json:"scenarios"`
	Review          CheckpointCustodyReview `json:"review"`
}

func validateCustodyEvidenceReference(reference CheckpointCustodyEvidenceReference) error {
	if strings.TrimSpace(reference.Path) == "" || path.IsAbs(reference.Path) ||
		strings.Contains(reference.Path, "\\") || hasWindowsCustodyDrivePrefix(reference.Path) || strings.ContainsRune(reference.Path, 0) ||
		path.Clean(reference.Path) != reference.Path || reference.Path == "." ||
		reference.Path == ".." || strings.HasPrefix(reference.Path, "../") {
		return fmt.Errorf("%w: custody evidence path is unsafe", ErrCorrupt)
	}
	if !validAuditDigest(reference.SHA256) || strings.TrimSpace(reference.MediaType) == "" {
		return fmt.Errorf("%w: custody evidence digest or media type is invalid", ErrCorrupt)
	}
	return nil
}

func hasWindowsCustodyDrivePrefix(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':'
}

func ValidateCheckpointCustodyQualificationManifest(manifest CheckpointCustodyQualificationManifest) error {
	if manifest.SchemaVersion != "1.0" || strings.TrimSpace(manifest.QualificationID) == "" {
		return fmt.Errorf("%w: custody qualification identity is invalid", ErrCorrupt)
	}
	adapter := manifest.Adapter
	if strings.TrimSpace(adapter.Provider) == "" || strings.TrimSpace(adapter.Product) == "" ||
		strings.TrimSpace(adapter.APIOrSDKVersion) == "" || strings.TrimSpace(adapter.AccountScope) == "" ||
		strings.TrimSpace(adapter.Region) == "" || strings.TrimSpace(adapter.StorageClass) == "" ||
		strings.TrimSpace(adapter.RetentionMode) == "" {
		return fmt.Errorf("%w: actual custody adapter identity is incomplete", ErrCorrupt)
	}
	environment := manifest.Environment
	if strings.TrimSpace(environment.OS) == "" || strings.TrimSpace(environment.Kernel) == "" ||
		strings.TrimSpace(environment.Architecture) == "" || strings.TrimSpace(environment.Endpoint) == "" ||
		strings.TrimSpace(environment.EncryptionAtRest) == "" || strings.TrimSpace(environment.Versioning) == "" ||
		strings.TrimSpace(environment.Replication) == "" || strings.TrimSpace(environment.RetentionConfiguration) == "" {
		return fmt.Errorf("%w: custody environment is incomplete", ErrCorrupt)
	}
	if len(manifest.Scenarios) != len(checkpointCustodyScenarios) {
		return fmt.Errorf("%w: custody qualification must contain exactly %d scenarios", ErrCorrupt, len(checkpointCustodyScenarios))
	}
	seen := make(map[string]struct{}, len(manifest.Scenarios))
	expected := make(map[string]CheckpointCustodyScenario, len(checkpointCustodyScenarios))
	for _, scenario := range checkpointCustodyScenarios {
		expected[scenario.ID] = scenario
	}
	allEvidencePaths := make(map[string]struct{})
	allEvidenceDigests := make(map[string]struct{})
	for _, result := range manifest.Scenarios {
		scenario, ok := expected[result.ScenarioID]
		if !ok {
			return fmt.Errorf("%w: unknown custody scenario %q", ErrCorrupt, result.ScenarioID)
		}
		if _, ok := seen[result.ScenarioID]; ok {
			return fmt.Errorf("%w: duplicate custody scenario %q", ErrCorrupt, result.ScenarioID)
		}
		seen[result.ScenarioID] = struct{}{}
		switch result.Status {
		case EvidencePass, EvidenceFail, EvidenceBlocked, EvidenceSkipped:
		default:
			return fmt.Errorf("%w: invalid custody scenario status", ErrCorrupt)
		}
		if strings.TrimSpace(result.RunID) == "" || strings.TrimSpace(result.Command) == "" {
			return fmt.Errorf("%w: custody scenario run identity is incomplete", ErrCorrupt)
		}
		started, err := time.Parse(time.RFC3339Nano, result.StartedAt)
		if err != nil {
			return fmt.Errorf("%w: custody scenario start time is invalid", ErrCorrupt)
		}
		completed, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
		if err != nil || completed.Before(started) {
			return fmt.Errorf("%w: custody scenario completion time is invalid", ErrCorrupt)
		}
		if len(result.Evidence) == 0 {
			return fmt.Errorf("%w: custody scenario has no evidence", ErrCorrupt)
		}
		for _, reference := range result.Evidence {
			if err := validateCustodyEvidenceReference(reference); err != nil {
				return err
			}
			allEvidencePaths[reference.Path] = struct{}{}
			allEvidenceDigests[reference.SHA256] = struct{}{}
		}
		if scenario.RequiresIndependentWitness && len(result.IndependentWitnessEvidence) == 0 {
			return fmt.Errorf("%w: custody scenario %s requires independent witness evidence", ErrCorrupt, result.ScenarioID)
		}
		for _, reference := range result.IndependentWitnessEvidence {
			if err := validateCustodyEvidenceReference(reference); err != nil {
				return err
			}
			if _, duplicate := allEvidencePaths[reference.Path]; duplicate {
				return fmt.Errorf("%w: independent witness evidence must use a distinct path", ErrCorrupt)
			}
			if _, duplicate := allEvidenceDigests[reference.SHA256]; duplicate {
				return fmt.Errorf("%w: independent witness evidence must have a distinct digest", ErrCorrupt)
			}
			allEvidencePaths[reference.Path] = struct{}{}
			allEvidenceDigests[reference.SHA256] = struct{}{}
		}
	}
	if manifest.Review.Status != "APPROVED" && manifest.Review.Status != "PENDING" && manifest.Review.Status != "REJECTED" {
		return fmt.Errorf("%w: custody review status is invalid", ErrCorrupt)
	}
	if strings.TrimSpace(manifest.Review.ReviewerIdentity) == "" {
		return fmt.Errorf("%w: custody reviewer identity is missing", ErrCorrupt)
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.Review.ReviewedAt); err != nil {
		return fmt.Errorf("%w: custody review timestamp is invalid", ErrCorrupt)
	}
	if err := validateCustodyEvidenceReference(manifest.Review.Attestation); err != nil {
		return err
	}
	if _, duplicate := allEvidencePaths[manifest.Review.Attestation.Path]; duplicate {
		return fmt.Errorf("%w: review attestation must be a distinct evidence artifact", ErrCorrupt)
	}
	if _, duplicate := allEvidenceDigests[manifest.Review.Attestation.SHA256]; duplicate {
		return fmt.Errorf("%w: review attestation digest must be distinct", ErrCorrupt)
	}
	return nil
}

func CheckpointCustodyQualificationReady(manifest CheckpointCustodyQualificationManifest) bool {
	if ValidateCheckpointCustodyQualificationManifest(manifest) != nil || manifest.Review.Status != "APPROVED" {
		return false
	}
	for _, result := range manifest.Scenarios {
		if result.Status != EvidencePass {
			return false
		}
	}
	return true
}
