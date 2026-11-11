package journal

import (
	"errors"
	"testing"
)

func custodyQualificationFixture() CheckpointCustodyQualificationManifest {
	manifest := CheckpointCustodyQualificationManifest{
		SchemaVersion: "1.1", QualificationID: "custody-qualification-2026-01",
		Adapter: CheckpointCustodyAdapterIdentity{
			Provider: "test-provider", Product: "object-lock-service", APIOrSDKVersion: "v1",
			AccountScope: "test-account", Region: "test-region", StorageClass: "immutable-object",
			RetentionMode: "compliance",
		},
		Environment: CheckpointCustodyEnvironment{
			OS: "linux", Kernel: "6.x", Architecture: "amd64", Endpoint: "https://custody.invalid",
			EncryptionAtRest: "provider-managed", Versioning: "enabled", Replication: "cross-region",
			RetentionConfiguration: "compliance-lock-365d",
		},
		Review: CheckpointCustodyReview{
			Status: "APPROVED", ReviewerIdentity: "independent-reviewer",
			ReviewedAt: "2026-11-11T10:00:00Z",
			Attestation: CheckpointCustodyEvidenceReference{
				Path:      "evidence/review-attestation.json",
				SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				MediaType: "application/json",
			},
		},
	}
	for _, scenario := range CheckpointCustodyQualificationCatalog() {
		result := CheckpointCustodyScenarioEvidence{
			ScenarioID: scenario.ID, Status: EvidencePass, RunID: "run-" + scenario.ID,
			Command:   "qualification-runner --scenario " + scenario.ID,
			StartedAt: "2026-11-11T09:00:00Z", CompletedAt: "2026-11-11T09:01:00Z",
			Evidence: []CheckpointCustodyEvidenceReference{{
				Path:      "evidence/" + scenario.ID + ".json",
				SHA256:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MediaType: "application/json",
			}},
		}
		if scenario.RequiresIndependentWitness {
			witnessDigest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			if scenario.ID == "CUSTODY-012" {
				witnessDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			}
			result.IndependentWitnessEvidence = []CheckpointCustodyEvidenceReference{{
				Path:      "evidence/witness-" + scenario.ID + ".json",
				SHA256:    witnessDigest,
				MediaType: "application/json",
			}}
			attestationDigest := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			if scenario.ID == "CUSTODY-012" {
				attestationDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			}
			result.IndependentWitnessAttestation = CheckpointCustodyEvidenceReference{
				Path: "evidence/witness-attestation-" + scenario.ID + ".json",
				SHA256: attestationDigest, MediaType: "application/json",
			}
		}
		manifest.Scenarios = append(manifest.Scenarios, result)
	}
	return manifest
}

func TestCheckpointCustodyQualificationCatalogIsStableAndComplete(t *testing.T) {
	t.Parallel()
	catalog := CheckpointCustodyQualificationCatalog()
	if len(catalog) != 12 {
		t.Fatalf("catalog length = %d, want 12", len(catalog))
	}
	seen := make(map[string]bool, len(catalog))
	for _, scenario := range catalog {
		if scenario.ID == "" || scenario.Category == "" || scenario.FailureInjection == "" ||
			scenario.RequiredInvariant == "" || len(scenario.RequiredEvidence) == 0 {
			t.Fatalf("incomplete scenario: %+v", scenario)
		}
		if seen[scenario.ID] {
			t.Fatalf("duplicate scenario ID %q", scenario.ID)
		}
		seen[scenario.ID] = true
	}
}

func TestValidateCheckpointCustodyQualificationManifest(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if !CheckpointCustodyQualificationReady(manifest) {
		t.Fatal("complete approved manifest is not ready")
	}
}

func TestCheckpointCustodyQualificationRejectsMissingAndDuplicateScenarios(t *testing.T) {
	t.Parallel()
	missing := custodyQualificationFixture()
	missing.Scenarios = missing.Scenarios[:len(missing.Scenarios)-1]
	if err := ValidateCheckpointCustodyQualificationManifest(missing); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing scenario error = %v, want ErrCorrupt", err)
	}
	duplicate := custodyQualificationFixture()
	duplicate.Scenarios[1].ScenarioID = duplicate.Scenarios[0].ScenarioID
	if err := ValidateCheckpointCustodyQualificationManifest(duplicate); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate scenario error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationDoesNotTreatSkippedAsReady(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Scenarios[0].Status = EvidenceSkipped
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); err != nil {
		t.Fatalf("structurally valid skipped manifest rejected: %v", err)
	}
	if CheckpointCustodyQualificationReady(manifest) {
		t.Fatal("skipped scenario incorrectly marked ready")
	}
}

func TestCheckpointCustodyQualificationRejectsUnsafeEvidencePath(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Scenarios[0].Evidence[0].Path = "../outside.json"
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unsafe path error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationRejectsInvalidEvidenceDigest(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Scenarios[0].Evidence[0].SHA256 = "not-a-digest"
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("digest error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationRequiresApprovedIndependentReview(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Review.Status = "PENDING"
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); err != nil {
		t.Fatalf("pending review should remain structurally valid: %v", err)
	}
	if CheckpointCustodyQualificationReady(manifest) {
		t.Fatal("pending review incorrectly marked ready")
	}
}

func TestCheckpointCustodyQualificationRequiresIndependentWitnessEvidence(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	for i := range manifest.Scenarios {
		if manifest.Scenarios[i].ScenarioID == "CUSTODY-011" {
			manifest.Scenarios[i].IndependentWitnessEvidence = nil
			break
		}
	}
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing witness error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationRejectsWindowsDrivePath(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Scenarios[0].Evidence[0].Path = "C:/outside/evidence.json"
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Windows drive path error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationRejectsReusedWitnessEvidence(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	for i := range manifest.Scenarios {
		if manifest.Scenarios[i].ScenarioID == "CUSTODY-011" {
			manifest.Scenarios[i].IndependentWitnessEvidence[0] = manifest.Scenarios[i].Evidence[0]
			break
		}
	}
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reused witness error = %v, want ErrCorrupt", err)
	}
}

func TestCheckpointCustodyQualificationRejectsReusedReviewAttestation(t *testing.T) {
	t.Parallel()
	manifest := custodyQualificationFixture()
	manifest.Review.Attestation = manifest.Scenarios[0].Evidence[0]
	if err := ValidateCheckpointCustodyQualificationManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reused review evidence error = %v, want ErrCorrupt", err)
	}
}
