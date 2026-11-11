package journal

import (
	"errors"
	"testing"
)

func validEvidenceManifest() QualificationEvidenceManifest {
	tests := make([]QualificationTestEvidence, 0, len(RequiredQualificationScenarios))
	for _, scenario := range RequiredQualificationScenarios {
		tests = append(tests, QualificationTestEvidence{
			ScenarioID: scenario.ID, Status: EvidencePass, TestRunID: "run-001",
			Command:   "adapter-qualification --scenario " + scenario.ID,
			StartedAt: "2026-11-11T08:00:00Z", CompletedAt: "2026-11-11T08:01:00Z",
			Evidence: []EvidenceReference{{Path: "evidence/" + scenario.ID + ".json", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MediaType: "application/json"}},
		})
	}
	return QualificationEvidenceManifest{
		SchemaVersion: "1.0", QualificationID: "qualification-001", CatalogVersion: "m0-jq-1",
		Adapter:     JournalAdapterIdentity{Name: "candidate", Version: "1.0", Driver: "candidate-driver", DriverVersion: "1.0"},
		Environment: QualificationEnvironment{OperatingSystem: "Linux", Kernel: "6.x", Architecture: "x86_64", Filesystem: "ext4", MountOptions: "defaults", StorageTopology: "test volume"},
		Durability:  DurabilityProfile{AcknowledgementBarrier: "sync completed", PowerLossModel: "declared test model", SyncPolicy: "sync on commit", WALCheckpointPolicy: "documented checkpoint policy"},
		Tests:       tests,
		Review:      IndependentReview{Status: "APPROVED", ReviewerIdentity: "independent-reviewer", ReviewedAt: "2026-11-11T09:00:00Z", Attestation: EvidenceReference{Path: "evidence/review.json", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MediaType: "application/json"}},
	}
}

func TestQualificationEvidenceManifestComplete(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	if err := ValidateQualificationEvidenceManifest(manifest); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if !QualificationEvidenceReady(manifest) {
		t.Fatal("complete approved manifest should be ready")
	}
}

func TestQualificationEvidenceManifestRejectsMissingScenario(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	manifest.Tests = manifest.Tests[:len(manifest.Tests)-1]
	if err := ValidateQualificationEvidenceManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing scenario error = %v, want ErrCorrupt", err)
	}
}

func TestQualificationEvidenceManifestRejectsSkippedScenarioForReadiness(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	manifest.Tests[0].Status = EvidenceSkipped
	if err := ValidateQualificationEvidenceManifest(manifest); err != nil {
		t.Fatalf("skipped status should be structurally valid: %v", err)
	}
	if QualificationEvidenceReady(manifest) {
		t.Fatal("skipped scenario must never qualify")
	}
}

func TestQualificationEvidenceManifestRejectsUnsafeEvidencePath(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	manifest.Tests[0].Evidence[0].Path = "../../outside.json"
	if err := ValidateQualificationEvidenceManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unsafe path error = %v, want ErrCorrupt", err)
	}
}

func TestQualificationEvidenceManifestRejectsInvalidDigest(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	manifest.Tests[0].Evidence[0].SHA256 = "not-a-digest"
	if err := ValidateQualificationEvidenceManifest(manifest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid digest error = %v, want ErrCorrupt", err)
	}
}

func TestQualificationEvidenceManifestRejectsUnapprovedReview(t *testing.T) {
	t.Parallel()
	manifest := validEvidenceManifest()
	manifest.Review.Status = "PENDING"
	if err := ValidateQualificationEvidenceManifest(manifest); err != nil {
		t.Fatalf("pending review should be structurally valid: %v", err)
	}
	if QualificationEvidenceReady(manifest) {
		t.Fatal("pending review must never qualify")
	}
}
