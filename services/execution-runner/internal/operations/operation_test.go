package operations

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/lifecycle"
)

func validIdentity() Identity {
	return Identity{
		HostInstanceID: "host-01",
		ProofRunID:     "proof-01",
		FixtureID:      "fixture-01",
		AttemptID:      "attempt-01",
		OperationID:    "operation-01",
		RequestDigest:  strings.Repeat("a", 64),
		ProfileDigest:  strings.Repeat("b", 64),
	}
}

func validOperationRecord() Record {
	resource, _ := DeterministicResourceIdentity(validIdentity())
	return Record{
		Identity:             validIdentity(),
		ResourceIdentity:     resource,
		Sequence:             1,
		Type:                 TypeCreate,
		SupervisorGeneration: 4,
		AttemptGeneration:    7,
		ExpectedAttemptState: lifecycle.StateQueued,
		ExpectedStateVersion: 2,
		Phase:                PhaseIntentDurable,
		PhaseVersion:         1,
		IntentAtUTC:          time.Date(2026, time.November, 11, 8, 0, 0, 0, time.UTC),
	}
}

func validTransition(from, to Phase) TransitionCommand {
	resource, _ := DeterministicResourceIdentity(validIdentity())
	return TransitionCommand{
		OperationID:              "operation-01",
		AttemptID:                "attempt-01",
		ExpectedPhase:            from,
		ExpectedPhaseVersion:     1,
		SupervisorGeneration:     4,
		AttemptGeneration:        7,
		ExpectedResourceIdentity: resource,
		TargetPhase:              to,
	}
}

func validInspection(disposition InspectionDisposition) InspectionProof {
	resource, _ := DeterministicResourceIdentity(validIdentity())
	return InspectionProof{
		Disposition:            disposition,
		ResourceIdentity:       resource,
		InspectionID:           "inspection-01",
		InspectedAtUTC:         time.Date(2026, time.November, 11, 8, 1, 0, 0, time.UTC),
		Authoritative:          true,
		IdentityVerified:       true,
		GenerationsCurrent:     true,
		WithinOriginalDeadline: true,
		AttemptStillAuthorized: true,
	}
}

func TestDeterministicResourceIdentityBindsEveryImmutableField(t *testing.T) {
	t.Parallel()

	identity := validIdentity()
	first, err := DeterministicResourceIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.OperationID = "operation-02"
	second, err := DeterministicResourceIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different operation IDs produced the same resource identity")
	}
	if len(first) != len("skyhigh-m0-")+64 {
		t.Fatalf("resource identity length = %d, want %d", len(first), len("skyhigh-m0-")+64)
	}
	identity = validIdentity()
	identity.RequestDigest = strings.Repeat("A", 64)
	if _, err := DeterministicResourceIdentity(identity); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("uppercase digest error = %v, want ErrInvalidOperation", err)
	}
}

func TestOperationRecordValidate(t *testing.T) {
	t.Parallel()

	if err := validOperationRecord().Validate(); err != nil {
		t.Fatalf("valid operation rejected: %v", err)
	}

	record := validOperationRecord()
	record.ResourceIdentity += "/untrusted-suffix"
	if err := record.Validate(); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("caller-modified resource identity error = %v, want ErrInvalidOperation", err)
	}

	record = validOperationRecord()
	record.Type = TypeStart
	if err := record.Validate(); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("START with QUEUED state error = %v, want ErrInvalidOperation", err)
	}
}

func TestValidatePhaseTransitionIsClosedAndForwardOnly(t *testing.T) {
	t.Parallel()

	allowed := [][2]Phase{
		{PhaseIntentDurable, PhaseDispatchPossible},
		{PhaseDispatchPossible, PhaseObserved},
		{PhaseDispatchPossible, PhaseReconciliationRequired},
		{PhaseObserved, PhaseCompleted},
		{PhaseObserved, PhaseReconciliationRequired},
		{PhaseReconciliationRequired, PhaseDispatchPossible},
		{PhaseReconciliationRequired, PhaseObserved},
	}
	for _, transition := range allowed {
		if err := ValidatePhaseTransition(transition[0], transition[1]); err != nil {
			t.Fatalf("allowed transition %s -> %s rejected: %v", transition[0], transition[1], err)
		}
	}

	forbidden := [][2]Phase{
		{PhaseCompleted, PhaseDispatchPossible},
		{PhaseCompleted, PhaseObserved},
		{PhaseIntentDurable, PhaseCompleted},
		{PhaseIntentDurable, PhaseObserved},
		{PhaseReconciliationRequired, PhaseCompleted},
		{Phase("UNKNOWN"), PhaseObserved},
	}
	for _, transition := range forbidden {
		if err := ValidatePhaseTransition(transition[0], transition[1]); !errors.Is(err, ErrInvalidPhaseTransition) {
			t.Fatalf("forbidden transition %s -> %s error = %v, want ErrInvalidPhaseTransition", transition[0], transition[1], err)
		}
	}
}

func TestTransitionCommandRequiresDispatchTimestamp(t *testing.T) {
	t.Parallel()

	command := validTransition(PhaseIntentDurable, PhaseDispatchPossible)
	if err := command.Validate(); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("missing dispatch timestamp error = %v, want ErrInvalidOperation", err)
	}
	command.DispatchAtUTC = time.Date(2026, time.November, 11, 8, 1, 0, 0, time.UTC)
	if err := command.Validate(); err != nil {
		t.Fatalf("valid dispatch transition rejected: %v", err)
	}
}

func TestTransitionToObservedRequiresExactAuthoritativeInspection(t *testing.T) {
	t.Parallel()

	command := validTransition(PhaseDispatchPossible, PhaseObserved)
	command.Inspection = validInspection(InspectionResourcePresent)
	if err := command.Validate(); err != nil {
		t.Fatalf("valid observed transition rejected: %v", err)
	}

	command.Inspection.IdentityVerified = false
	if err := command.Validate(); !errors.Is(err, ErrReconciliationDenied) {
		t.Fatalf("unverified resource identity error = %v, want ErrReconciliationDenied", err)
	}

	command.Inspection = validInspection(InspectionResourcePresent)
	command.Inspection.ResourceIdentity = "skyhigh-m0-" + strings.Repeat("f", 64)
	if err := command.Validate(); !errors.Is(err, ErrReconciliationDenied) {
		t.Fatalf("mismatched resource identity error = %v, want ErrReconciliationDenied", err)
	}
}

func TestReconciliationRetryRequiresAuthoritativeAbsenceAndOriginalAuthorization(t *testing.T) {
	t.Parallel()

	command := validTransition(PhaseReconciliationRequired, PhaseDispatchPossible)
	command.DispatchAtUTC = time.Date(2026, time.November, 11, 8, 2, 0, 0, time.UTC)
	command.Inspection = validInspection(InspectionResourceAbsent)
	if err := command.Validate(); err != nil {
		t.Fatalf("valid retry proof rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*InspectionProof)
	}{
		{
			name: "ambiguous resource",
			mutate: func(proof *InspectionProof) {
				proof.Disposition = InspectionAmbiguous
			},
		},
		{
			name: "not authoritative",
			mutate: func(proof *InspectionProof) {
				proof.Authoritative = false
			},
		},
		{
			name: "stale generations",
			mutate: func(proof *InspectionProof) {
				proof.GenerationsCurrent = false
			},
		},
		{
			name: "original deadline expired",
			mutate: func(proof *InspectionProof) {
				proof.WithinOriginalDeadline = false
			},
		},
		{
			name: "attempt no longer authorized",
			mutate: func(proof *InspectionProof) {
				proof.AttemptStillAuthorized = false
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := validTransition(PhaseReconciliationRequired, PhaseDispatchPossible)
			command.DispatchAtUTC = time.Date(2026, time.November, 11, 8, 2, 0, 0, time.UTC)
			command.Inspection = validInspection(InspectionResourceAbsent)
			test.mutate(&command.Inspection)
			if err := command.Validate(); !errors.Is(err, ErrReconciliationDenied) {
				t.Fatalf("retry proof error = %v, want ErrReconciliationDenied", err)
			}
		})
	}
}

func TestReconciliationRequiredNeedsReasonAndUTCObservation(t *testing.T) {
	t.Parallel()

	command := validTransition(PhaseDispatchPossible, PhaseReconciliationRequired)
	if err := command.Validate(); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("missing reconciliation reason/time error = %v, want ErrInvalidOperation", err)
	}
	command.ReconciliationReason = "dispatch response lost"
	command.ReconciliationAtUTC = time.Date(2026, time.November, 11, 8, 3, 0, 0, time.UTC)
	if err := command.Validate(); err != nil {
		t.Fatalf("valid reconciliation-required transition rejected: %v", err)
	}
}

func TestCompletedRequiresIndependentVerification(t *testing.T) {
	t.Parallel()

	command := validTransition(PhaseObserved, PhaseCompleted)
	command.CompletedAtUTC = time.Date(2026, time.November, 11, 8, 4, 0, 0, time.UTC)
	if err := command.Validate(); !errors.Is(err, ErrInvalidOperation) {
		t.Fatalf("unverified completion error = %v, want ErrInvalidOperation", err)
	}
	command.CompletionVerified = true
	command.CompletionEvidenceRef = "evidence://operation-01/verified-result"
	if err := command.Validate(); err != nil {
		t.Fatalf("verified completion rejected: %v", err)
	}
}
