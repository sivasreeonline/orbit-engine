package lifecycle

import (
	"errors"
	"testing"
)

func validFinalizationSnapshot() FinalizationSnapshot {
	return FinalizationSnapshot{
		SupervisorGeneration:    4,
		AttemptGeneration:       7,
		TriggerStreamSealed:     true,
		TriggerWatermark:        2,
		DurableTriggerSequences: []uint64{1, 2},
		PrimaryTriggerID:        "trigger-1",
		PrimaryTriggerSequence:  1,
		Output: OutputSnapshot{
			Finalized:        true,
			StdoutObserved:   120,
			StderrObserved:   20,
			StdoutRetained:   100,
			StderrRetained:   20,
			CombinedRetained: 120,
		},
		Cleanup: FinalizationBranch{
			Kind:                 BranchCleanup,
			Generation:           3,
			StateVersion:         9,
			SupervisorGeneration: 4,
			AttemptGeneration:    7,
			Disposition:          BranchSucceeded,
			Durable:              true,
		},
		Evidence: FinalizationBranch{
			Kind:                 BranchEvidence,
			Generation:           2,
			StateVersion:         6,
			SupervisorGeneration: 4,
			AttemptGeneration:    7,
			Disposition:          BranchSucceeded,
			Durable:              true,
		},
	}
}

func TestValidateTerminalCommitAcceptsVerifiedSuccess(t *testing.T) {
	t.Parallel()

	if err := ValidateTerminalCommit(validFinalizationSnapshot(), TerminalSuccess); err != nil {
		t.Fatalf("ValidateTerminalCommit() error = %v", err)
	}
}

func TestValidateTerminalCommitRejectsUnsealedOrGappedTriggerStream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*FinalizationSnapshot)
	}{
		{
			name: "unsealed",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.TriggerStreamSealed = false
			},
		},
		{
			name: "missing trigger",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.DurableTriggerSequences = []uint64{1}
			},
		},
		{
			name: "gap",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.DurableTriggerSequences = []uint64{1, 3}
			},
		},
		{
			name: "missing primary",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.PrimaryTriggerID = ""
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validFinalizationSnapshot()
			test.mutate(&snapshot)
			if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrFinalizationNotReady) && !errors.Is(err, ErrInvalidFinalization) {
				t.Fatalf("ValidateTerminalCommit() error = %v, want finalization rejection", err)
			}
		})
	}
}

func TestValidateTerminalCommitRequiresFrozenValidOutputAccounting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*FinalizationSnapshot)
	}{
		{
			name: "not finalized",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Output.Finalized = false
			},
		},
		{
			name: "retained exceeds observed",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Output.StdoutRetained = snapshot.Output.StdoutObserved + 1
			},
		},
		{
			name: "combined mismatch",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Output.CombinedRetained++
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validFinalizationSnapshot()
			test.mutate(&snapshot)
			if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrInvalidFinalization) && !errors.Is(err, ErrFinalizationNotReady) {
				t.Fatalf("ValidateTerminalCommit() error = %v, want finalization rejection", err)
			}
		})
	}
}

func TestValidateTerminalCommitRejectsStaleOrNonDurableBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*FinalizationSnapshot)
	}{
		{
			name: "stale supervisor generation",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Cleanup.SupervisorGeneration--
			},
		},
		{
			name: "stale attempt generation",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Evidence.AttemptGeneration--
			},
		},
		{
			name: "cleanup not durable",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Cleanup.Durable = false
			},
		},
		{
			name: "evidence not durable",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Evidence.Durable = false
			},
		},
		{
			name: "missing branch generation",
			mutate: func(snapshot *FinalizationSnapshot) {
				snapshot.Evidence.Generation = 0
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := validFinalizationSnapshot()
			test.mutate(&snapshot)
			if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrFinalizationNotReady) && !errors.Is(err, ErrInvalidFinalization) {
				t.Fatalf("ValidateTerminalCommit() error = %v, want finalization rejection", err)
			}
		})
	}
}

func TestValidateTerminalCommitRequiresQuarantineForUnsuccessfulBranch(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	snapshot.Evidence.Disposition = BranchIncomplete
	snapshot.Quarantined = true
	if err := ValidateTerminalCommit(snapshot, TerminalInfrastructureFailure); err != nil {
		t.Fatalf("infrastructure failure with durable quarantine error = %v", err)
	}
	if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrFinalizationNotReady) {
		t.Fatalf("success with incomplete evidence error = %v, want ErrFinalizationNotReady", err)
	}

	snapshot.Quarantined = false
	if err := ValidateTerminalCommit(snapshot, TerminalInfrastructureFailure); !errors.Is(err, ErrFinalizationNotReady) {
		t.Fatalf("infrastructure failure without quarantine error = %v, want ErrFinalizationNotReady", err)
	}
}

func TestValidateTerminalCommitRejectsUnknownDispositionAndClassification(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	snapshot.Cleanup.Disposition = BranchDisposition("UNKNOWN")
	if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrInvalidFinalization) {
		t.Fatalf("unknown branch disposition error = %v, want ErrInvalidFinalization", err)
	}

	snapshot = validFinalizationSnapshot()
	if err := ValidateTerminalCommit(snapshot, TerminalClassification("PASS")); !errors.Is(err, ErrInvalidFinalization) {
		t.Fatalf("unknown terminal classification error = %v, want ErrInvalidFinalization", err)
	}
}

func TestValidateTerminalCommitRequiresBothBranchesForInfrastructureResult(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	snapshot.Cleanup.Disposition = BranchFailed
	snapshot.Quarantined = true
	if err := ValidateTerminalCommit(snapshot, TerminalInfrastructureFailure); err != nil {
		t.Fatalf("infrastructure failure with failed cleanup and verified evidence error = %v", err)
	}
}

func TestValidateTerminalCommitRequiresPrimaryTriggerToBeFirst(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	snapshot.PrimaryTriggerSequence = 2
	if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrInvalidFinalization) {
		t.Fatalf("non-first primary trigger error = %v, want ErrInvalidFinalization", err)
	}
}

func TestValidateTerminalCommitRejectsOutputCounterOverflow(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	snapshot.Output.StdoutRetained = ^uint64(0)
	snapshot.Output.StderrRetained = 1
	snapshot.Output.StdoutObserved = ^uint64(0)
	snapshot.Output.StderrObserved = 1
	snapshot.Output.CombinedRetained = 0
	if err := ValidateTerminalCommit(snapshot, TerminalSuccess); !errors.Is(err, ErrInvalidFinalization) {
		t.Fatalf("overflowed output accounting error = %v, want ErrInvalidFinalization", err)
	}
}
