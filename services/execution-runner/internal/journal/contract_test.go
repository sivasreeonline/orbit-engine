package journal

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/lifecycle"
)

func validAttemptRecord() AttemptRecord {
	now := time.Date(2026, time.November, 11, 8, 0, 0, 0, time.UTC)
	return AttemptRecord{
		AttemptID:       "attempt-1",
		ProofRunID:      "proof-1",
		FixtureID:       "fixture-1",
		RequestDigest:   strings.Repeat("a", 64),
		OwnerID:         "owner-1",
		ProfileID:       "profile-java-25",
		ProfileRevision: 3,
		ImageDigest:     strings.Repeat("b", 64),
		IntakeUTC:       now,
		DeadlineUTC:     now.Add(10 * time.Minute),
		IntakeBootID:    "boot-1",
		IntakeBootTime:  time.Second,
		State:           lifecycle.StateRequested,
		StateVersion:    1,
	}
}

func validFinalizationSnapshot() lifecycle.FinalizationSnapshot {
	return lifecycle.FinalizationSnapshot{
		SupervisorGeneration:    4,
		AttemptGeneration:       7,
		TriggerStreamSealed:     true,
		TriggerWatermark:        1,
		DurableTriggerSequences: []uint64{1},
		PrimaryTriggerID:        "trigger-1",
		PrimaryTriggerSequence:  1,
		Output: lifecycle.OutputSnapshot{
			Finalized:        true,
			StdoutObserved:   20,
			StderrObserved:   10,
			StdoutRetained:   20,
			StderrRetained:   10,
			CombinedRetained: 30,
		},
		Cleanup: lifecycle.FinalizationBranch{
			Kind:                 lifecycle.BranchCleanup,
			Generation:           2,
			StateVersion:         5,
			SupervisorGeneration: 4,
			AttemptGeneration:    7,
			Disposition:          lifecycle.BranchSucceeded,
			Durable:              true,
		},
		Evidence: lifecycle.FinalizationBranch{
			Kind:                 lifecycle.BranchEvidence,
			Generation:           3,
			StateVersion:         6,
			SupervisorGeneration: 4,
			AttemptGeneration:    7,
			Disposition:          lifecycle.BranchSucceeded,
			Durable:              true,
		},
	}
}

func TestAttemptRecordValidate(t *testing.T) {
	t.Parallel()

	if err := validAttemptRecord().Validate(); err != nil {
		t.Fatalf("valid attempt rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*AttemptRecord)
	}{
		{
			name: "uppercase digest",
			mutate: func(record *AttemptRecord) {
				record.RequestDigest = strings.Repeat("A", 64)
			},
		},
		{
			name: "wrong digest length",
			mutate: func(record *AttemptRecord) {
				record.ImageDigest = strings.Repeat("b", 63)
			},
		},
		{
			name: "deadline before intake",
			mutate: func(record *AttemptRecord) {
				record.DeadlineUTC = record.IntakeUTC
			},
		},
		{
			name: "wrong initial state",
			mutate: func(record *AttemptRecord) {
				record.State = lifecycle.StateQueued
			},
		},
		{
			name: "wrong initial version",
			mutate: func(record *AttemptRecord) {
				record.StateVersion = 2
			},
		},
		{
			name: "negative boot time",
			mutate: func(record *AttemptRecord) {
				record.IntakeBootTime = -1
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := validAttemptRecord()
			test.mutate(&record)
			if err := record.Validate(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Validate() error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestAttemptCASCommandValidate(t *testing.T) {
	t.Parallel()

	valid := AttemptCASCommand{
		AttemptID:            "attempt-1",
		ExpectedState:        lifecycle.StateRequested,
		ExpectedStateVersion: 1,
		SupervisorGeneration: 4,
		AttemptGeneration:    7,
		TargetState:          lifecycle.StateValidating,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid CAS rejected: %v", err)
	}

	valid.TargetState = lifecycle.StateTerminating
	if err := valid.Validate(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid transition error = %v, want ErrCorrupt", err)
	}
}

func TestAppendTriggerCommandValidate(t *testing.T) {
	t.Parallel()

	command := AppendTriggerCommand{
		AttemptID:            "attempt-1",
		SupervisorGeneration: 4,
		AttemptGeneration:    7,
		Sequence:             1,
		Disposition:          lifecycle.TriggerPrimary,
		Trigger: lifecycle.Trigger{
			ID:                  "trigger-1",
			Kind:                "deadline",
			AuthenticatedSource: "host-deadline",
			BootID:              "boot-1",
			ObservedBootTime:    time.Second,
			ObservedAtUTC:       time.Date(2026, time.November, 11, 8, 1, 0, 0, time.UTC),
		},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid trigger rejected: %v", err)
	}

	command.Sequence = 2
	if err := command.Validate(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("secondary sequence 2 with PRIMARY disposition error = %v, want ErrCorrupt", err)
	}
}

func TestSealTriggerStreamCommandValidate(t *testing.T) {
	t.Parallel()

	command := SealTriggerStreamCommand{
		AttemptID:            "attempt-1",
		SupervisorGeneration: 4,
		AttemptGeneration:    7,
		Watermark:            0,
		Output: lifecycle.OutputSnapshot{
			Finalized:        true,
			StdoutObserved:   5,
			StderrObserved:   3,
			StdoutRetained:   5,
			StderrRetained:   3,
			CombinedRetained: 8,
		},
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid zero-trigger seal rejected: %v", err)
	}

	command.Output.CombinedRetained = 9
	if err := command.Validate(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mismatched output accounting error = %v, want ErrCorrupt", err)
	}
}

func TestBranchCASCommandValidate(t *testing.T) {
	t.Parallel()

	command := BranchCASCommand{
		AttemptID:            "attempt-1",
		Kind:                 lifecycle.BranchCleanup,
		SupervisorGeneration: 4,
		AttemptGeneration:    7,
		BranchGeneration:     2,
		ExpectedStateVersion: 5,
		Disposition:          lifecycle.BranchSucceeded,
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid branch CAS rejected: %v", err)
	}

	command.Kind = lifecycle.BranchKind("unknown")
	if err := command.Validate(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown branch error = %v, want ErrCorrupt", err)
	}
}

func TestTerminalCommitCommandValidate(t *testing.T) {
	t.Parallel()

	snapshot := validFinalizationSnapshot()
	command := TerminalCommitCommand{
		AttemptID:                  "attempt-1",
		ExpectedState:              lifecycle.StateFinalizing,
		ExpectedStateVersion:       12,
		SupervisorGeneration:       4,
		AttemptGeneration:          7,
		CleanupBranchGeneration:    2,
		CleanupBranchStateVersion:  5,
		EvidenceBranchGeneration:   3,
		EvidenceBranchStateVersion: 6,
		TriggerWatermark:           1,
		TerminalResultID:           "result-1",
		CommittedAtUTC:             time.Date(2026, time.November, 11, 8, 2, 0, 0, time.UTC),
		ResponseDescriptorDigest:   strings.Repeat("c", 64),
		Classification:             lifecycle.TerminalSuccess,
		Snapshot:                   snapshot,
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid terminal commit rejected: %v", err)
	}

	command.EvidenceBranchGeneration++
	if err := command.Validate(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stale evidence generation error = %v, want ErrCorrupt", err)
	}
}
