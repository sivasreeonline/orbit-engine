package lifecycle

import (
	"errors"
	"fmt"
)

type BranchKind string

const (
	BranchCleanup  BranchKind = "cleanup"
	BranchEvidence BranchKind = "evidence"
)

type BranchDisposition string

const (
	BranchSucceeded  BranchDisposition = "SUCCEEDED"
	BranchFailed     BranchDisposition = "FAILED"
	BranchIncomplete BranchDisposition = "INCOMPLETE"
)

type FinalizationBranch struct {
	Kind                 BranchKind
	Generation           uint64
	StateVersion         uint64
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	Disposition          BranchDisposition
	Durable              bool
}

type OutputSnapshot struct {
	Finalized        bool
	StdoutObserved   uint64
	StderrObserved   uint64
	StdoutRetained   uint64
	StderrRetained   uint64
	CombinedRetained uint64
}

type FinalizationSnapshot struct {
	SupervisorGeneration    uint64
	AttemptGeneration       uint64
	TriggerStreamSealed     bool
	TriggerWatermark        uint64
	DurableTriggerSequences []uint64
	PrimaryTriggerID        string
	PrimaryTriggerSequence  uint64
	Output                  OutputSnapshot
	Cleanup                 FinalizationBranch
	Evidence                FinalizationBranch
	Quarantined             bool
}

type TerminalClassification string

const (
	TerminalSuccess               TerminalClassification = "SUCCESS"
	TerminalInfrastructureFailure TerminalClassification = "INFRASTRUCTURE_FAILURE"
)

var (
	ErrFinalizationNotReady = errors.New("finalization is not ready for terminal commit")
	ErrInvalidFinalization  = errors.New("invalid finalization snapshot")
)

// ValidateTerminalCommit verifies the backend-independent preconditions for
// the terminal transaction. A journal adapter must repeat these predicates
// atomically with its generation/version compare-and-set and immutable result
// insert; this function alone does not provide durability or exclusion.
func ValidateTerminalCommit(snapshot FinalizationSnapshot, classification TerminalClassification) error {
	if snapshot.SupervisorGeneration == 0 || snapshot.AttemptGeneration == 0 {
		return fmt.Errorf("%w: supervisor and attempt generations must be non-zero", ErrInvalidFinalization)
	}
	if !snapshot.TriggerStreamSealed {
		return fmt.Errorf("%w: trigger stream is not sealed", ErrFinalizationNotReady)
	}
	if uint64(len(snapshot.DurableTriggerSequences)) != snapshot.TriggerWatermark {
		return fmt.Errorf("%w: durable trigger count does not match sealed watermark", ErrFinalizationNotReady)
	}
	for index, sequence := range snapshot.DurableTriggerSequences {
		expected := uint64(index + 1)
		if sequence != expected {
			return fmt.Errorf("%w: trigger sequence at index %d is %d, want %d", ErrFinalizationNotReady, index, sequence, expected)
		}
	}
	if snapshot.TriggerWatermark > 0 && (snapshot.PrimaryTriggerID == "" || snapshot.PrimaryTriggerSequence != 1) {
		return fmt.Errorf("%w: sealed trigger stream has no primary trigger", ErrInvalidFinalization)
	}
	if !snapshot.Output.Finalized {
		return fmt.Errorf("%w: final output snapshot is not sealed", ErrFinalizationNotReady)
	}
	if snapshot.Output.StdoutRetained > snapshot.Output.StdoutObserved ||
		snapshot.Output.StderrRetained > snapshot.Output.StderrObserved ||
		snapshot.Output.StdoutRetained > ^uint64(0)-snapshot.Output.StderrRetained ||
		snapshot.Output.CombinedRetained != snapshot.Output.StdoutRetained+snapshot.Output.StderrRetained {
		return fmt.Errorf("%w: output accounting invariants are violated", ErrInvalidFinalization)
	}

	if err := validateBranch(snapshot.Cleanup, BranchCleanup, snapshot); err != nil {
		return err
	}
	if err := validateBranch(snapshot.Evidence, BranchEvidence, snapshot); err != nil {
		return err
	}

	branchesSucceeded := snapshot.Cleanup.Disposition == BranchSucceeded &&
		snapshot.Evidence.Disposition == BranchSucceeded
	switch classification {
	case TerminalSuccess:
		if !branchesSucceeded {
			return fmt.Errorf("%w: success requires successful cleanup and evidence dispositions", ErrFinalizationNotReady)
		}
		if snapshot.Quarantined {
			return fmt.Errorf("%w: quarantined attempt cannot commit success", ErrFinalizationNotReady)
		}
	case TerminalInfrastructureFailure:
		if branchesSucceeded && snapshot.Quarantined {
			return fmt.Errorf("%w: fully successful branches cannot be classified as quarantined infrastructure failure", ErrInvalidFinalization)
		}
		if !branchesSucceeded && !snapshot.Quarantined {
			return fmt.Errorf("%w: unsuccessful branch disposition requires quarantine", ErrFinalizationNotReady)
		}
	default:
		return fmt.Errorf("%w: unknown terminal classification %q", ErrInvalidFinalization, classification)
	}

	return nil
}

func validateBranch(branch FinalizationBranch, expectedKind BranchKind, snapshot FinalizationSnapshot) error {
	if branch.Kind != expectedKind {
		return fmt.Errorf("%w: expected %s branch, got %q", ErrInvalidFinalization, expectedKind, branch.Kind)
	}
	if branch.Generation == 0 || branch.StateVersion == 0 {
		return fmt.Errorf("%w: %s branch generation and state version must be non-zero", ErrInvalidFinalization, expectedKind)
	}
	if branch.SupervisorGeneration != snapshot.SupervisorGeneration ||
		branch.AttemptGeneration != snapshot.AttemptGeneration {
		return fmt.Errorf("%w: %s branch is owned by stale supervisor/attempt generations", ErrFinalizationNotReady, expectedKind)
	}
	if !branch.Durable {
		return fmt.Errorf("%w: %s branch disposition is not durable", ErrFinalizationNotReady, expectedKind)
	}
	switch branch.Disposition {
	case BranchSucceeded, BranchFailed, BranchIncomplete:
		return nil
	default:
		return fmt.Errorf("%w: %s branch has unknown disposition %q", ErrInvalidFinalization, expectedKind, branch.Disposition)
	}
}
