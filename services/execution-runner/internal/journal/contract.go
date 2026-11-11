package journal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/lifecycle"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/operations"
)

var (
	ErrConflict      = errors.New("journal compare-and-set conflict")
	ErrNotFound      = errors.New("journal record not found")
	ErrCorrupt       = errors.New("journal invariant violation")
	ErrNotConfigured = errors.New("durable journal is not configured")
)

type AttemptRecord struct {
	AttemptID            string
	ProofRunID           string
	FixtureID            string
	RequestDigest        string
	OwnerID              string
	ProfileID            string
	ProfileRevision      uint64
	ImageDigest          string
	IntakeUTC            time.Time
	DeadlineUTC          time.Time
	IntakeBootID         string
	IntakeBootTime       time.Duration
	State                lifecycle.State
	StateVersion         uint64
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	ActiveOperationID    string
}

func (record AttemptRecord) Validate() error {
	if strings.TrimSpace(record.AttemptID) == "" ||
		strings.TrimSpace(record.ProofRunID) == "" ||
		strings.TrimSpace(record.FixtureID) == "" ||
		strings.TrimSpace(record.OwnerID) == "" ||
		strings.TrimSpace(record.ProfileID) == "" ||
		record.ProfileRevision == 0 ||
		strings.TrimSpace(record.IntakeBootID) == "" ||
		record.IntakeBootTime < 0 {
		return fmt.Errorf("%w: attempt identity/profile/intake fields are incomplete", ErrCorrupt)
	}
	if !validSHA256(record.RequestDigest) || !validSHA256(record.ImageDigest) {
		return fmt.Errorf("%w: request and image digests must be canonical lowercase SHA-256", ErrCorrupt)
	}
	if record.IntakeUTC.IsZero() || record.IntakeUTC.Location() != time.UTC ||
		record.DeadlineUTC.IsZero() || record.DeadlineUTC.Location() != time.UTC ||
		!record.DeadlineUTC.After(record.IntakeUTC) {
		return fmt.Errorf("%w: intake and deadline must be UTC and deadline must be later", ErrCorrupt)
	}
	if record.State != lifecycle.StateRequested || record.StateVersion != 1 {
		return fmt.Errorf("%w: a newly inserted attempt must begin at REQUESTED state version 1", ErrCorrupt)
	}
	return nil
}

type AttemptCASCommand struct {
	AttemptID            string
	ExpectedState        lifecycle.State
	ExpectedStateVersion uint64
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	TargetState          lifecycle.State
}

func (command AttemptCASCommand) Validate() error {
	if strings.TrimSpace(command.AttemptID) == "" ||
		command.ExpectedStateVersion == 0 ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 {
		return fmt.Errorf("%w: attempt CAS identity, version, and generations are required", ErrCorrupt)
	}
	if err := lifecycle.ValidateTransition(command.ExpectedState, command.TargetState); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return nil
}

type AppendTriggerCommand struct {
	AttemptID            string
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	Sequence             uint64
	Disposition          lifecycle.TriggerDisposition
	Trigger              lifecycle.Trigger
}

func (command AppendTriggerCommand) Validate() error {
	if strings.TrimSpace(command.AttemptID) == "" ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 ||
		command.Sequence == 0 {
		return fmt.Errorf("%w: trigger attempt identity, generations, and sequence are required", ErrCorrupt)
	}
	if strings.TrimSpace(command.Trigger.ID) == "" ||
		strings.TrimSpace(command.Trigger.Kind) == "" ||
		strings.TrimSpace(command.Trigger.AuthenticatedSource) == "" ||
		strings.TrimSpace(command.Trigger.BootID) == "" ||
		command.Trigger.ObservedBootTime < 0 ||
		command.Trigger.ObservedAtUTC.IsZero() ||
		command.Trigger.ObservedAtUTC.Location() != time.UTC {
		return fmt.Errorf("%w: trigger identity and trusted timestamps are incomplete", ErrCorrupt)
	}
	switch command.Disposition {
	case lifecycle.TriggerPrimary, lifecycle.TriggerSecondary, lifecycle.TriggerLate:
	default:
		return fmt.Errorf("%w: unknown trigger disposition %q", ErrCorrupt, command.Disposition)
	}
	if command.Sequence == 1 && command.Disposition != lifecycle.TriggerPrimary {
		return fmt.Errorf("%w: first trigger sequence must be PRIMARY", ErrCorrupt)
	}
	if command.Sequence > 1 && command.Disposition == lifecycle.TriggerPrimary {
		return fmt.Errorf("%w: only trigger sequence 1 may be PRIMARY", ErrCorrupt)
	}
	return nil
}

type SealTriggerStreamCommand struct {
	AttemptID            string
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	Watermark            uint64
	Output               lifecycle.OutputSnapshot
}

func (command SealTriggerStreamCommand) Validate() error {
	if strings.TrimSpace(command.AttemptID) == "" ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 {
		return fmt.Errorf("%w: trigger seal identity and generations are required", ErrCorrupt)
	}
	if !command.Output.Finalized {
		return fmt.Errorf("%w: output snapshot must be finalized before trigger-stream sealing", ErrCorrupt)
	}
	if command.Output.StdoutRetained > command.Output.StdoutObserved ||
		command.Output.StderrRetained > command.Output.StderrObserved ||
		command.Output.StdoutRetained > ^uint64(0)-command.Output.StderrRetained ||
		command.Output.CombinedRetained != command.Output.StdoutRetained+command.Output.StderrRetained {
		return fmt.Errorf("%w: output accounting invariants are violated", ErrCorrupt)
	}
	return nil
}

type BranchCASCommand struct {
	AttemptID            string
	Kind                 lifecycle.BranchKind
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	BranchGeneration     uint64
	ExpectedStateVersion uint64
	Disposition          lifecycle.BranchDisposition
}

func (command BranchCASCommand) Validate() error {
	if strings.TrimSpace(command.AttemptID) == "" ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 ||
		command.BranchGeneration == 0 ||
		command.ExpectedStateVersion == 0 {
		return fmt.Errorf("%w: branch CAS identity, generations, and version are required", ErrCorrupt)
	}
	if command.Kind != lifecycle.BranchCleanup && command.Kind != lifecycle.BranchEvidence {
		return fmt.Errorf("%w: unknown finalization branch %q", ErrCorrupt, command.Kind)
	}
	switch command.Disposition {
	case lifecycle.BranchSucceeded, lifecycle.BranchFailed, lifecycle.BranchIncomplete:
		return nil
	default:
		return fmt.Errorf("%w: unknown branch disposition %q", ErrCorrupt, command.Disposition)
	}
}

type TerminalCommitCommand struct {
	AttemptID                  string
	ExpectedState              lifecycle.State
	ExpectedStateVersion       uint64
	SupervisorGeneration       uint64
	AttemptGeneration          uint64
	CleanupBranchGeneration    uint64
	CleanupBranchStateVersion  uint64
	EvidenceBranchGeneration   uint64
	EvidenceBranchStateVersion uint64
	TriggerWatermark           uint64
	TerminalResultID           string
	CommittedAtUTC             time.Time
	ResponseDescriptorDigest   string
	Classification             lifecycle.TerminalClassification
	Snapshot                   lifecycle.FinalizationSnapshot
}

func (command TerminalCommitCommand) Validate() error {
	if strings.TrimSpace(command.AttemptID) == "" ||
		command.ExpectedState != lifecycle.StateFinalizing ||
		command.ExpectedStateVersion == 0 ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 ||
		command.CleanupBranchGeneration == 0 ||
		command.CleanupBranchStateVersion == 0 ||
		command.EvidenceBranchGeneration == 0 ||
		command.EvidenceBranchStateVersion == 0 ||
		strings.TrimSpace(command.TerminalResultID) == "" {
		return fmt.Errorf("%w: terminal commit identity, finalizing version, and branch fences are required", ErrCorrupt)
	}
	if command.CommittedAtUTC.IsZero() || command.CommittedAtUTC.Location() != time.UTC ||
		!validSHA256(command.ResponseDescriptorDigest) {
		return fmt.Errorf("%w: terminal commit timestamp/digest is invalid", ErrCorrupt)
	}
	if command.Snapshot.SupervisorGeneration != command.SupervisorGeneration ||
		command.Snapshot.AttemptGeneration != command.AttemptGeneration ||
		command.Snapshot.TriggerWatermark != command.TriggerWatermark ||
		command.Snapshot.Cleanup.Generation != command.CleanupBranchGeneration ||
		command.Snapshot.Cleanup.StateVersion != command.CleanupBranchStateVersion ||
		command.Snapshot.Evidence.Generation != command.EvidenceBranchGeneration ||
		command.Snapshot.Evidence.StateVersion != command.EvidenceBranchStateVersion {
		return fmt.Errorf("%w: terminal snapshot does not match the expected transaction fences", ErrCorrupt)
	}
	if err := lifecycle.ValidateTerminalCommit(command.Snapshot, command.Classification); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return nil
}

// Transaction is a single journal transaction. Implementations must use
// parameterized values, enforce affected-row counts, and reject stale
// supervisor/attempt/branch generations. CommitTerminal must insert the
// immutable terminal result and perform the attempt's terminal compare-and-set
// atomically in this transaction.
type Transaction interface {
	InsertAttempt(record AttemptRecord) error
	CompareAndSwapAttempt(command AttemptCASCommand) (AttemptRecord, error)
	AppendTrigger(command AppendTriggerCommand) error
	SealTriggerStream(command SealTriggerStreamCommand) error
	CompareAndSwapBranch(command BranchCASCommand) (lifecycle.FinalizationBranch, error)
	CommitTerminal(command TerminalCommitCommand) error
	InsertOperation(record operations.Record) error
	CompareAndSwapOperation(command operations.TransitionCommand) (operations.Record, error)
}

// Store is the backend-neutral journal port. WithTransaction must provide one
// durable transaction: callback errors roll back, and a nil callback result
// is returned only after the backend confirms commit. No implementation is
// selected or supplied in this package.
type Store interface {
	WithTransaction(ctx context.Context, callback func(Transaction) error) error
	ReadAttempt(ctx context.Context, attemptID string) (AttemptRecord, error)
	ReadOperation(ctx context.Context, operationID string) (operations.Record, error)
	ListNonTerminalOperations(ctx context.Context, attemptID string) ([]operations.Record, error)
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
