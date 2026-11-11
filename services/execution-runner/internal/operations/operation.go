package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/lifecycle"
)

type Type string

const (
	TypeCreate Type = "CREATE"
	TypeStart  Type = "START"
	TypeStop   Type = "STOP"
	TypeDelete Type = "DELETE"
)

type Phase string

const (
	PhaseIntentDurable          Phase = "INTENT_DURABLE"
	PhaseDispatchPossible       Phase = "DISPATCH_POSSIBLE"
	PhaseObserved               Phase = "OBSERVED"
	PhaseCompleted              Phase = "COMPLETED"
	PhaseReconciliationRequired Phase = "RECONCILIATION_REQUIRED"
)

type InspectionDisposition string

const (
	InspectionResourcePresent InspectionDisposition = "RESOURCE_PRESENT"
	InspectionResourceAbsent  InspectionDisposition = "RESOURCE_ABSENT"
	InspectionAmbiguous       InspectionDisposition = "AMBIGUOUS"
)

var (
	ErrInvalidOperation       = errors.New("invalid operation record or command")
	ErrInvalidPhaseTransition = errors.New("invalid operation phase transition")
	ErrReconciliationDenied   = errors.New("operation reconciliation proof is insufficient")
)

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Identity struct {
	HostInstanceID string
	ProofRunID     string
	FixtureID      string
	AttemptID      string
	OperationID    string
	RequestDigest  string
	ProfileDigest  string
}

func (identity Identity) Validate() error {
	ids := []struct {
		name  string
		value string
	}{
		{name: "host instance", value: identity.HostInstanceID},
		{name: "proof run", value: identity.ProofRunID},
		{name: "fixture", value: identity.FixtureID},
		{name: "attempt", value: identity.AttemptID},
		{name: "operation", value: identity.OperationID},
	}
	for _, item := range ids {
		if !opaqueIDPattern.MatchString(item.value) {
			return fmt.Errorf("%w: %s ID is missing or non-canonical", ErrInvalidOperation, item.name)
		}
	}
	if !validDigest(identity.RequestDigest) || !validDigest(identity.ProfileDigest) {
		return fmt.Errorf("%w: request/profile digests must be lowercase SHA-256", ErrInvalidOperation)
	}
	return nil
}

// DeterministicResourceIdentity returns a bounded supervisor-owned resource
// name derived from every immutable operation identity field. Reconciliation
// must still inspect and compare the full metadata; the name is not ownership
// proof by itself.
func DeterministicResourceIdentity(identity Identity) (string, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	canonical := strings.Join([]string{
		identity.HostInstanceID,
		identity.ProofRunID,
		identity.FixtureID,
		identity.AttemptID,
		identity.OperationID,
		identity.RequestDigest,
		identity.ProfileDigest,
	}, "/")
	digest := sha256.Sum256([]byte(canonical))
	return "skyhigh-m0-" + hex.EncodeToString(digest[:]), nil
}

type Record struct {
	Identity             Identity
	ResourceIdentity     string
	Sequence             uint64
	Type                 Type
	SupervisorGeneration uint64
	AttemptGeneration    uint64
	ExpectedAttemptState lifecycle.State
	ExpectedStateVersion uint64
	Phase                Phase
	PhaseVersion         uint64
	IntentAtUTC          time.Time
}

func (record Record) Validate() error {
	resourceIdentity, err := DeterministicResourceIdentity(record.Identity)
	if err != nil {
		return err
	}
	if record.ResourceIdentity != resourceIdentity ||
		record.Sequence == 0 ||
		record.SupervisorGeneration == 0 ||
		record.AttemptGeneration == 0 ||
		record.ExpectedStateVersion == 0 ||
		record.PhaseVersion != 1 ||
		record.Phase != PhaseIntentDurable ||
		record.IntentAtUTC.IsZero() ||
		record.IntentAtUTC.Location() != time.UTC {
		return fmt.Errorf("%w: operation must start with immutable identity and INTENT_DURABLE version 1", ErrInvalidOperation)
	}
	switch record.Type {
	case TypeCreate:
		if record.ExpectedAttemptState != lifecycle.StateQueued {
			return fmt.Errorf("%w: CREATE requires QUEUED attempt state", ErrInvalidOperation)
		}
	case TypeStart:
		if record.ExpectedAttemptState != lifecycle.StateCreating {
			return fmt.Errorf("%w: START requires CREATING attempt state", ErrInvalidOperation)
		}
	case TypeStop, TypeDelete:
		if record.ExpectedAttemptState != lifecycle.StateTerminating {
			return fmt.Errorf("%w: STOP/DELETE require TERMINATING attempt state", ErrInvalidOperation)
		}
	default:
		return fmt.Errorf("%w: unknown operation type %q", ErrInvalidOperation, record.Type)
	}
	return nil
}

func ValidatePhaseTransition(from, to Phase) error {
	if !knownPhase(from) || !knownPhase(to) || !allowedPhaseTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidPhaseTransition, from, to)
	}
	return nil
}

type InspectionProof struct {
	Disposition            InspectionDisposition
	ResourceIdentity       string
	InspectionID           string
	InspectedAtUTC         time.Time
	Authoritative          bool
	IdentityVerified       bool
	GenerationsCurrent     bool
	WithinOriginalDeadline bool
	AttemptStillAuthorized bool
}

func (proof InspectionProof) validatePresent(expectedResourceIdentity string) error {
	if proof.Disposition != InspectionResourcePresent ||
		proof.ResourceIdentity != expectedResourceIdentity ||
		!validResourceIdentity(proof.ResourceIdentity) ||
		strings.TrimSpace(proof.InspectionID) == "" ||
		proof.InspectedAtUTC.IsZero() ||
		proof.InspectedAtUTC.Location() != time.UTC ||
		!proof.Authoritative ||
		!proof.IdentityVerified ||
		!proof.GenerationsCurrent {
		return fmt.Errorf("%w: exact resource presence is not authoritatively verified", ErrReconciliationDenied)
	}
	return nil
}

func (proof InspectionProof) validateSafeRetry(expectedResourceIdentity string) error {
	if proof.Disposition != InspectionResourceAbsent ||
		proof.ResourceIdentity != expectedResourceIdentity ||
		strings.TrimSpace(proof.ResourceIdentity) == "" ||
		strings.TrimSpace(proof.InspectionID) == "" ||
		proof.InspectedAtUTC.IsZero() ||
		proof.InspectedAtUTC.Location() != time.UTC ||
		!proof.Authoritative ||
		!proof.IdentityVerified ||
		!proof.GenerationsCurrent ||
		!proof.WithinOriginalDeadline ||
		!proof.AttemptStillAuthorized {
		return fmt.Errorf("%w: retry requires authoritative absence, exact identity inspection, current generations, original deadline, and current authorization", ErrReconciliationDenied)
	}
	return nil
}

type TransitionCommand struct {
	OperationID              string
	AttemptID                string
	ExpectedPhase            Phase
	ExpectedPhaseVersion     uint64
	SupervisorGeneration     uint64
	AttemptGeneration        uint64
	ExpectedResourceIdentity string
	TargetPhase              Phase
	DispatchAtUTC            time.Time
	ReconciliationAtUTC      time.Time
	ReconciliationReason     string
	Inspection               InspectionProof
	CompletionVerified       bool
	CompletionEvidenceRef    string
	CompletedAtUTC           time.Time
}

func (command TransitionCommand) Validate() error {
	if !opaqueIDPattern.MatchString(command.OperationID) ||
		!opaqueIDPattern.MatchString(command.AttemptID) ||
		command.ExpectedPhaseVersion == 0 ||
		command.SupervisorGeneration == 0 ||
		command.AttemptGeneration == 0 ||
		!validResourceIdentity(command.ExpectedResourceIdentity) {
		return fmt.Errorf("%w: operation transition identity, version, and generations are required", ErrInvalidOperation)
	}
	if err := ValidatePhaseTransition(command.ExpectedPhase, command.TargetPhase); err != nil {
		return err
	}
	switch command.TargetPhase {
	case PhaseDispatchPossible:
		if command.DispatchAtUTC.IsZero() || command.DispatchAtUTC.Location() != time.UTC {
			return fmt.Errorf("%w: dispatch timestamp must be UTC", ErrInvalidOperation)
		}
		if command.ExpectedPhase == PhaseReconciliationRequired {
			if err := command.Inspection.validateSafeRetry(command.ExpectedResourceIdentity); err != nil {
				return err
			}
		}
	case PhaseObserved:
		if err := command.Inspection.validatePresent(command.ExpectedResourceIdentity); err != nil {
			return err
		}
	case PhaseReconciliationRequired:
		if strings.TrimSpace(command.ReconciliationReason) == "" ||
			command.ReconciliationAtUTC.IsZero() ||
			command.ReconciliationAtUTC.Location() != time.UTC {
			return fmt.Errorf("%w: reconciliation reason and UTC timestamp are required", ErrInvalidOperation)
		}
	case PhaseCompleted:
		if !command.CompletionVerified ||
			strings.TrimSpace(command.CompletionEvidenceRef) == "" ||
			command.CompletedAtUTC.IsZero() ||
			command.CompletedAtUTC.Location() != time.UTC {
			return fmt.Errorf("%w: completion requires independently verified result and UTC timestamp", ErrInvalidOperation)
		}
	}
	return nil
}

func knownPhase(phase Phase) bool {
	switch phase {
	case PhaseIntentDurable, PhaseDispatchPossible, PhaseObserved, PhaseCompleted, PhaseReconciliationRequired:
		return true
	default:
		return false
	}
}

func allowedPhaseTransition(from, to Phase) bool {
	switch from {
	case PhaseIntentDurable:
		return to == PhaseDispatchPossible
	case PhaseDispatchPossible:
		return to == PhaseObserved || to == PhaseReconciliationRequired
	case PhaseObserved:
		return to == PhaseCompleted || to == PhaseReconciliationRequired
	case PhaseReconciliationRequired:
		return to == PhaseDispatchPossible || to == PhaseObserved
	default:
		return false
	}
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validResourceIdentity(value string) bool {
	return len(value) == len("skyhigh-m0-")+64 &&
		strings.HasPrefix(value, "skyhigh-m0-") &&
		validDigest(strings.TrimPrefix(value, "skyhigh-m0-"))
}
