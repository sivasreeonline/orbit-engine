package lifecycle

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type TriggerDisposition string

const (
	TriggerPrimary   TriggerDisposition = "PRIMARY"
	TriggerSecondary TriggerDisposition = "SECONDARY"
	TriggerLate      TriggerDisposition = "LATE"
)

var (
	ErrInvalidTrigger = errors.New("invalid termination trigger")
	ErrBootIdentity   = errors.New("trigger boot identity mismatch")
	ErrClockRollback  = errors.New("trigger BOOTTIME moved backwards")
	ErrTriggerNotApplicable = errors.New("termination trigger is not applicable to the current lifecycle state")
)

type Trigger struct {
	ID                  string
	Kind                string
	AuthenticatedSource string
	BootID              string
	ObservedBootTime    time.Duration
	ObservedAtUTC       time.Time
}

type TriggerRecord struct {
	Trigger
	Sequence    uint64
	Disposition TriggerDisposition
}

// TriggerArbiter is an in-memory, concurrency-safe reference implementation
// of first-trigger arbitration. The caller must authenticate the source and
// supply trusted host-observed timestamps before calling Capture.
//
// This type is not a durable journal, watchdog, or termination controller.
// A production host boundary must persist the returned record and request
// termination immediately after accepting the primary trigger.
type TriggerArbiter struct {
	mu                 sync.Mutex
	bootID             string
	lastObserved       time.Duration
	hasObserved        bool
	nextSequence       uint64
	primary            *TriggerRecord
	finalizationBegun  bool
}

func NewTriggerArbiter(bootID string) (*TriggerArbiter, error) {
	if strings.TrimSpace(bootID) == "" {
		return nil, fmt.Errorf("%w: boot ID is required", ErrInvalidTrigger)
	}
	return &TriggerArbiter{bootID: bootID}, nil
}

// Capture assigns the in-process sequence under one mutex and enforces the
// lifecycle eligibility rule. Pre-create states cannot enter cleanup; a
// TERMINATING state requires an existing primary trigger. FINALIZING triggers
// are retained as late incidents and cannot rewrite the primary cause.
func (arbiter *TriggerArbiter) Capture(state State, trigger Trigger) (TriggerRecord, error) {
	if strings.TrimSpace(trigger.ID) == "" ||
		strings.TrimSpace(trigger.Kind) == "" ||
		strings.TrimSpace(trigger.AuthenticatedSource) == "" ||
		strings.TrimSpace(trigger.BootID) == "" ||
		trigger.ObservedBootTime < 0 ||
		trigger.ObservedAtUTC.IsZero() ||
		trigger.ObservedAtUTC.Location() != time.UTC {
		return TriggerRecord{}, fmt.Errorf("%w: required identity and UTC/BOOTTIME fields are missing or invalid", ErrInvalidTrigger)
	}

	arbiter.mu.Lock()
	defer arbiter.mu.Unlock()

	if trigger.BootID != arbiter.bootID {
		return TriggerRecord{}, ErrBootIdentity
	}
	if !arbiter.finalizationBegun {
		switch state {
		case StateCreating, StateStarting, StateRunning:
		case StateTerminating:
			if arbiter.primary == nil {
				return TriggerRecord{}, ErrTriggerNotApplicable
			}
		case StateFinalizing:
			arbiter.finalizationBegun = true
		default:
			return TriggerRecord{}, ErrTriggerNotApplicable
		}
	}
	if arbiter.hasObserved && trigger.ObservedBootTime < arbiter.lastObserved {
		return TriggerRecord{}, ErrClockRollback
	}

	arbiter.nextSequence++
	arbiter.lastObserved = trigger.ObservedBootTime
	arbiter.hasObserved = true

	record := TriggerRecord{
		Trigger:     trigger,
		Sequence:    arbiter.nextSequence,
		Disposition: TriggerSecondary,
	}
	switch {
	case arbiter.finalizationBegun || state == StateFinalizing:
		record.Disposition = TriggerLate
	case arbiter.primary == nil:
		record.Disposition = TriggerPrimary
		primary := record
		arbiter.primary = &primary
	}

	return record, nil
}

// BeginFinalization freezes the primary cause against later trigger rewrites.
// It is safe to call more than once.
func (arbiter *TriggerArbiter) BeginFinalization() {
	arbiter.mu.Lock()
	defer arbiter.mu.Unlock()
	arbiter.finalizationBegun = true
}

// Primary returns a copy of the immutable primary trigger, if one exists.
func (arbiter *TriggerArbiter) Primary() (TriggerRecord, bool) {
	arbiter.mu.Lock()
	defer arbiter.mu.Unlock()

	if arbiter.primary == nil {
		return TriggerRecord{}, false
	}
	return *arbiter.primary, true
}
