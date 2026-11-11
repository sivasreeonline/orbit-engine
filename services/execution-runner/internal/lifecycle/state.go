package lifecycle

import (
	"errors"
	"fmt"
)

type State string

const (
	StateRequested   State = "REQUESTED"
	StateValidating  State = "VALIDATING"
	StateQueued      State = "QUEUED"
	StateCreating    State = "CREATING"
	StateStarting    State = "STARTING"
	StateRunning     State = "RUNNING"
	StateTerminating State = "TERMINATING"
	StateFinalizing  State = "FINALIZING"
	StateQuarantined State = "QUARANTINED"
	StateRejected    State = "REJECTED"
	StateExpired     State = "EXPIRED"
)

var ErrInvalidTransition = errors.New("invalid lifecycle state transition")

// ValidateTransition enforces the closed transition table in the M0
// supervisor/journal contract. It is a pure policy check: it performs no
// persistence, authorization, process control, or resource cleanup.
func ValidateTransition(from, to State) error {
	if !knownState(from) {
		return fmt.Errorf("%w: unknown source state %q", ErrInvalidTransition, from)
	}
	if !knownState(to) {
		return fmt.Errorf("%w: unknown destination state %q", ErrInvalidTransition, to)
	}
	if !allowedTransition(from, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	return nil
}

// CanEnterTerminationPath reports whether a termination trigger may move the
// attempt into TERMINATING. The contract limits this path to states where a
// durable create intent may already have escaped.
func CanEnterTerminationPath(state State) bool {
	switch state {
	case StateCreating, StateStarting, StateRunning:
		return true
	default:
		return false
	}
}

func knownState(state State) bool {
	switch state {
	case StateRequested, StateValidating, StateQueued, StateCreating,
		StateStarting, StateRunning, StateTerminating, StateFinalizing,
		StateQuarantined, StateRejected, StateExpired:
		return true
	default:
		return false
	}
}

func allowedTransition(from, to State) bool {
	switch from {
	case StateRequested:
		return to == StateValidating || to == StateRejected || to == StateExpired
	case StateValidating:
		return to == StateQueued || to == StateRejected ||
			to == StateExpired || to == StateQuarantined
	case StateQueued:
		return to == StateCreating || to == StateExpired ||
			to == StateRejected || to == StateQuarantined
	case StateCreating:
		return to == StateStarting || to == StateTerminating ||
			to == StateFinalizing || to == StateQuarantined
	case StateStarting:
		return to == StateRunning || to == StateTerminating ||
			to == StateFinalizing || to == StateQuarantined
	case StateRunning:
		return to == StateTerminating || to == StateFinalizing ||
			to == StateQuarantined
	case StateTerminating:
		return to == StateFinalizing || to == StateQuarantined
	case StateFinalizing:
		return to == StateQuarantined
	default:
		// REJECTED, EXPIRED and QUARANTINED have no automatic outgoing
		// transitions. Quarantine recovery requires a separately authorized,
		// operator-controlled reconciliation procedure.
		return false
	}
}
