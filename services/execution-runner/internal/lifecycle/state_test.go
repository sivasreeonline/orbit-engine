package lifecycle

import (
	"errors"
	"testing"
)

func TestValidateTransitionMatchesContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from State
		to   State
		want bool
	}{
		{name: "requested to validating", from: StateRequested, to: StateValidating, want: true},
		{name: "requested to rejected", from: StateRequested, to: StateRejected, want: true},
		{name: "validating to queued", from: StateValidating, to: StateQueued, want: true},
		{name: "queued to creating", from: StateQueued, to: StateCreating, want: true},
		{name: "creating to starting", from: StateCreating, to: StateStarting, want: true},
		{name: "creating to terminating", from: StateCreating, to: StateTerminating, want: true},
		{name: "starting to running", from: StateStarting, to: StateRunning, want: true},
		{name: "running to finalizing", from: StateRunning, to: StateFinalizing, want: true},
		{name: "terminating to finalizing", from: StateTerminating, to: StateFinalizing, want: true},
		{name: "finalizing to quarantine", from: StateFinalizing, to: StateQuarantined, want: true},
		{name: "queued cannot enter terminating", from: StateQueued, to: StateTerminating},
		{name: "requested cannot enter creating", from: StateRequested, to: StateCreating},
		{name: "running cannot return to queued", from: StateRunning, to: StateQueued},
		{name: "quarantine has no automatic recovery", from: StateQuarantined, to: StateRequested},
		{name: "rejected is terminal", from: StateRejected, to: StateValidating},
		{name: "expired is terminal", from: StateExpired, to: StateQueued},
		{name: "unknown source rejected", from: State("UNKNOWN"), to: StateValidating},
		{name: "unknown destination rejected", from: StateRequested, to: State("UNKNOWN")},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateTransition(test.from, test.to)
			if test.want && err != nil {
				t.Fatalf("ValidateTransition(%q, %q) error = %v", test.from, test.to, err)
			}
			if !test.want && !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("ValidateTransition(%q, %q) error = %v, want ErrInvalidTransition", test.from, test.to, err)
			}
		})
	}
}

func TestCanEnterTerminationPathOnlyAfterCreateIntent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state State
		want  bool
	}{
		{state: StateRequested, want: false},
		{state: StateValidating, want: false},
		{state: StateQueued, want: false},
		{state: StateCreating, want: true},
		{state: StateStarting, want: true},
		{state: StateRunning, want: true},
		{state: StateTerminating, want: false},
		{state: StateFinalizing, want: false},
		{state: StateQuarantined, want: false},
		{state: StateRejected, want: false},
		{state: StateExpired, want: false},
	}

	for _, test := range tests {
		test := test
		t.Run(string(test.state), func(t *testing.T) {
			t.Parallel()
			if got := CanEnterTerminationPath(test.state); got != test.want {
				t.Fatalf("CanEnterTerminationPath(%q) = %t, want %t", test.state, got, test.want)
			}
		})
	}
}
