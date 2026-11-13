package runner

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrSupervisorStopped = errors.New("runner supervisor stopped")

// ReadinessGate is independent of executor construction. It must be backed by
// a current, successful Linux/runsc qualification performed by the operator.
// An absent or false gate prevents RunOnce from being called at all.
type ReadinessGate interface {
	Qualified(context.Context) (bool, error)
}

// SupervisorConfig bounds polling and transient retry behavior.
type SupervisorConfig struct {
	PollInterval time.Duration
	RetryDelay   time.Duration
}

type Supervisor struct {
	worker   *Worker
	gate     ReadinessGate
	config   SupervisorConfig
}

// NewSupervisor creates a foreground loop around the existing single-dispatch
// worker. It does not own the journal or client; the process must close those
// after Run returns.
func NewSupervisor(worker *Worker, gate ReadinessGate, config SupervisorConfig) (*Supervisor, error) {
	if worker == nil || gate == nil {
		return nil, errors.New("runner worker and explicit sandbox qualification gate are required")
	}
	if config.PollInterval == 0 {
		config.PollInterval = 2 * time.Second
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.PollInterval < 250*time.Millisecond || config.PollInterval > 30*time.Second ||
		config.RetryDelay < time.Second || config.RetryDelay > time.Minute {
		return nil, errors.New("runner supervisor timing configuration is outside safe bounds")
	}
	return &Supervisor{worker: worker, gate: gate, config: config}, nil
}

// Run is deliberately fail-closed. Until an independently qualified
// deployment gate reports true, the worker is never called and cannot claim.
func (supervisor *Supervisor) Run(ctx context.Context) error {
	if supervisor == nil || supervisor.worker == nil || supervisor.gate == nil {
		return errors.New("runner supervisor is not configured")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		qualified, err := supervisor.gate.Qualified(ctx)
		if err != nil || !qualified {
			if err := waitSupervisor(ctx, supervisor.config.RetryDelay); err != nil {
				return nil
			}
			continue
		}
		_, runErr := supervisor.worker.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		delay := supervisor.config.PollInterval
		if runErr != nil && !errors.Is(runErr, ErrSandboxNotConfigured) {
			delay = supervisor.config.RetryDelay
		}
		if err := waitSupervisor(ctx, delay); err != nil {
			return nil
		}
	}
}

func waitSupervisor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// StaticQualificationGate is intended for explicit deployment configuration.
// A false value is the default; CI and local development must not opt in.
type StaticQualificationGate struct {
	mu        sync.RWMutex
	qualified bool
}

func (gate *StaticQualificationGate) Qualified(context.Context) (bool, error) {
	if gate == nil {
		return false, nil
	}
	gate.mu.RLock()
	defer gate.mu.RUnlock()
	return gate.qualified, nil
}
