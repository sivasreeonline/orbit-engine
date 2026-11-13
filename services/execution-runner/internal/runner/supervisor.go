package runner

import (
	"context"
	"errors"
	"sync"
	"time"
)

type workerRunner interface {
	RunOnce(context.Context) (WorkResult, error)
}

// ReadinessGate must be backed by current, successful Linux/runsc qualification.
// An absent or false gate prevents the worker from being called.
type ReadinessGate interface {
	Qualified(context.Context) (bool, error)
}

type SupervisorConfig struct {
	PollInterval time.Duration
	RetryDelay   time.Duration
}

type Supervisor struct {
	worker workerRunner
	gate ReadinessGate
	config SupervisorConfig
}

func NewSupervisor(worker workerRunner, gate ReadinessGate, config SupervisorConfig) (*Supervisor, error) {
	if worker == nil || gate == nil {
		return nil, errors.New("runner worker and explicit sandbox qualification gate are required")
	}
	if config.PollInterval == 0 { config.PollInterval = 2 * time.Second }
	if config.RetryDelay == 0 { config.RetryDelay = 5 * time.Second }
	if config.PollInterval < 250*time.Millisecond || config.PollInterval > 30*time.Second ||
		config.RetryDelay < time.Second || config.RetryDelay > time.Minute {
		return nil, errors.New("runner supervisor timing configuration is outside safe bounds")
	}
	return &Supervisor{worker: worker, gate: gate, config: config}, nil
}

// Run never invokes RunOnce unless the independent qualification gate is true.
// Cancellation exits promptly; resource ownership remains with the process.
func (s *Supervisor) Run(ctx context.Context) error {
	if s == nil || s.worker == nil || s.gate == nil {
		return errors.New("runner supervisor is not configured")
	}
	for {
		if ctx.Err() != nil { return nil }
		qualified, err := s.gate.Qualified(ctx)
		if err != nil || !qualified {
			if waitSupervisor(ctx, s.config.RetryDelay) != nil { return nil }
			continue
		}
		_, runErr := s.worker.RunOnce(ctx)
		if ctx.Err() != nil { return nil }
		delay := s.config.PollInterval
		if runErr != nil && !errors.Is(runErr, ErrSandboxNotConfigured) {
			delay = s.config.RetryDelay
		}
		if waitSupervisor(ctx, delay) != nil { return nil }
	}
}

func waitSupervisor(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done(): return ctx.Err()
	case <-timer.C: return nil
	}
}

// StaticQualificationGate defaults to false. SetQualified must only be called
// by the reviewed deployment qualification integration.
type StaticQualificationGate struct {
	mu sync.RWMutex
	qualified bool
}

func (g *StaticQualificationGate) SetQualified(value bool) {
	if g == nil { return }
	g.mu.Lock()
	defer g.mu.Unlock()
	g.qualified = value
}

func (g *StaticQualificationGate) Qualified(context.Context) (bool, error) {
	if g == nil { return false, nil }
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.qualified, nil
}
