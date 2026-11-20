package runner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type countedWorker struct {
	calls atomic.Int32
}

func (w *countedWorker) RunOnce(context.Context) (WorkResult, error) {
	w.calls.Add(1)
	return WorkResult{}, nil
}

type fixedGate struct {
	qualified bool
}

func (g fixedGate) Qualified(context.Context) (bool, error) {
	return g.qualified, nil
}

type failingGate struct {
	cancel context.CancelFunc
}

func (g failingGate) Qualified(context.Context) (bool, error) {
	g.cancel()
	return true, errors.New("qualification attestation unavailable")
}

func TestSupervisorRejectsNilContext(t *testing.T) {
	worker := &countedWorker{}
	s, err := NewSupervisor(worker, fixedGate{qualified: true}, SupervisorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(nil); err != ErrExecutionContextRequired {
		t.Fatalf("Run with nil context error = %v, want ErrExecutionContextRequired", err)
	}
	if got := worker.calls.Load(); got != 0 {
		t.Fatalf("RunOnce calls = %d, want 0", got)
	}
}

func TestSupervisorNeverCallsWorkerWithoutQualification(t *testing.T) {
	worker := &countedWorker{}
	s, err := NewSupervisor(worker, fixedGate{qualified: false}, SupervisorConfig{
		PollInterval: 250 * time.Millisecond,
		RetryDelay:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := worker.calls.Load(); got != 0 {
		t.Fatalf("RunOnce calls = %d, want 0", got)
	}
}

func TestSupervisorNeverCallsWorkerWhenQualificationGateErrors(t *testing.T) {
	worker := &countedWorker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := NewSupervisor(worker, failingGate{cancel: cancel}, SupervisorConfig{
		PollInterval: 250 * time.Millisecond,
		RetryDelay:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed > 100*time.Millisecond {
		t.Fatalf("supervisor did not stop promptly after gate error and cancellation: %s", elapsed)
	}
	if got := worker.calls.Load(); got != 0 {
		t.Fatalf("RunOnce calls = %d after qualification gate error, want 0", got)
	}
}

func TestSupervisorStopsPromptlyOnCancellation(t *testing.T) {
	worker := &countedWorker{}
	s, err := NewSupervisor(worker, fixedGate{qualified: false}, SupervisorConfig{
		PollInterval: 250 * time.Millisecond,
		RetryDelay:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	startedAt := time.Now()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(startedAt) > 100*time.Millisecond {
		t.Fatal("supervisor did not stop promptly")
	}
}
