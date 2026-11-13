package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type countedWorker struct { calls atomic.Int32 }
func (w *countedWorker) RunOnce(context.Context) (WorkResult, error) {
	w.calls.Add(1)
	return WorkResult{}, nil
}

type fixedGate struct { qualified bool }
func (g fixedGate) Qualified(context.Context) (bool, error) { return g.qualified, nil }

func TestSupervisorNeverCallsWorkerWithoutQualification(t *testing.T) {
	worker := &countedWorker{}
	s, err := NewSupervisor(worker, fixedGate{qualified: false}, SupervisorConfig{
		PollInterval: 250*time.Millisecond, RetryDelay: time.Second,
	})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(30*time.Millisecond)
	cancel()
	if err := <-done; err != nil { t.Fatal(err) }
	if got := worker.calls.Load(); got != 0 {
		t.Fatalf("RunOnce calls = %d, want 0", got)
	}
}

func TestSupervisorStopsPromptlyOnCancellation(t *testing.T) {
	worker := &countedWorker{}
	s, err := NewSupervisor(worker, fixedGate{qualified: false}, SupervisorConfig{
		PollInterval: 250*time.Millisecond, RetryDelay: time.Second,
	})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := s.Run(ctx); err != nil { t.Fatal(err) }
	if time.Since(start) > 100*time.Millisecond { t.Fatal("supervisor did not stop promptly") }
}
