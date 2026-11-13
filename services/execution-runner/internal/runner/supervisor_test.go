package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type countedWorker struct{ calls atomic.Int32 }
func (worker *countedWorker) RunOnce(context.Context) (WorkResult, error) {
	worker.calls.Add(1)
	return WorkResult{}, nil
}

type fixedGate struct{ qualified bool }
func (gate fixedGate) Qualified(context.Context) (bool, error) { return gate.qualified, nil }

// Compile-time adapter makes it explicit that the supervisor consumes only
// RunOnce; the production Worker implements the same narrow contract.
type workerAdapter struct{ run func(context.Context) (WorkResult, error) }
func (adapter workerAdapter) RunOnce(ctx context.Context) (WorkResult, error) { return adapter.run(ctx) }

func TestSupervisorNeverCallsWorkerWithoutQualification(t *testing.T) {
	worker := &countedWorker{}
	// Supervisor accepts a narrow RunOnce contract so a fake can prove gating.
	supervisor, err := NewSupervisor(worker, fixedGate{qualified:false}, SupervisorConfig{
		PollInterval: 250*time.Millisecond, RetryDelay: time.Second,
	})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error,1)
	go func(){ done <- supervisor.Run(ctx) }()
	time.Sleep(30*time.Millisecond)
	cancel()
	if err := <-done; err != nil { t.Fatal(err) }
	if got:=worker.calls.Load(); got!=0 { t.Fatalf("RunOnce calls=%d, want 0",got) }
}

func TestSupervisorStopsPromptlyOnCancellation(t *testing.T) {
	worker := &countedWorker{}
	supervisor, err := NewSupervisor(worker, fixedGate{qualified:false}, SupervisorConfig{
		PollInterval: 250*time.Millisecond, RetryDelay: time.Second,
	})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start:=time.Now()
	if err:=supervisor.Run(ctx); err!=nil { t.Fatal(err) }
	if time.Since(start)>100*time.Millisecond { t.Fatal("supervisor did not stop promptly") }
}
