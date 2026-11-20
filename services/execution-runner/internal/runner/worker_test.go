package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerclient"
)

type fakeControlPlane struct {
	mu sync.Mutex

	dispatch runnerclient.Dispatch
	artifact runnerclient.ExecutionArtifact
	hasWork bool
	events []string
	heartbeatIDs []string
	completionDispatches []runnerclient.Dispatch
	completionInputs []runnerclient.CompletionInput
	renewErrors []error
	completionErrors []error
	heartbeatSequence int
}

func newFakeControlPlane() *fakeControlPlane {
	now := time.Now().UTC()
	return &fakeControlPlane{
		hasWork: true,
		dispatch: runnerclient.Dispatch{
			DispatchID: "50000000-0000-4000-8000-000000000001",
			ExecutionID: "60000000-0000-4000-8000-000000000001",
			AttemptID: "70000000-0000-4000-8000-000000000001",
			ProtocolVersion: "v1",
			CorrelationID: "worker-test",
			DeliveryAttempt: 1,
			LeaseToken: "80000000-0000-4000-8000-000000000001",
			LeaseExpiresAt: now.Add(120 * time.Second),
		},
		artifact: runnerclient.ExecutionArtifact{
			ExecutionID: "60000000-0000-4000-8000-000000000001",
			AttemptID: "70000000-0000-4000-8000-000000000001",
			ProblemVersionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
			Action: "SUBMIT",
			Language: "java",
			RuntimeVersion: "25",
			SourceCode: "public class Main {}",
		},
	}
}

func (fake *fakeControlPlane) event(value string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.events = append(fake.events, value)
}

func (fake *fakeControlPlane) RetryPending(context.Context, *acceptancejournal.Journal) ([]runnerclient.AcceptanceResult, error) {
	fake.event("retry-pending")
	return nil, nil
}

func (fake *fakeControlPlane) Claim(_ context.Context, slots int) ([]runnerclient.Dispatch, error) {
	fake.event("claim")
	if slots != 1 {
		return nil, fmt.Errorf("slots = %d, want 1", slots)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.hasWork {
		return nil, nil
	}
	return []runnerclient.Dispatch{fake.dispatch}, nil
}

func (fake *fakeControlPlane) AcceptDispatch(
	_ context.Context,
	journal *acceptancejournal.Journal,
	dispatch runnerclient.Dispatch,
) (runnerclient.AcceptanceResult, error) {
	fake.event("accept")
	if dispatch.DispatchID != fake.dispatch.DispatchID {
		return runnerclient.AcceptanceResult{}, errors.New("wrong dispatch")
	}
	receipt, found, err := journal.Find(dispatch.DispatchID, dispatch.LeaseToken)
	if err != nil {
		return runnerclient.AcceptanceResult{}, err
	}
	if !found {
		receipt = acceptancejournal.Receipt{
			AcceptanceID: "90000000-0000-4000-8000-000000000001",
			DispatchID: dispatch.DispatchID,
			ExecutionID: dispatch.ExecutionID,
			AttemptID: dispatch.AttemptID,
			LeaseToken: dispatch.LeaseToken,
			PreparedAt: time.Now().UTC(),
		}
		if _, err := journal.Prepare(receipt); err != nil {
			return runnerclient.AcceptanceResult{}, err
		}
	}
	eventID := "a1000000-0000-4000-8000-000000000001"
	if _, err := journal.Confirm(receipt.AcceptanceID, eventID, time.Now().UTC()); err != nil {
		return runnerclient.AcceptanceResult{}, err
	}
	return runnerclient.AcceptanceResult{
		DispatchID: dispatch.DispatchID,
		AcceptanceID: receipt.AcceptanceID,
		EventID: eventID,
		AcceptedAt: time.Now().UTC(),
	}, nil
}

func (fake *fakeControlPlane) StartDispatch(
	_ context.Context,
	dispatch runnerclient.Dispatch,
) (runnerclient.StartResult, error) {
	fake.event("start")
	return runnerclient.StartResult{
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		EventID: "a2000000-0000-4000-8000-000000000001",
		StartedAt: time.Now().UTC(),
	}, nil
}

func (fake *fakeControlPlane) NewHeartbeatID() (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.heartbeatSequence++
	return fmt.Sprintf("a3000000-0000-4000-8000-%012x", fake.heartbeatSequence), nil
}

func (fake *fakeControlPlane) RenewLease(
	ctx context.Context,
	dispatch runnerclient.Dispatch,
	heartbeatID string,
) (runnerclient.HeartbeatResult, error) {
	fake.mu.Lock()
	fake.heartbeatIDs = append(fake.heartbeatIDs, heartbeatID)
	var err error
	if len(fake.renewErrors) > 0 {
		err = fake.renewErrors[0]
		fake.renewErrors = fake.renewErrors[1:]
	}
	fake.mu.Unlock()
	if err != nil {
		return runnerclient.HeartbeatResult{}, err
	}
	fake.event("heartbeat")
	return runnerclient.HeartbeatResult{
		HeartbeatID: heartbeatID,
		DispatchID: dispatch.DispatchID,
		ExecutionID: dispatch.ExecutionID,
		LeaseExpiresAt: time.Now().UTC().Add(120 * time.Second),
	}, nil
}

func (fake *fakeControlPlane) FetchArtifact(
	_ context.Context,
	dispatch runnerclient.Dispatch,
) (runnerclient.ExecutionArtifact, error) {
	fake.event("artifact")
	if dispatch.ExecutionID != fake.artifact.ExecutionID ||
		dispatch.AttemptID != fake.artifact.AttemptID {
		return runnerclient.ExecutionArtifact{}, errors.New("artifact identity mismatch")
	}
	return fake.artifact, nil
}

func (fake *fakeControlPlane) CompleteExecution(
	_ context.Context,
	dispatch runnerclient.Dispatch,
	result runnerclient.CompletionInput,
) (runnerclient.CompletionResult, error) {
	fake.mu.Lock()
	fake.completionDispatches = append(fake.completionDispatches, dispatch)
	fake.completionInputs = append(fake.completionInputs, result)
	var err error
	if len(fake.completionErrors) > 0 {
		err = fake.completionErrors[0]
		fake.completionErrors = fake.completionErrors[1:]
	}
	fake.mu.Unlock()
	fake.event("complete")
	if err != nil {
		return runnerclient.CompletionResult{}, err
	}
	return runnerclient.CompletionResult{
		ExecutionID: dispatch.ExecutionID,
		AttemptID: dispatch.AttemptID,
		State: "COMPLETED",
		ResultSHA256: result.ResultSHA256,
	}, nil
}

type fakeArtifactExecutor struct {
	ready bool
	execute func(context.Context, runnerclient.ExecutionArtifact) (runnerclient.CompletionInput, error)
}

func (fake fakeArtifactExecutor) Ready() bool { return fake.ready }

func (fake fakeArtifactExecutor) Execute(
	ctx context.Context,
	artifact runnerclient.ExecutionArtifact,
) (runnerclient.CompletionInput, error) {
	if fake.execute == nil {
		return validTestCompletionInput(), nil
	}
	return fake.execute(ctx, artifact)
}

func validTestCompletionInput() runnerclient.CompletionInput {
	now := time.Now().UTC()
	return runnerclient.CompletionInput{
		InfrastructureStatus: "SUCCEEDED",
		CompilationStatus: "SUCCEEDED",
		Verdict: "ACCEPTED",
		CleanupStatus: "SUCCEEDED",
		TestsTotal: 2,
		TestsPassed: 2,
		ElapsedMs: 20,
		RunnerVersion: "runner-test",
		ResultSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		StartedAt: now.Add(-20 * time.Millisecond),
		CompletedAt: now,
	}
}

func openTestJournal(t *testing.T) *acceptancejournal.Journal {
	t.Helper()
	journal, err := acceptancejournal.Open(filepath.Join(t.TempDir(), "runner", "acceptance.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close acceptance journal: %v", err)
		}
	})
	return journal
}

func testWorker(t *testing.T, control *fakeControlPlane, executor ArtifactExecutor, config WorkerConfig) *Worker {
	t.Helper()
	worker, err := NewWorker(control, openTestJournal(t), executor, config)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestRunOnceRefusesToClaimUntilExecutorIsReady(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	worker := testWorker(t, control, UnconfiguredArtifactExecutor{}, WorkerConfig{})

	result, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("RunOnce error = %v, want ErrSandboxNotConfigured", err)
	}
	if result.HasWork {
		t.Fatalf("unconfigured executor claimed work: %+v", result)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.events) != 1 || control.events[0] != "retry-pending" {
		t.Fatalf("unexpected control-plane calls before executor readiness: %v", control.events)
	}
}

func TestRunOnceOrdersAcceptanceStartArtifactExecutionAndCompletion(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	executor := fakeArtifactExecutor{ready: true}
	worker := testWorker(t, control, executor, WorkerConfig{})

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasWork || result.DispatchID != control.dispatch.DispatchID ||
		result.Completion.State != "COMPLETED" {
		t.Fatalf("unexpected worker result: %+v", result)
	}

	control.mu.Lock()
	defer control.mu.Unlock()
	want := []string{"retry-pending", "claim", "accept", "start", "artifact", "complete"}
	if len(control.events) != len(want) {
		t.Fatalf("events = %v, want %v", control.events, want)
	}
	for index := range want {
		if control.events[index] != want[index] {
			t.Fatalf("events = %v, want %v", control.events, want)
		}
	}
	if len(control.completionDispatches) != 1 ||
		!control.completionDispatches[0].LeaseExpiresAt.After(time.Now()) {
		t.Fatalf("completion did not use a current dispatch lease: %+v", control.completionDispatches)
	}
}

func TestRunOnceMaintainsLeaseAndUsesSameHeartbeatIDAfterRetryableFailure(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	control.renewErrors = []error{&runnerclient.RemoteError{StatusCode: 503, Code: "TEMPORARILY_UNAVAILABLE"}}
	executor := fakeArtifactExecutor{
		ready: true,
		execute: func(ctx context.Context, _ runnerclient.ExecutionArtifact) (runnerclient.CompletionInput, error) {
			timer := time.NewTimer(1100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return runnerclient.CompletionInput{}, ctx.Err()
			case <-timer.C:
				return validTestCompletionInput(), nil
			}
		},
	}
	worker := testWorker(t, control, executor, WorkerConfig{
		HeartbeatInterval: 1 * time.Second,
		HeartbeatRetryDelay: 10 * time.Millisecond,
	})

	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.heartbeatIDs) < 2 {
		t.Fatalf("heartbeat attempts = %d, want retry + successful renewal", len(control.heartbeatIDs))
	}
	if control.heartbeatIDs[0] != control.heartbeatIDs[1] {
		t.Fatalf("one logical heartbeat used different IDs across retry: %v", control.heartbeatIDs)
	}
	if len(control.completionDispatches) != 1 ||
		!control.completionDispatches[0].LeaseExpiresAt.After(control.dispatch.LeaseExpiresAt) {
		t.Fatalf("completion did not use the renewed lease expiry: %+v", control.completionDispatches)
	}
}

func TestRunOnceStopsExecutionAndDoesNotCompleteWhenLeaseIsFenced(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	control.renewErrors = []error{&runnerclient.RemoteError{StatusCode: 409, Code: "RUNNER_LEASE_STALE"}}
	executor := fakeArtifactExecutor{
		ready: true,
		execute: func(ctx context.Context, _ runnerclient.ExecutionArtifact) (runnerclient.CompletionInput, error) {
			select {
			case <-ctx.Done():
				return runnerclient.CompletionInput{}, ctx.Err()
			case <-time.After(3 * time.Second):
				return validTestCompletionInput(), nil
			}
		},
	}
	worker := testWorker(t, control, executor, WorkerConfig{
		HeartbeatInterval: 1 * time.Second,
	})
	_, err := worker.RunOnce(context.Background())
	if err == nil {
		t.Fatal("stale heartbeat was accepted")
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.completionInputs) != 0 {
		t.Fatal("worker submitted a terminal result after losing its lease")
	}
}

func TestRunOnceRetriesTerminalCompletionWithIdenticalResult(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	control.completionErrors = []error{&runnerclient.RemoteError{StatusCode: 503, Code: "TEMPORARILY_UNAVAILABLE"}}
	worker := testWorker(t, control, fakeArtifactExecutor{ready: true}, WorkerConfig{
		CompletionRetryDelay: 10 * time.Millisecond,
		CompletionMaxAttempts: 2,
	})

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.completionInputs) != 2 {
		t.Fatalf("completion attempts = %d, want 2", len(control.completionInputs))
	}
	if control.completionInputs[0] != control.completionInputs[1] {
		t.Fatal("completion retry changed the immutable result payload")
	}
}

func TestRunOnceDoesNotClaimWhenQueueIsEmpty(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	control.hasWork = false
	worker := testWorker(t, control, fakeArtifactExecutor{ready: true}, WorkerConfig{})

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.HasWork {
		t.Fatalf("empty queue returned work: %+v", result)
	}
}

func TestNewWorkerRejectsUnsafeTimingConfiguration(t *testing.T) {
	t.Parallel()
	control := newFakeControlPlane()
	journal := openTestJournal(t)
	_, err := NewWorker(control, journal, fakeArtifactExecutor{ready: true}, WorkerConfig{
		HeartbeatInterval: 90 * time.Second,
	})
	if err == nil {
		t.Fatal("unsafe heartbeat interval was accepted")
	}
}
