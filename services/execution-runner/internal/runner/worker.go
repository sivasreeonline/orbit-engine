package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/acceptancejournal"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerclient"
)

var ErrLeaseWindowTooShort = errors.New("runner lease does not have enough time remaining for completion")

type ControlPlane interface {
	RetryPending(context.Context, *acceptancejournal.Journal) ([]runnerclient.AcceptanceResult, error)
	Claim(context.Context, int) ([]runnerclient.Dispatch, error)
	AcceptDispatch(context.Context, *acceptancejournal.Journal, runnerclient.Dispatch) (runnerclient.AcceptanceResult, error)
	StartDispatch(context.Context, runnerclient.Dispatch) (runnerclient.StartResult, error)
	NewHeartbeatID() (string, error)
	RenewLease(context.Context, runnerclient.Dispatch, string) (runnerclient.HeartbeatResult, error)
	FetchArtifact(context.Context, runnerclient.Dispatch) (runnerclient.ExecutionArtifact, error)
	CompleteExecution(context.Context, runnerclient.Dispatch, runnerclient.CompletionInput) (runnerclient.CompletionResult, error)
}

// ArtifactExecutor must explicitly report readiness before the worker will
// claim a lease. Execute returns only the aggregate result contract; source,
// test data and process output must never be copied into CompletionInput.
type ArtifactExecutor interface {
	Ready() bool
	Execute(context.Context, runnerclient.ExecutionArtifact) (runnerclient.CompletionInput, error)
}

type WorkerConfig struct {
	HeartbeatInterval      time.Duration
	HeartbeatRetryDelay    time.Duration
	CompletionRetryDelay   time.Duration
	CompletionMaxAttempts  int
	MinimumCompletionLease time.Duration
	Now                    func() time.Time
}

type Worker struct {
	controlPlane ControlPlane
	journal      *acceptancejournal.Journal
	executor     ArtifactExecutor
	config       WorkerConfig
}

type WorkResult struct {
	HasWork   bool
	DispatchID string
	Completion runnerclient.CompletionResult
}

type leaseState struct {
	mu       sync.RWMutex
	dispatch runnerclient.Dispatch
}

func newLeaseState(dispatch runnerclient.Dispatch) *leaseState {
	return &leaseState{dispatch: dispatch}
}

func (state *leaseState) snapshot() runnerclient.Dispatch {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.dispatch
}

func (state *leaseState) renew(expiry time.Time) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.dispatch.LeaseExpiresAt = expiry.UTC()
}

func NewWorker(
	controlPlane ControlPlane,
	journal *acceptancejournal.Journal,
	executor ArtifactExecutor,
	config WorkerConfig,
) (*Worker, error) {
	if controlPlane == nil || journal == nil || executor == nil {
		return nil, errors.New("runner control plane, acceptance journal and executor are required")
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 30 * time.Second
	}
	if config.HeartbeatRetryDelay == 0 {
		config.HeartbeatRetryDelay = 250 * time.Millisecond
	}
	if config.CompletionRetryDelay == 0 {
		config.CompletionRetryDelay = 250 * time.Millisecond
	}
	if config.CompletionMaxAttempts == 0 {
		config.CompletionMaxAttempts = 2
	}
	if config.MinimumCompletionLease == 0 {
		config.MinimumCompletionLease = 40 * time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.HeartbeatInterval < time.Second || config.HeartbeatInterval > 60*time.Second ||
		config.HeartbeatRetryDelay < 10*time.Millisecond || config.HeartbeatRetryDelay > 5*time.Second ||
		config.CompletionRetryDelay < 10*time.Millisecond || config.CompletionRetryDelay > 5*time.Second ||
		config.CompletionMaxAttempts < 1 || config.CompletionMaxAttempts > 3 ||
		config.MinimumCompletionLease < 10*time.Second || config.MinimumCompletionLease > 90*time.Second {
		return nil, errors.New("runner worker timing configuration is outside safe bounds")
	}
	return &Worker{
		controlPlane: controlPlane,
		journal:      journal,
		executor:     executor,
		config:       config,
	}, nil
}

// RunOnce retries locally journaled acceptance intents, checks executor
// readiness, then claims at most one dispatch and drives it through completion.
// It is intentionally not a poll loop; a future service supervisor may call it
// repeatedly only after runner key and sandbox configuration are approved.
func (worker *Worker) RunOnce(ctx context.Context) (WorkResult, error) {
	if err := ctx.Err(); err != nil {
		return WorkResult{}, err
	}
	if _, err := worker.controlPlane.RetryPending(ctx, worker.journal); err != nil {
		return WorkResult{}, fmt.Errorf("recover pending runner acceptance receipts: %w", err)
	}
	if !worker.executor.Ready() {
		return WorkResult{}, ErrSandboxNotConfigured
	}

	dispatches, err := worker.controlPlane.Claim(ctx, 1)
	if err != nil {
		return WorkResult{}, fmt.Errorf("claim runner dispatch: %w", err)
	}
	if len(dispatches) == 0 {
		return WorkResult{}, nil
	}
	if len(dispatches) != 1 {
		return WorkResult{}, errors.New("control plane returned more than one dispatch for a single-slot claim")
	}

	completion, err := worker.processDispatch(ctx, dispatches[0])
	if err != nil {
		return WorkResult{HasWork: true, DispatchID: dispatches[0].DispatchID}, err
	}
	return WorkResult{
		HasWork: true,
		DispatchID: dispatches[0].DispatchID,
		Completion: completion,
	}, nil
}

func (worker *Worker) processDispatch(
	ctx context.Context,
	dispatch runnerclient.Dispatch,
) (runnerclient.CompletionResult, error) {
	if _, err := worker.controlPlane.AcceptDispatch(ctx, worker.journal, dispatch); err != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("durably accept runner dispatch: %w", err)
	}
	if _, err := worker.controlPlane.StartDispatch(ctx, dispatch); err != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("start accepted runner dispatch: %w", err)
	}
	artifact, err := worker.controlPlane.FetchArtifact(ctx, dispatch)
	if err != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("fetch private execution artifact: %w", err)
	}
	if artifact.ExecutionID != dispatch.ExecutionID || artifact.AttemptID != dispatch.AttemptID {
		return runnerclient.CompletionResult{}, errors.New("execution artifact identity does not match the claimed dispatch")
	}

	executionContext, cancelExecution := context.WithCancel(ctx)
	defer cancelExecution()
	heartbeatContext, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()

	lease := newLeaseState(dispatch)
	heartbeatDone := make(chan error, 1)
	go func() {
		heartbeatDone <- worker.maintainLease(heartbeatContext, cancelExecution, lease)
	}()

	result, executionErr := worker.executor.Execute(executionContext, artifact)
	stopHeartbeat()
	heartbeatErr := <-heartbeatDone
	if heartbeatErr != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("runner lease heartbeat failed: %w", heartbeatErr)
	}
	if err := ctx.Err(); err != nil {
		return runnerclient.CompletionResult{}, err
	}
	if executionErr != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("sandbox execution failed: %w", executionErr)
	}

	dispatch = lease.snapshot()
	if !dispatch.LeaseExpiresAt.After(worker.config.Now().Add(worker.config.MinimumCompletionLease)) {
		return runnerclient.CompletionResult{}, ErrLeaseWindowTooShort
	}
	completed, err := worker.completeWithRetry(ctx, dispatch, result)
	if err != nil {
		return runnerclient.CompletionResult{}, fmt.Errorf("submit terminal runner result: %w", err)
	}
	return completed, nil
}

func (worker *Worker) maintainLease(
	ctx context.Context,
	cancelExecution context.CancelFunc,
	lease *leaseState,
) error {
	for {
		timer := time.NewTimer(worker.config.HeartbeatInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}

		heartbeatID, err := worker.controlPlane.NewHeartbeatID()
		if err != nil {
			cancelExecution()
			return fmt.Errorf("create runner heartbeat ID: %w", err)
		}
		for {
			dispatch := lease.snapshot()
			result, renewErr := worker.controlPlane.RenewLease(ctx, dispatch, heartbeatID)
			if renewErr == nil {
				if !result.LeaseExpiresAt.After(worker.config.Now()) {
					cancelExecution()
					return errors.New("control plane returned an expired lease heartbeat")
				}
				lease.renew(result.LeaseExpiresAt)
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			if !retryableControlPlaneError(renewErr) ||
				!dispatch.LeaseExpiresAt.After(worker.config.Now().Add(worker.config.MinimumCompletionLease)) {
				cancelExecution()
				return renewErr
			}
			if err := waitContext(ctx, worker.config.HeartbeatRetryDelay); err != nil {
				return nil
			}
			// The same heartbeat ID is deliberately reused after an uncertain
			// response. The client signs each retry with a fresh nonce.
		}
	}
}

func (worker *Worker) completeWithRetry(
	ctx context.Context,
	dispatch runnerclient.Dispatch,
	result runnerclient.CompletionInput,
) (runnerclient.CompletionResult, error) {
	delay := worker.config.CompletionRetryDelay
	var lastErr error
	for attempt := 0; attempt < worker.config.CompletionMaxAttempts; attempt++ {
		completed, err := worker.controlPlane.CompleteExecution(ctx, dispatch, result)
		if err == nil {
			return completed, nil
		}
		lastErr = err
		if !retryableControlPlaneError(err) || attempt+1 == worker.config.CompletionMaxAttempts {
			break
		}
		if err := waitContext(ctx, delay); err != nil {
			return runnerclient.CompletionResult{}, err
		}
		delay *= 2
	}
	return runnerclient.CompletionResult{}, lastErr
}

func retryableControlPlaneError(err error) bool {
	var remote *runnerclient.RemoteError
	if errors.As(err, &remote) {
		return remote.StatusCode >= 500 && remote.StatusCode <= 599
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// UnconfiguredArtifactExecutor keeps the lifecycle coordinator fail-closed.
// It allows the health process and client protocol to be tested without
// enabling Java/Python process execution on the host.
type UnconfiguredArtifactExecutor struct{}

func (UnconfiguredArtifactExecutor) Ready() bool {
	return false
}

func (UnconfiguredArtifactExecutor) Execute(
	context.Context,
	runnerclient.ExecutionArtifact,
) (runnerclient.CompletionInput, error) {
	return runnerclient.CompletionInput{}, ErrSandboxNotConfigured
}
