package runner

import (
	"context"
	"errors"

	"github.com/sivasreeonline/sky-high-coding-judge/services/execution-runner/internal/protocol"
)

var ErrSandboxNotConfigured = errors.New("sandbox executor is not configured")

type Result struct {
	ExecutionID string
}

type Executor interface {
	Execute(context.Context, protocol.ExecutionRequest) (Result, error)
}

// UnconfiguredExecutor is the only executor implementation in the M0 contract
// skeleton. It fails closed and never starts student processes.
type UnconfiguredExecutor struct{}

func (UnconfiguredExecutor) Execute(
	_ context.Context,
	_ protocol.ExecutionRequest,
) (Result, error) {
	return Result{}, ErrSandboxNotConfigured
}
