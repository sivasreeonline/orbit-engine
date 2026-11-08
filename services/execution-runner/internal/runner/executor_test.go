package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

func TestUnconfiguredExecutorFailsClosed(t *testing.T) {
	t.Parallel()

	executor := UnconfiguredExecutor{}
	result, err := executor.Execute(context.Background(), protocol.ExecutionRequest{})

	if !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("error = %v, want ErrSandboxNotConfigured", err)
	}
	if result.ExecutionID != "" {
		t.Fatalf("unexpected execution result: %+v", result)
	}
}
