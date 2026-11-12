package runner

import (
	"context"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

type SandboxStatus string

const (
	SandboxSucceeded      SandboxStatus = "SUCCEEDED"
	SandboxCompileError   SandboxStatus = "COMPILE_ERROR"
	SandboxRuntimeError   SandboxStatus = "RUNTIME_ERROR"
	SandboxTimeLimit      SandboxStatus = "TIME_LIMIT_EXCEEDED"
	SandboxMemoryLimit    SandboxStatus = "MEMORY_LIMIT_EXCEEDED"
	SandboxOutputLimit    SandboxStatus = "OUTPUT_LIMIT_EXCEEDED"
)

type SandboxRequest struct {
	ExecutionID   string
	Language      protocol.Language
	RuntimeVersion string
	ImageRef      string
	SourceName    string
	SourceBytes   []byte
	StandardInput []byte
	Limits        protocol.ResourceLimits
}

type SandboxObservation struct {
	Status             SandboxStatus
	CompilationStatus  CompilationStatus
	StandardOutput     []byte
	StandardError      []byte
	ElapsedMillis      int64
	PeakMemoryBytes    *int64
	CleanupSucceeded   bool
}

type Sandbox interface {
	RunCase(context.Context, SandboxRequest) (SandboxObservation, error)
}
