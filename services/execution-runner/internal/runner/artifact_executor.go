package runner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerclient"
)

// SandboxArtifactExecutorConfig keeps execution opt-in. Enabled must remain
// false until a real Linux runsc proof, digest-pinned runtime images and
// cleanup/security review have passed.
type SandboxArtifactExecutorConfig struct {
	Runtime RuntimeConfiguration
	Limits  protocol.ResourceLimits
	Enabled bool
}

// SandboxArtifactExecutor adapts the authenticated, already-verified runner
// artifact into the legacy opaque-ID execution contract and maps the resulting
// evidence into the aggregate completion envelope.
type SandboxArtifactExecutor struct {
	sandbox Sandbox
	runtime RuntimeConfiguration
	limits  protocol.ResourceLimits
	enabled bool
}

type dispatchArtifactResolver struct {
	artifact runnerclient.ExecutionArtifact
}

type sandboxPreflight interface {
	Preflight(context.Context, RuntimeConfiguration) error
}

func NewSandboxArtifactExecutor(
	sandbox Sandbox,
	config SandboxArtifactExecutorConfig,
) (*SandboxArtifactExecutor, error) {
	if sandbox == nil {
		return nil, ErrSandboxNotConfigured
	}
	if err := validateExecutionLimits(config.Limits); err != nil {
		return nil, err
	}
	// Reuse the runtime pin validation performed by SandboxExecutor without
	// resolving any artifacts or creating a sandbox during construction.
	if _, err := NewSandboxExecutor(emptyArtifactResolver{}, sandbox, config.Runtime); err != nil {
		return nil, err
	}
	if config.Enabled {
		preflight, ok := sandbox.(sandboxPreflight)
		if !ok {
			return nil, errors.New("enabled sandbox must provide a runtime preflight")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := preflight.Preflight(ctx, config.Runtime); err != nil {
			return nil, fmt.Errorf("sandbox runtime preflight failed: %w", err)
		}
	}
	return &SandboxArtifactExecutor{
		sandbox: sandbox,
		runtime: config.Runtime,
		limits:  config.Limits,
		enabled: config.Enabled,
	}, nil
}

func (executor *SandboxArtifactExecutor) Ready() bool {
	return executor != nil && executor.enabled && executor.sandbox != nil
}

func (executor *SandboxArtifactExecutor) Execute(
	ctx context.Context,
	artifact runnerclient.ExecutionArtifact,
) (runnerclient.CompletionInput, error) {
	if !executor.Ready() {
		return runnerclient.CompletionInput{}, ErrSandboxNotConfigured
	}
	if err := ctx.Err(); err != nil {
		return runnerclient.CompletionInput{}, err
	}
	request, err := executionRequestFromArtifact(artifact, executor.limits)
	if err != nil {
		return runnerclient.CompletionInput{}, err
	}
	resolver := dispatchArtifactResolver{artifact: artifact}
	sandboxExecutor, err := NewSandboxExecutor(&resolver, executor.sandbox, executor.runtime)
	if err != nil {
		return runnerclient.CompletionInput{}, err
	}
	result, err := sandboxExecutor.Execute(ctx, request)
	if err != nil {
		return runnerclient.CompletionInput{}, err
	}
	return completionInputFromResult(result), nil
}

func executionRequestFromArtifact(
	artifact runnerclient.ExecutionArtifact,
	limits protocol.ResourceLimits,
) (protocol.ExecutionRequest, error) {
	action := protocol.Action(artifact.Action)
	language := protocol.Language(artifact.Language)
	request := protocol.ExecutionRequest{
		ProtocolVersion:  "v1",
		ExecutionID:      artifact.ExecutionID,
		AttemptID:        artifact.AttemptID,
		ProblemVersionID: artifact.ProblemVersionID,
		Action:           action,
		Language:         language,
		RuntimeVersion:   artifact.RuntimeVersion,
		SourceArtifactID: artifact.SourceArtifactID,
		SourceSHA256:     artifact.SourceSHA256,
		TestBundleID:     artifact.TestBundleID,
		Limits:           limits,
	}
	if err := request.Validate(); err != nil {
		return protocol.ExecutionRequest{}, err
	}
	if err := validateExecutionLimits(limits); err != nil {
		return protocol.ExecutionRequest{}, err
	}
	if len(artifact.TestCases) == 0 || len(artifact.TestCases) > maximumTestCases {
		return protocol.ExecutionRequest{}, protocol.ErrInvalidRequest
	}
	lastSequence := 0
	for _, testCase := range artifact.TestCases {
		if testCase.Sequence <= lastSequence {
			return protocol.ExecutionRequest{}, protocol.ErrInvalidRequest
		}
		lastSequence = testCase.Sequence
	}
	return request, nil
}

func (resolver dispatchArtifactResolver) ResolveSource(
	ctx context.Context,
	request protocol.ExecutionRequest,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.ExecutionID != resolver.artifact.ExecutionID ||
		request.AttemptID != resolver.artifact.AttemptID ||
		request.ProblemVersionID != resolver.artifact.ProblemVersionID ||
		request.SourceArtifactID != resolver.artifact.SourceArtifactID ||
		request.SourceSHA256 != resolver.artifact.SourceSHA256 {
		return nil, errors.New("authenticated source artifact identity mismatch")
	}
	return []byte(resolver.artifact.SourceCode), nil
}

func (resolver dispatchArtifactResolver) ResolveTestBundle(
	ctx context.Context,
	request protocol.ExecutionRequest,
) (TestBundle, error) {
	if err := ctx.Err(); err != nil {
		return TestBundle{}, err
	}
	if request.ExecutionID != resolver.artifact.ExecutionID ||
		request.AttemptID != resolver.artifact.AttemptID ||
		request.ProblemVersionID != resolver.artifact.ProblemVersionID ||
		request.TestBundleID != resolver.artifact.TestBundleID ||
		string(request.Action) != resolver.artifact.Action {
		return TestBundle{}, errors.New("authenticated test bundle identity mismatch")
	}
	cases := make([]TestCase, 0, len(resolver.artifact.TestCases))
	lastSequence := 0
	for _, testCase := range resolver.artifact.TestCases {
		if testCase.Sequence <= lastSequence {
			return TestBundle{}, protocol.ErrInvalidRequest
		}
		lastSequence = testCase.Sequence
		visibility := TestVisibility(testCase.Visibility)
		cases = append(cases, TestCase{
			ID:             testCase.TestCaseID,
			Visibility:     visibility,
			Input:          []byte(testCase.Input),
			ExpectedOutput: []byte(testCase.ExpectedOutput),
			Comparison:     CompareExactBytes,
		})
	}
	return TestBundle{
		ProblemVersionID: resolver.artifact.ProblemVersionID,
		Cases:            cases,
	}, nil
}

type emptyArtifactResolver struct{}

func (emptyArtifactResolver) ResolveSource(context.Context, protocol.ExecutionRequest) ([]byte, error) {
	return nil, fmt.Errorf("artifact resolver is available only for an active dispatch")
}

func (emptyArtifactResolver) ResolveTestBundle(context.Context, protocol.ExecutionRequest) (TestBundle, error) {
	return TestBundle{}, fmt.Errorf("artifact resolver is available only for an active dispatch")
}

func completionInputFromResult(result Result) runnerclient.CompletionInput {
	var peakMemory *int64
	if result.PeakMemoryBytes != nil {
		value := *result.PeakMemoryBytes
		peakMemory = &value
	}
	return runnerclient.CompletionInput{
		InfrastructureStatus:    string(result.InfrastructureStatus),
		InfrastructureErrorCode: result.InfrastructureErrorCode,
		CompilationStatus:       string(result.CompilationStatus),
		Verdict:                 string(result.Verdict),
		CleanupStatus:           string(result.CleanupStatus),
		TestsTotal:              int64(result.TestsTotal),
		TestsPassed:             int64(result.TestsPassed),
		ElapsedMs:               result.ElapsedMillis,
		PeakMemoryBytes:         peakMemory,
		RunnerVersion:           result.RunnerVersion,
		RuntimeImageDigest:      result.RuntimeImageDigest,
		ResultSHA256:            result.ResultSHA256,
		StartedAt:               result.StartedAt,
		CompletedAt:             result.CompletedAt,
	}
}
