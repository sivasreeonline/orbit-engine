package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

var (
	ErrSandboxNotConfigured = errors.New("sandbox executor is not configured")
	ErrInvalidRuntimeConfig = errors.New("invalid pinned runtime configuration")
)

const (
	maximumSourceBytes = 200 * 1024
	maximumTestCases   = 1000
	maximumTestBytes   = 64 * 1024
	maximumBundleBytes = 4 * 1024 * 1024
	maximumCPUQuota    = int64(2000)
	maximumMemoryBytes = int64(1024 * 1024 * 1024)
	maximumWallMillis  = int64(30_000)
	maximumProcessCount = int64(128)
	maximumOutputBytes = int64(1024 * 1024)
)

var (
	runtimeVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	artifactCaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	imageReferencePattern = regexp.MustCompile(`^.+@sha256:([0-9a-f]{64})$`)
)

type Executor interface {
	Execute(context.Context, protocol.ExecutionRequest) (Result, error)
}

type RuntimeConfiguration struct {
	RunnerVersion  string
	JavaVersion    string
	JavaImageRef   string
	PythonVersion  string
	PythonImageRef string
}

type SandboxExecutor struct {
	resolver ArtifactResolver
	sandbox  Sandbox
	runtimes RuntimeConfiguration
}

func NewSandboxExecutor(
	resolver ArtifactResolver,
	sandbox Sandbox,
	runtimes RuntimeConfiguration,
) (*SandboxExecutor, error) {
	if resolver == nil || sandbox == nil {
		return nil, ErrInvalidRuntimeConfig
	}
	if !runtimeVersionPattern.MatchString(runtimes.RunnerVersion) ||
		!runtimeVersionPattern.MatchString(runtimes.JavaVersion) ||
		!runtimeVersionPattern.MatchString(runtimes.PythonVersion) {
		return nil, ErrInvalidRuntimeConfig
	}
	if !imageReferencePattern.MatchString(runtimes.JavaImageRef) ||
		!imageReferencePattern.MatchString(runtimes.PythonImageRef) {
		return nil, ErrInvalidRuntimeConfig
	}

	return &SandboxExecutor{
		resolver: resolver,
		sandbox:  sandbox,
		runtimes: runtimes,
	}, nil
}

func (executor *SandboxExecutor) Execute(
	ctx context.Context,
	request protocol.ExecutionRequest,
) (Result, error) {
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	if err := validateExecutionLimits(request.Limits); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	startedAt := time.Now().UTC()
	imageRef, runtimeVersion, runtimeDigest, ok := executor.runtimeFor(request.Language)
	if !ok || runtimeVersion != request.RuntimeVersion {
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"RUNTIME_VERSION_NOT_CONFIGURED",
			CleanupUnknown,
			startedAt,
		), nil
	}

	source, err := executor.resolver.ResolveSource(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"SOURCE_ARTIFACT_UNAVAILABLE",
			CleanupUnknown,
			startedAt,
		), nil
	}
	if len(source) == 0 || len(source) > maximumSourceBytes {
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"SOURCE_ARTIFACT_INVALID",
			CleanupUnknown,
			startedAt,
		), nil
	}

	sourceDigest := sha256.Sum256(source)
	actualSourceDigest := hex.EncodeToString(sourceDigest[:])
	if !strings.EqualFold(actualSourceDigest, request.SourceSHA256) {
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"SOURCE_DIGEST_MISMATCH",
			CleanupUnknown,
			startedAt,
		), nil
	}

	bundle, err := executor.resolver.ResolveTestBundle(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"TEST_BUNDLE_UNAVAILABLE",
			CleanupUnknown,
			startedAt,
		), nil
	}
	if err := validateTestBundle(request, bundle); err != nil {
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"TEST_BUNDLE_INVALID",
			CleanupUnknown,
			startedAt,
		), nil
	}

	result := Result{
		ExecutionID:          request.ExecutionID,
		SourceSHA256:          actualSourceDigest,
		InfrastructureStatus: InfrastructureSucceeded,
		CompilationStatus:    CompilationNotStarted,
		Verdict:              VerdictAccepted,
		CleanupStatus:        CleanupSucceeded,
		TestsTotal:           len(bundle.Cases),
		RunnerVersion:        executor.runtimes.RunnerVersion,
		RuntimeImageDigest:   runtimeDigest,
		StartedAt:            startedAt,
	}
	hasWrongAnswer := false

	for _, testCase := range bundle.Cases {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		observation, runErr := executor.sandbox.RunCase(ctx, SandboxRequest{
			ExecutionID:    request.ExecutionID,
			Language:       request.Language,
			RuntimeVersion: request.RuntimeVersion,
			ImageRef:       imageRef,
			SourceName:     sourceFileName(request.Language),
			SourceBytes:    source,
			StandardInput:  testCase.Input,
			Limits:         request.Limits,
		})
		if runErr != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return executor.infrastructureFailure(
				request,
				runtimeDigest,
				"SANDBOX_EXECUTION_FAILED",
				CleanupUnknown,
				startedAt,
			), nil
		}
		if !observation.CleanupSucceeded {
			return executor.infrastructureFailure(
				request,
				runtimeDigest,
				"SANDBOX_CLEANUP_FAILED",
				CleanupFailed,
				startedAt,
			), nil
		}
		if observation.ElapsedMillis < 0 ||
			int64(len(observation.StandardOutput)+len(observation.StandardError)) > request.Limits.OutputBytes {
			return executor.infrastructureFailure(
				request,
				runtimeDigest,
				"SANDBOX_RESULT_INVALID",
				CleanupSucceeded,
				startedAt,
			), nil
		}
		if observation.PeakMemoryBytes != nil &&
			(observation.PeakMemoryBytes == nil || *observation.PeakMemoryBytes < 0) {
			return executor.infrastructureFailure(
				request,
				runtimeDigest,
				"SANDBOX_METRIC_INVALID",
				CleanupSucceeded,
				startedAt,
			), nil
		}
		if observation.PeakMemoryBytes != nil {
			if result.PeakMemoryBytes == nil || *observation.PeakMemoryBytes > *result.PeakMemoryBytes {
				value := *observation.PeakMemoryBytes
				result.PeakMemoryBytes = &value
			}
		}
		result.ElapsedMillis += observation.ElapsedMillis

		switch observation.Status {
		case SandboxCompileError:
			if observation.CompilationStatus != CompilationFailed {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationFailed
			result.Verdict = VerdictCompilationError
			result.TestsTotal = 0
			result.TestsPassed = 0
			result.CompilationOutput = append(
				append([]byte(nil), observation.StandardOutput...),
				observation.StandardError...,
			)
			return executor.finish(result), nil

		case SandboxSucceeded:
			if observation.CompilationStatus != CompilationSucceeded {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationSucceeded
			passed := outputsMatch(
				observation.StandardOutput,
				testCase.ExpectedOutput,
				testCase.Comparison,
			)
			publicStatus := PublicTestPassed
			if passed {
				result.TestsPassed++
			} else {
				hasWrongAnswer = true
				publicStatus = PublicTestFailed
			}
			if testCase.Visibility == TestVisibilityPublic {
				result.PublicTestResults = append(result.PublicTestResults, PublicTestResult{
					CaseID:         testCase.ID,
					Status:         publicStatus,
					StandardOutput: append([]byte(nil), observation.StandardOutput...),
					StandardError:  append([]byte(nil), observation.StandardError...),
					ElapsedMillis:  observation.ElapsedMillis,
				})
			}

		case SandboxRuntimeError:
			if observation.CompilationStatus != CompilationSucceeded {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationSucceeded
			result.Verdict = VerdictRuntimeError
			if testCase.Visibility == TestVisibilityPublic {
				result.PublicTestResults = append(result.PublicTestResults, PublicTestResult{
					CaseID:         testCase.ID,
					Status:         PublicTestRuntimeError,
					StandardOutput: append([]byte(nil), observation.StandardOutput...),
					StandardError:  append([]byte(nil), observation.StandardError...),
					ElapsedMillis:  observation.ElapsedMillis,
				})
			}
			return executor.finish(result), nil

		case SandboxTimeLimit:
			if observation.CompilationStatus == CompilationFailed {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationSucceeded
			result.Verdict = VerdictTimeLimitExceeded
			if testCase.Visibility == TestVisibilityPublic {
				result.PublicTestResults = append(result.PublicTestResults, PublicTestResult{
					CaseID:         testCase.ID,
					Status:         PublicTestTimeLimitExceeded,
					StandardOutput: append([]byte(nil), observation.StandardOutput...),
					StandardError:  append([]byte(nil), observation.StandardError...),
					ElapsedMillis:  observation.ElapsedMillis,
				})
			}
			return executor.finish(result), nil

		case SandboxMemoryLimit:
			if observation.CompilationStatus == CompilationFailed {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationSucceeded
			result.Verdict = VerdictMemoryLimitExceeded
			if testCase.Visibility == TestVisibilityPublic {
				result.PublicTestResults = append(result.PublicTestResults, PublicTestResult{
					CaseID:         testCase.ID,
					Status:         PublicTestMemoryLimitExceeded,
					StandardOutput: append([]byte(nil), observation.StandardOutput...),
					StandardError:  append([]byte(nil), observation.StandardError...),
					ElapsedMillis:  observation.ElapsedMillis,
				})
			}
			return executor.finish(result), nil

		case SandboxOutputLimit:
			if observation.CompilationStatus == CompilationFailed {
				return executor.infrastructureFailure(
					request,
					runtimeDigest,
					"SANDBOX_RESULT_INVALID",
					CleanupSucceeded,
					startedAt,
				), nil
			}
			result.CompilationStatus = CompilationSucceeded
			result.Verdict = VerdictOutputLimitExceeded
			if testCase.Visibility == TestVisibilityPublic {
				result.PublicTestResults = append(result.PublicTestResults, PublicTestResult{
					CaseID:         testCase.ID,
					Status:         PublicTestOutputLimitExceeded,
					StandardOutput: append([]byte(nil), observation.StandardOutput...),
					StandardError:  append([]byte(nil), observation.StandardError...),
					ElapsedMillis:  observation.ElapsedMillis,
				})
			}
			return executor.finish(result), nil

		default:
			return executor.infrastructureFailure(
				request,
				runtimeDigest,
				"SANDBOX_RESULT_INVALID",
				CleanupSucceeded,
				startedAt,
			), nil
		}
	}

	if result.CompilationStatus == CompilationNotStarted {
		return executor.infrastructureFailure(
			request,
			runtimeDigest,
			"NO_TESTS_EXECUTED",
			CleanupSucceeded,
			startedAt,
		), nil
	}
	if hasWrongAnswer {
		result.Verdict = VerdictWrongAnswer
	}
	return executor.finish(result), nil
}

type UnconfiguredExecutor struct{}

func (UnconfiguredExecutor) Execute(
	_ context.Context,
	_ protocol.ExecutionRequest,
) (Result, error) {
	return Result{}, ErrSandboxNotConfigured
}

func (executor *SandboxExecutor) runtimeFor(language protocol.Language) (string, string, string, bool) {
	var imageRef, version string
	switch language {
	case protocol.LanguageJava:
		imageRef = executor.runtimes.JavaImageRef
		version = executor.runtimes.JavaVersion
	case protocol.LanguagePython:
		imageRef = executor.runtimes.PythonImageRef
		version = executor.runtimes.PythonVersion
	default:
		return "", "", "", false
	}
	match := imageReferencePattern.FindStringSubmatch(imageRef)
	if len(match) != 2 {
		return "", "", "", false
	}
	return imageRef, version, match[1], true
}

func (executor *SandboxExecutor) infrastructureFailure(
	request protocol.ExecutionRequest,
	runtimeDigest string,
	code string,
	cleanup CleanupStatus,
	startedAt time.Time,
) Result {
	now := time.Now().UTC()
	result := Result{
		ExecutionID:             request.ExecutionID,
		SourceSHA256:             strings.ToLower(request.SourceSHA256),
		InfrastructureStatus:    InfrastructureFailed,
		InfrastructureErrorCode: code,
		CompilationStatus:       CompilationNotStarted,
		Verdict:                 VerdictNotEvaluated,
		CleanupStatus:           cleanup,
		RunnerVersion:           executor.runtimes.RunnerVersion,
		RuntimeImageDigest:      runtimeDigest,
		StartedAt:               startedAt,
		CompletedAt:             now,
		ElapsedMillis:           nonNegativeMillis(now.Sub(startedAt)),
	}
	return sealResult(result)
}

func (executor *SandboxExecutor) finish(result Result) Result {
	now := time.Now().UTC()
	result.CompletedAt = now
	result.ElapsedMillis = nonNegativeMillis(now.Sub(result.StartedAt))
	return sealResult(result)
}

func sealResult(result Result) Result {
	result.ResultSHA256 = ""
	payload, err := json.Marshal(result)
	if err != nil {
		return result
	}
	digest := sha256.Sum256(payload)
	result.ResultSHA256 = hex.EncodeToString(digest[:])
	return result
}

func validateExecutionLimits(limits protocol.ResourceLimits) error {
	if limits.CPUQuotaMillis <= 0 || limits.CPUQuotaMillis > maximumCPUQuota ||
		limits.MemoryBytes <= 0 || limits.MemoryBytes > maximumMemoryBytes ||
		limits.WallTimeMillis <= 0 || limits.WallTimeMillis > maximumWallMillis ||
		limits.ProcessLimit <= 0 || limits.ProcessLimit > maximumProcessCount ||
		limits.OutputBytes <= 0 || limits.OutputBytes > maximumOutputBytes {
		return protocol.ErrInvalidRequest
	}
	return nil
}

func validateTestBundle(request protocol.ExecutionRequest, bundle TestBundle) error {
	if bundle.ProblemVersionID != request.ProblemVersionID ||
		len(bundle.Cases) == 0 || len(bundle.Cases) > maximumTestCases {
		return protocol.ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(bundle.Cases))
	totalBytes := 0
	for _, testCase := range bundle.Cases {
		if !artifactCaseIDPattern.MatchString(testCase.ID) {
			return protocol.ErrInvalidRequest
		}
		if _, exists := seen[testCase.ID]; exists {
			return protocol.ErrInvalidRequest
		}
		seen[testCase.ID] = struct{}{}
		if testCase.Visibility != TestVisibilityPublic && testCase.Visibility != TestVisibilityHidden {
			return protocol.ErrInvalidRequest
		}
		if request.Action == protocol.ActionRun && testCase.Visibility != TestVisibilityPublic {
			return protocol.ErrInvalidRequest
		}
		if len(testCase.Input) > maximumTestBytes || len(testCase.ExpectedOutput) > maximumTestBytes {
			return protocol.ErrInvalidRequest
		}
		if testCase.Comparison != CompareExactBytes &&
			testCase.Comparison != CompareTrimTrailingWhitespace {
			return protocol.ErrInvalidRequest
		}
		totalBytes += len(testCase.Input) + len(testCase.ExpectedOutput)
		if totalBytes > maximumBundleBytes {
			return protocol.ErrInvalidRequest
		}
	}
	return nil
}

func outputsMatch(actual, expected []byte, comparison OutputComparison) bool {
	switch comparison {
	case CompareExactBytes:
		return bytes.Equal(actual, expected)
	case CompareTrimTrailingWhitespace:
		trim := func(value []byte) []byte {
			return bytes.TrimRightFunc(value, unicode.IsSpace)
		}
		return bytes.Equal(trim(actual), trim(expected))
	default:
		return false
	}
}

func sourceFileName(language protocol.Language) string {
	if language == protocol.LanguageJava {
		return "Main.java"
	}
	return "main.py"
}

func nonNegativeMillis(duration time.Duration) int64 {
	millis := duration.Milliseconds()
	if millis < 0 {
		return 0
	}
	return millis
}
