package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

type conformanceResolver struct {
	source []byte
	bundle TestBundle
	err    error
}

func (r *conformanceResolver) ResolveSource(context.Context, protocol.ExecutionRequest) ([]byte, error) {
	return append([]byte(nil), r.source...), r.err
}

func (r *conformanceResolver) ResolveTestBundle(context.Context, protocol.ExecutionRequest) (TestBundle, error) {
	return r.bundle, r.err
}

type conformanceSandbox struct {
	observations []SandboxObservation
	requests     []SandboxRequest
}

func (s *conformanceSandbox) RunCase(_ context.Context, request SandboxRequest) (SandboxObservation, error) {
	s.requests = append(s.requests, request)
	if len(s.observations) == 0 {
		return SandboxObservation{}, errors.New("no_observation_configured")
	}
	observation := s.observations[0]
	s.observations = s.observations[1:]
	return observation, nil
}

func conformanceSource() []byte {
	return []byte("public class Main { public static void main(String[] args) { System.out.println(\"ok\"); } }")
}

func conformanceRequest(action protocol.Action, source []byte) protocol.ExecutionRequest {
	digest := sha256.Sum256(source)
	return protocol.ExecutionRequest{
		ProtocolVersion:  "v1",
		ExecutionID:      "exec_evidence_1",
		AttemptID:        "attempt_evidence_1",
		ProblemVersionID: "problem_v1",
		Action:           action,
		Language:         protocol.LanguageJava,
		RuntimeVersion:   "25",
		SourceArtifactID: "source_1",
		SourceSHA256:     hex.EncodeToString(digest[:]),
		TestBundleID:     "bundle_1",
		Limits: protocol.ResourceLimits{
			CPUQuotaMillis: 1000,
			MemoryBytes:    256 * 1024 * 1024,
			WallTimeMillis: 5000,
			ProcessLimit:   64,
			OutputBytes:    1024 * 1024,
		},
	}
}

func conformanceBundle() TestBundle {
	return TestBundle{
		ProblemVersionID: "problem_v1",
		Cases: []TestCase{
			{ID: "public_1", Visibility: TestVisibilityPublic, Input: []byte("1"), ExpectedOutput: []byte("ok\n"), Comparison: CompareExactBytes},
			{ID: "public_2", Visibility: TestVisibilityPublic, Input: []byte("2"), ExpectedOutput: []byte("ok\n"), Comparison: CompareExactBytes},
		},
	}
}

func conformanceExecutor(t *testing.T, resolver ArtifactResolver, sandbox Sandbox) *SandboxExecutor {
	t.Helper()
	executor, err := NewSandboxExecutor(resolver, sandbox, RuntimeConfiguration{
		RunnerVersion:  "runner-test",
		JavaVersion:    "25",
		JavaImageRef:   "registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		PythonVersion:  "3.14",
		PythonImageRef: "registry.example/sky-high/python@sha256:" + strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatalf("NewSandboxExecutor: %v", err)
	}
	return executor
}

func TestSandboxExecutorAcceptsAndReturnsOnlyPinnedPublicEvidence(t *testing.T) {
	t.Parallel()
	source := conformanceSource()
	sandbox := &conformanceSandbox{observations: []SandboxObservation{
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("ok\n"), ElapsedMillis: 12, CleanupSucceeded: true},
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("ok\n"), ElapsedMillis: 9, CleanupSucceeded: true},
	}}
	executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: conformanceBundle()}, sandbox)

	result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionRun, source))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.InfrastructureStatus != InfrastructureSucceeded || result.Verdict != VerdictAccepted ||
		result.TestsTotal != 2 || result.TestsPassed != 2 || len(result.PublicTestResults) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.RuntimeImageDigest != strings.Repeat("a", 64) || len(result.ResultSHA256) != 64 {
		t.Fatalf("runtime pin or result digest missing: %+v", result)
	}
}

func TestSubmitHidesPerCaseDetailsForHiddenTests(t *testing.T) {
	t.Parallel()
	source := conformanceSource()
	bundle := TestBundle{
		ProblemVersionID: "problem_v1",
		Cases: []TestCase{
			{ID: "visible-case", Visibility: TestVisibilityPublic, Input: []byte("visible"), ExpectedOutput: []byte("ok"), Comparison: CompareExactBytes},
			{ID: "secret-hidden-case-id", Visibility: TestVisibilityHidden, Input: []byte("secret hidden input"), ExpectedOutput: []byte("secret expected output"), Comparison: CompareExactBytes},
		},
	}
	sandbox := &conformanceSandbox{observations: []SandboxObservation{
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("ok"), CleanupSucceeded: true},
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("wrong"), CleanupSucceeded: true},
	}}
	executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: bundle}, sandbox)

	result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionSubmit, source))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Verdict != VerdictWrongAnswer || result.TestsTotal != 2 || result.TestsPassed != 1 {
		t.Fatalf("unexpected hidden-test aggregate: %+v", result)
	}
	if len(result.PublicTestResults) != 1 || result.PublicTestResults[0].CaseID != "visible-case" {
		t.Fatalf("hidden test details escaped: %+v", result.PublicTestResults)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-hidden-case-id", "secret hidden input", "secret expected output"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("hidden test detail leaked: %q", secret)
		}
	}
}

func TestRunRejectsHiddenTestBundleBeforeSandbox(t *testing.T) {
	t.Parallel()
	source := conformanceSource()
	bundle := conformanceBundle()
	bundle.Cases = append(bundle.Cases, TestCase{
		ID: "hidden_case", Visibility: TestVisibilityHidden,
		Input: []byte("hidden"), ExpectedOutput: []byte("hidden"),
		Comparison: CompareExactBytes,
	})
	sandbox := &conformanceSandbox{}
	executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: bundle}, sandbox)

	result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionRun, source))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.InfrastructureErrorCode != "TEST_BUNDLE_INVALID" || result.Verdict != VerdictNotEvaluated {
		t.Fatalf("invalid Run bundle was not rejected: %+v", result)
	}
	if len(sandbox.requests) != 0 {
		t.Fatal("sandbox started with a Run bundle containing hidden tests")
	}
}

func TestSourceHashMismatchFailsBeforeSandbox(t *testing.T) {
	t.Parallel()
	source := []byte("different source")
	sandbox := &conformanceSandbox{}
	executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: conformanceBundle()}, sandbox)

	result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionRun, conformanceSource()))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.InfrastructureErrorCode != "SOURCE_DIGEST_MISMATCH" || result.Verdict != VerdictNotEvaluated {
		t.Fatalf("source mismatch was not classified as infrastructure failure: %+v", result)
	}
	if len(sandbox.requests) != 0 {
		t.Fatal("sandbox started before source digest verification")
	}
}

func TestStudentFailuresRemainDistinctFromInfrastructureFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status      SandboxStatus
		compilation CompilationStatus
		want        Verdict
	}{
		{SandboxCompileError, CompilationFailed, VerdictCompilationError},
		{SandboxRuntimeError, CompilationSucceeded, VerdictRuntimeError},
		{SandboxTimeLimit, CompilationSucceeded, VerdictTimeLimitExceeded},
		{SandboxTimeLimit, CompilationNotStarted, VerdictTimeLimitExceeded},
		{SandboxMemoryLimit, CompilationSucceeded, VerdictMemoryLimitExceeded},
		{SandboxMemoryLimit, CompilationNotStarted, VerdictMemoryLimitExceeded},
		{SandboxOutputLimit, CompilationSucceeded, VerdictOutputLimitExceeded},
		{SandboxOutputLimit, CompilationNotStarted, VerdictOutputLimitExceeded},
	}
	for _, item := range cases {
		item := item
		t.Run(string(item.want), func(t *testing.T) {
			t.Parallel()
			source := conformanceSource()
			sandbox := &conformanceSandbox{observations: []SandboxObservation{{
				Status: item.status, CompilationStatus: item.compilation,
				StandardError: []byte("private diagnostic"), CleanupSucceeded: true,
			}}}
			executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: conformanceBundle()}, sandbox)
			result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionRun, source))
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.InfrastructureStatus != InfrastructureSucceeded ||
				result.Verdict != item.want || result.CompilationStatus != item.compilation {
				t.Fatalf("result = %+v, want verdict/compilation %s/%s",
					result, item.want, item.compilation)
			}
		})
	}
}

func TestSandboxCleanupFailureIsInfrastructureFailure(t *testing.T) {
	t.Parallel()
	source := conformanceSource()
	sandbox := &conformanceSandbox{observations: []SandboxObservation{{
		Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded,
		CleanupSucceeded: false,
	}}}
	executor := conformanceExecutor(t, &conformanceResolver{source: source, bundle: conformanceBundle()}, sandbox)
	result, err := executor.Execute(context.Background(), conformanceRequest(protocol.ActionRun, source))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.InfrastructureErrorCode != "SANDBOX_CLEANUP_FAILED" ||
		result.Verdict != VerdictNotEvaluated || result.CleanupStatus != CleanupFailed {
		t.Fatalf("cleanup failure incorrectly became a student verdict: %+v", result)
	}
}
