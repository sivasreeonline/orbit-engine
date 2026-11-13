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
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerclient"
)

func adapterRuntimeConfig() RuntimeConfiguration {
	return RuntimeConfiguration{
		RunnerVersion: "runner-adapter-test",
		JavaVersion: "25",
		JavaImageRef: "registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		PythonVersion: "3.14",
		PythonImageRef: "registry.example/sky-high/python@sha256:" + strings.Repeat("b", 64),
	}
}

func adapterExecutionLimits() protocol.ResourceLimits {
	return protocol.ResourceLimits{
		CPUQuotaMillis: 1000,
		MemoryBytes: 256 * 1024 * 1024,
		WallTimeMillis: 5000,
		ProcessLimit: 64,
		OutputBytes: 1024 * 1024,
	}
}

func adapterArtifact(action string) runnerclient.ExecutionArtifact {
	source := conformanceSource()
	digest := sha256.Sum256(source)
	cases := []runnerclient.ArtifactTestCase{
		{
			TestCaseID: "a3000000-0000-4000-8000-000000000001",
			Sequence: 1,
			Visibility: "PUBLIC",
			Input: "1",
			ExpectedOutput: "ok\n",
		},
	}
	if action == "SUBMIT" {
		cases = append(cases, runnerclient.ArtifactTestCase{
			TestCaseID: "a3000000-0000-4000-8000-000000000002",
			Sequence: 2,
			Visibility: "HIDDEN",
			Input: "secret input",
			ExpectedOutput: "secret expected output",
		})
	}
	return runnerclient.ExecutionArtifact{
		ExecutionID: "60000000-0000-4000-8000-000000000001",
		AttemptID: "70000000-0000-4000-8000-000000000001",
		ProblemVersionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
		ProblemSlug: "two-sum",
		ProblemTitle: "Two Sum",
		Action: action,
		Language: "java",
		RuntimeVersion: "25",
		SourceArtifactID: "a2000000-0000-4000-8000-000000000001",
		SourceSHA256: hex.EncodeToString(digest[:]),
		SourceCode: string(source),
		TestBundleID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1-" + strings.ToLower(action) + "-0123456789abcdef",
		TestBundleSHA256: strings.Repeat("c", 64),
		TestCases: cases,
	}
}

func TestSandboxArtifactExecutorIsDisabledUnlessExplicitlyEnabled(t *testing.T) {
	t.Parallel()
	sandbox := &conformanceSandbox{}
	executor, err := NewSandboxArtifactExecutor(sandbox, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: adapterExecutionLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.Ready() {
		t.Fatal("sandbox executor became ready without an explicit enable decision")
	}
	if _, err := executor.Execute(context.Background(), adapterArtifact("RUN")); !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("disabled execution error = %v, want ErrSandboxNotConfigured", err)
	}
	if len(sandbox.requests) != 0 {
		t.Fatal("disabled artifact executor invoked the sandbox")
	}
}

func TestSandboxArtifactExecutorMapsVerifiedRunArtifactsToAggregateCompletion(t *testing.T) {
	t.Parallel()
	sandbox := &conformanceSandbox{observations: []SandboxObservation{{
		Status: SandboxSucceeded,
		CompilationStatus: CompilationSucceeded,
		StandardOutput: []byte("ok\n"),
		ElapsedMillis: 8,
		CleanupSucceeded: true,
	}}}
	executor, err := NewSandboxArtifactExecutor(sandbox, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: adapterExecutionLimits(),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !executor.Ready() {
		t.Fatal("explicitly enabled sandbox executor did not report readiness")
	}

	result, err := executor.Execute(context.Background(), adapterArtifact("RUN"))
	if err != nil {
		t.Fatal(err)
	}
	if result.InfrastructureStatus != string(InfrastructureSucceeded) ||
		result.CompilationStatus != string(CompilationSucceeded) ||
		result.Verdict != string(VerdictAccepted) ||
		result.CleanupStatus != string(CleanupSucceeded) ||
		result.TestsTotal != 1 || result.TestsPassed != 1 {
		t.Fatalf("unexpected completion aggregate: %+v", result)
	}
	if len(result.ResultSHA256) != 64 || result.RunnerVersion != "runner-adapter-test" ||
		result.RuntimeImageDigest != strings.Repeat("a", 64) {
		t.Fatalf("completion result is missing its trusted runtime/result identity: %+v", result)
	}
	if len(sandbox.requests) != 1 || string(sandbox.requests[0].SourceBytes) != string(conformanceSource()) {
		t.Fatalf("authenticated source was not passed to the sandbox: %+v", sandbox.requests)
	}
}

func TestSandboxArtifactExecutorKeepsHiddenFixturesOutOfCompletionPayload(t *testing.T) {
	t.Parallel()
	sandbox := &conformanceSandbox{observations: []SandboxObservation{
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("ok\n"), CleanupSucceeded: true},
		{Status: SandboxSucceeded, CompilationStatus: CompilationSucceeded, StandardOutput: []byte("wrong\n"), CleanupSucceeded: true},
	}}
	executor, err := NewSandboxArtifactExecutor(sandbox, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: adapterExecutionLimits(),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(context.Background(), adapterArtifact("SUBMIT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != string(VerdictWrongAnswer) || result.TestsTotal != 2 || result.TestsPassed != 1 {
		t.Fatalf("hidden fixture aggregate is incorrect: %+v", result)
	}
	// The terminal completion contract carries only the aggregate. It cannot
	// expose any per-case identifier, input, expected output, stdout or stderr.
	completion := completionInputFromResult(result)
	encodedBytes, err := json.Marshal(completion)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(encodedBytes)
	for _, forbidden := range []string{
		"secret input",
		"secret expected output",
		"wrong\\n",
		"ok\\n",
		"a3000000-0000-4000-8000-000000000001",
		"a3000000-0000-4000-8000-000000000002",
		"standardOutput",
		"standardError",
		"caseId",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("per-case data leaked into completion envelope: %q", forbidden)
		}
	}
	if completion.TestsTotal != 2 || completion.TestsPassed != 1 ||
		completion.Verdict != string(VerdictWrongAnswer) {
		t.Fatalf("terminal completion lost aggregate verdict/counts: %+v", completion)
	}
}

func TestSandboxArtifactExecutorRejectsHiddenRunCasesBeforeSandbox(t *testing.T) {
	t.Parallel()
	sandbox := &conformanceSandbox{}
	artifact := adapterArtifact("RUN")
	artifact.TestCases = append(artifact.TestCases, runnerclient.ArtifactTestCase{
		TestCaseID: "a3000000-0000-4000-8000-000000000002",
		Sequence: 2,
		Visibility: "HIDDEN",
		Input: "hidden",
		ExpectedOutput: "hidden",
	})
	executor, err := NewSandboxArtifactExecutor(sandbox, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: adapterExecutionLimits(),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.InfrastructureStatus != string(InfrastructureFailed) ||
		result.InfrastructureErrorCode != "TEST_BUNDLE_INVALID" ||
		result.Verdict != string(VerdictNotEvaluated) {
		t.Fatalf("invalid RUN fixture policy was not failed closed: %+v", result)
	}
	if len(sandbox.requests) != 0 {
		t.Fatal("sandbox invoked for a RUN bundle containing hidden fixtures")
	}
}

func TestSandboxArtifactExecutorRechecksSourceDigestAndDispatchFixtureOrder(t *testing.T) {
	t.Parallel()
	sandbox := &conformanceSandbox{}
	executor, err := NewSandboxArtifactExecutor(sandbox, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: adapterExecutionLimits(),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	artifact := adapterArtifact("RUN")
	artifact.SourceSHA256 = strings.Repeat("d", 64)
	digestMismatch, err := executor.Execute(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if digestMismatch.InfrastructureErrorCode != "SOURCE_DIGEST_MISMATCH" || len(sandbox.requests) != 0 {
		t.Fatalf("source digest was not rechecked before sandbox: %+v", digestMismatch)
	}

	artifact = adapterArtifact("RUN")
	artifact.TestCases[0].Sequence = 2
	artifact.TestCases = append(artifact.TestCases, runnerclient.ArtifactTestCase{
		TestCaseID: "a3000000-0000-4000-8000-000000000002",
		Sequence: 1,
		Visibility: "PUBLIC",
		Input: "2",
		ExpectedOutput: "ok\n",
	})
	if _, err := executor.Execute(context.Background(), artifact); !errors.Is(err, protocol.ErrInvalidRequest) {
		t.Fatalf("out-of-order authenticated test cases were accepted: %v", err)
	}
	if len(sandbox.requests) != 0 {
		t.Fatal("sandbox invoked for a noncanonical test order")
	}
}

func TestSandboxArtifactExecutorRequiresValidResourcePolicy(t *testing.T) {
	t.Parallel()
	limits := adapterExecutionLimits()
	limits.WallTimeMillis = 0
	if _, err := NewSandboxArtifactExecutor(&conformanceSandbox{}, SandboxArtifactExecutorConfig{
		Runtime: adapterRuntimeConfig(),
		Limits: limits,
		Enabled: true,
	}); err == nil {
		t.Fatal("invalid resource policy was accepted")
	}
}
