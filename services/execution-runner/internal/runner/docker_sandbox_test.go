package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

type fakeDockerCLI struct {
	createArgs     []string
	containerID    string
	createErr      error
	startExitCode  int
	startErr       error
	stdout         []byte
	stderr         []byte
	waitForContext bool
	state          DockerContainerState
	inspectErr     error
	removeErr      error
	created        bool
	removed        bool
	stdin          []byte
}

func (fake *fakeDockerCLI) Create(_ context.Context, args []string) (string, error) {
	fake.created = true
	fake.createArgs = append([]string(nil), args...)
	if fake.createErr != nil {
		return "", fake.createErr
	}
	if fake.containerID == "" {
		fake.containerID = "0123456789abcdef"
	}
	return fake.containerID, nil
}

func (fake *fakeDockerCLI) StartAttached(
	ctx context.Context,
	id string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	if id != fake.containerID {
		return 0, ErrDockerCommandFailed
	}
	var err error
	fake.stdin, err = io.ReadAll(stdin)
	if err != nil {
		return 0, err
	}
	if fake.waitForContext {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if len(fake.stdout) > 0 {
		if _, err := stdout.Write(fake.stdout); err != nil {
			return 0, err
		}
	}
	if len(fake.stderr) > 0 {
		if _, err := stderr.Write(fake.stderr); err != nil {
			return 0, err
		}
	}
	return fake.startExitCode, fake.startErr
}

func (fake *fakeDockerCLI) Inspect(_ context.Context, id string) (DockerContainerState, error) {
	if id != fake.containerID {
		return DockerContainerState{}, ErrDockerCommandFailed
	}
	return fake.state, fake.inspectErr
}

func (fake *fakeDockerCLI) Remove(_ context.Context, id string) error {
	if id != fake.containerID {
		return ErrDockerCommandFailed
	}
	fake.removed = true
	return fake.removeErr
}

func dockerSandboxTestRequest() SandboxRequest {
	return SandboxRequest{
		ExecutionID:    "exec_docker_test",
		Language:       protocol.LanguageJava,
		RuntimeVersion: "25",
		ImageRef:       "registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		SourceName:     "Main.java",
		SourceBytes:    []byte("public class Main {}"),
		StandardInput:  []byte("hello stdin\n"),
		Limits: protocol.ResourceLimits{
			CPUQuotaMillis: 1000,
			MemoryBytes:    256 * 1024 * 1024,
			WallTimeMillis: 1000,
			ProcessLimit:   64,
			OutputBytes:    1024,
		},
	}
}

func containsArgument(args []string, expected string) bool {
	for _, argument := range args {
		if argument == expected {
			return true
		}
	}
	return false
}

func argumentAfter(args []string, flag string) string {
	for index, argument := range args {
		if argument == flag && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}

func TestDockerCreateArgumentsApplyRequiredIsolationPolicy(t *testing.T) {
	t.Parallel()
	request := dockerSandboxTestRequest()
	args, err := dockerCreateArguments(request, filepath.Join(t.TempDir(), "workspace"))
	if err != nil {
		t.Fatalf("dockerCreateArguments: %v", err)
	}
	required := []string{
		"--runtime=runsc",
		"--network=none",
		"--ipc=none",
		"--read-only",
		"--memory=268435456",
		"--memory-swap=268435456",
		"--cpus=1.000",
		"--pids-limit=64",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user=65532:65532",
		"--ulimit",
		"core=0:0",
		"--interactive",
		"--env=HOME=/tmp",
		"--entrypoint=/bin/sh",
	}
	for _, item := range required {
		if !containsArgument(args, item) {
			t.Errorf("container arguments missing %q: %v", item, args)
		}
	}
	if mount := argumentAfter(args, "--mount"); !strings.Contains(mount, "dst=/workspace,readonly") {
		t.Errorf("source workspace is not mounted read-only: %q", mount)
	}
	if !strings.Contains(argumentAfter(args, "--tmpfs"), "noexec,nosuid,nodev") {
		t.Errorf("scratch tmpfs lacks restrictive mount options: %q", argumentAfter(args, "--tmpfs"))
	}
	if containsArgument(args, "--network=host") || containsArgument(args, "--privileged") {
		t.Fatalf("unsafe Docker flags present: %v", args)
	}
}

func TestDockerSandboxPreservesSeparateStreamsAndCleansTemporaryWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fake := &fakeDockerCLI{
		stdout: []byte("program output\n"),
		stderr: []byte("program warning\n"),
		state:  DockerContainerState{Status: "exited", ExitCode: 0},
	}
	sandbox, err := NewDockerSandbox(fake, root)
	if err != nil {
		t.Fatalf("NewDockerSandbox: %v", err)
	}

	request := dockerSandboxTestRequest()
	observation, err := sandbox.RunCase(context.Background(), request)
	if err != nil {
		t.Fatalf("RunCase: %v", err)
	}
	if observation.Status != SandboxSucceeded || observation.CompilationStatus != CompilationSucceeded {
		t.Fatalf("unexpected execution status: %+v", observation)
	}
	if string(observation.StandardOutput) != "program output\n" ||
		string(observation.StandardError) != "program warning\n" {
		t.Fatalf("stdout/stderr were not retained separately: %+v", observation)
	}
	if !observation.CleanupSucceeded || !fake.removed {
		t.Fatalf("sandbox cleanup did not complete: %+v", observation)
	}
	if string(fake.stdin) != string(request.StandardInput) {
		t.Fatalf("stdin = %q, want %q", fake.stdin, request.StandardInput)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir temporary root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary source workspace was not removed: %v", entries)
	}
	mount := argumentAfter(fake.createArgs, "--mount")
	if !strings.Contains(mount, ",dst=/workspace,readonly") {
		t.Fatalf("source mount does not remain read-only: %q", mount)
	}
}

func TestDockerSandboxMapsCompileAndOOMStatuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		fake            fakeDockerCLI
		want            SandboxStatus
		wantCompilation CompilationStatus
	}{
		{
			name: "compiler error",
			fake: fakeDockerCLI{
				startExitCode: 86,
				state:         DockerContainerState{Status: "exited", ExitCode: 86},
				stderr:        []byte("compiler error"),
			},
			want:            SandboxCompileError,
			wantCompilation: CompilationFailed,
		},
		{
			name: "out of memory",
			fake: fakeDockerCLI{
				startExitCode: 137,
				state:         DockerContainerState{Status: "exited", ExitCode: 137, OOMKilled: true},
			},
			want:            SandboxMemoryLimit,
			wantCompilation: CompilationSucceeded,
		},
		{
			name: "runtime error",
			fake: fakeDockerCLI{
				startExitCode: 1,
				state:         DockerContainerState{Status: "exited", ExitCode: 1},
			},
			want:            SandboxRuntimeError,
			wantCompilation: CompilationSucceeded,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fake := test.fake
			sandbox, err := NewDockerSandbox(&fake, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			observation, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
			if err != nil {
				t.Fatalf("RunCase: %v", err)
			}
			if observation.Status != test.want || observation.CompilationStatus != test.wantCompilation {
				t.Fatalf("observation = %+v, want status %s/%s", observation, test.want, test.wantCompilation)
			}
			if !fake.removed || !observation.CleanupSucceeded {
				t.Fatal("container cleanup was not confirmed")
			}
		})
	}
}

func TestDockerSandboxEnforcesCombinedStdoutAndStderrLimit(t *testing.T) {
	t.Parallel()
	fake := &fakeDockerCLI{
		stdout: []byte("123456"),
		stderr: []byte("abcdef"),
		state:  DockerContainerState{Status: "exited", ExitCode: 0},
	}
	sandbox, err := NewDockerSandbox(fake, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := dockerSandboxTestRequest()
	request.Limits.OutputBytes = 8
	observation, err := sandbox.RunCase(context.Background(), request)
	if err != nil {
		t.Fatalf("RunCase: %v", err)
	}
	if observation.Status != SandboxOutputLimit {
		t.Fatalf("status = %s, want output limit", observation.Status)
	}
	if len(observation.StandardOutput)+len(observation.StandardError) > 8 {
		t.Fatalf("combined output exceeded configured cap: stdout=%d stderr=%d",
			len(observation.StandardOutput), len(observation.StandardError))
	}
	if !fake.removed {
		t.Fatal("output-limit cancellation did not remove the container")
	}
}

func TestDockerSandboxTimeoutKillsContainerAndCleansWorkspace(t *testing.T) {
	t.Parallel()
	fake := &fakeDockerCLI{waitForContext: true}
	sandbox, err := NewDockerSandbox(fake, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := dockerSandboxTestRequest()
	request.Limits.WallTimeMillis = 20

	observation, err := sandbox.RunCase(context.Background(), request)
	if err != nil {
		t.Fatalf("RunCase: %v", err)
	}
	if observation.Status != SandboxTimeLimit || !observation.CleanupSucceeded || !fake.removed {
		t.Fatalf("timeout cleanup not enforced: observation=%+v removed=%v", observation, fake.removed)
	}
}

func TestDockerSandboxTreatsContainerCleanupFailureAsInfrastructureError(t *testing.T) {
	t.Parallel()
	fake := &fakeDockerCLI{
		state:     DockerContainerState{Status: "exited", ExitCode: 0},
		removeErr: errors.New("docker rm failed"),
	}
	sandbox, err := NewDockerSandbox(fake, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	observation, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("error = %v, want ErrDockerCommandFailed", err)
	}
	if observation.CleanupSucceeded {
		t.Fatal("cleanup failure was incorrectly reported as success")
	}
	if !fake.removed {
		t.Fatal("cleanup call was not attempted")
	}
}

func TestBoundedOutputCombinesStreamsAndCancelsOnOverflow(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := newBoundedOutput(5, cancel)
	_, _ = writer.StdoutWriter().Write([]byte("123"))
	_, _ = writer.StderrWriter().Write([]byte("456"))

	if !writer.Exceeded() {
		t.Fatal("combined stdout/stderr overflow was not detected")
	}
	if ctx.Err() == nil {
		t.Fatal("overflow did not cancel the execution context")
	}
	if bytes := len(writer.StdoutBytes()) + len(writer.StderrBytes()); bytes > 5 {
		t.Fatalf("captured %d bytes above the configured limit", bytes)
	}
}
