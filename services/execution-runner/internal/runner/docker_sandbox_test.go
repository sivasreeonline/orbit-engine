package runner

import (
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
	copyErr        error
	copySourcePath string
	copyDestination string
	stagedSource   []byte
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

func (fake *fakeDockerCLI) CopyInto(
	ctx context.Context,
	id string,
	sourcePath string,
	destination string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if id != fake.containerID ||
		(destination != "/workspace/Main.java" && destination != "/workspace/main.py") {
		return ErrDockerCommandFailed
	}
	parentInfo, err := os.Stat(filepath.Dir(sourcePath))
	if err != nil || parentInfo.Mode().Perm() != 0o700 {
		return errors.New("host source parent is not private")
	}
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil || sourceInfo.Mode().Perm() != 0o444 {
		return errors.New("host source file is not read-only")
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	fake.copySourcePath = sourcePath
	fake.copyDestination = destination
	fake.stagedSource = append([]byte(nil), content...)
	return fake.copyErr
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
	if fake.copySourcePath == "" || fake.copyDestination == "" {
		return 0, errors.New("source was not copied into the container")
	}
	if _, err := os.Stat(fake.copySourcePath); !os.IsNotExist(err) {
		return 0, errors.New("host source staging remained present during execution")
	}
	var err error
	fake.stdin, err = io.ReadAll(stdin)
	if err != nil {
		return 0, err
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
	if fake.waitForContext {
		<-ctx.Done()
		return 0, ctx.Err()
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
	args, err := dockerCreateArguments(request)
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
	workspaceTmpfs := ""
	tmpfsCount := 0
	for index, argument := range args {
		if argument == "--tmpfs" && index+1 < len(args) {
			tmpfsCount++
			if strings.HasPrefix(args[index+1], "/workspace:") {
				workspaceTmpfs = args[index+1]
			}
		}
	}
	if !strings.Contains(workspaceTmpfs, "noexec,nosuid,nodev") {
		t.Errorf("workspace tmpfs lacks restrictive mount options: %q", workspaceTmpfs)
	}
	if tmpfsCount != 2 {
		t.Errorf("expected distinct /workspace and /tmp tmpfs mounts, got %d: %v", tmpfsCount, args)
	}
	if containsArgument(args, "--mount") {
		t.Fatalf("student source must not be bind-mounted from the host: %v", args)
	}
	if containsArgument(args, "--network=host") || containsArgument(args, "--privileged") {
		t.Fatalf("unsafe Docker flags present: %v", args)
	}
}

func TestDockerSandboxPreservesSeparateStreamsAndCleansTemporaryWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "program output\n"),
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
	if fake.copyDestination != "/workspace/Main.java" ||
		string(fake.stagedSource) != string(request.SourceBytes) {
		t.Fatalf("source was not copied to the fixed private container path: destination=%q", fake.copyDestination)
	}
	if _, err := os.Stat(fake.copySourcePath); !os.IsNotExist(err) {
		t.Fatal("private host source staging was not removed before execution")
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
				stdout:        []byte(compileSuccessMarker),
				state:         DockerContainerState{Status: "exited", ExitCode: 137, OOMKilled: true},
			},
			want:            SandboxMemoryLimit,
			wantCompilation: CompilationSucceeded,
		},
		{
			name: "runtime error",
			fake: fakeDockerCLI{
				startExitCode: 1,
				stdout:        []byte(compileSuccessMarker),
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
	if observation.Status != SandboxTimeLimit || observation.CompilationStatus != CompilationNotStarted ||
		!observation.CleanupSucceeded || !fake.removed {
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

func TestRuntimeScriptsVerifyPinnedVersionsAndExposeCompileBoundary(t *testing.T) {
	t.Parallel()

	javaScript := runtimeScript(protocol.LanguageJava, "25")
	for _, expected := range []string{
		"java -version",
		"javac ",
		" -proc:none ",
		"printf '",
		"exec java ",
	} {
		if !strings.Contains(javaScript, expected) {
			t.Errorf("Java runtime script missing %q: %s", expected, javaScript)
		}
	}
	if strings.Index(javaScript, "printf '") > strings.Index(javaScript, "exec java ") {
		t.Fatal("Java compile marker must be emitted before the program starts")
	}

	pythonScript := runtimeScript(protocol.LanguagePython, "3.14")
	for _, expected := range []string{
		"python3 --version",
		"python3 -I -B -c",
		"printf '",
		"exec python3 -I -B /workspace/main.py",
	} {
		if !strings.Contains(pythonScript, expected) {
			t.Errorf("Python runtime script missing %q: %s", expected, pythonScript)
		}
	}
	if strings.Index(pythonScript, "printf '") > strings.Index(pythonScript, "exec python3 -I -B /workspace/main.py") {
		t.Fatal("Python compile marker must be emitted before the program starts")
	}
	if strings.Contains(javaScript, "source bytes") || strings.Contains(pythonScript, "source bytes") {
		t.Fatal("fixed runtime wrapper must not interpolate student source into shell text")
	}
}

func TestCompileMarkerIsRemovedWithoutChangingProgramOutput(t *testing.T) {
	t.Parallel()

	output := []byte(compileSuccessMarker + "student output\n")
	compiled, cleaned := removeCompileSuccessMarker(output)
	if !compiled {
		t.Fatal("compile marker was not recognized")
	}
	if string(cleaned) != "student output\n" {
		t.Fatalf("cleaned output = %q, want student output", cleaned)
	}

	plain := []byte("student output\n")
	compiled, cleaned = removeCompileSuccessMarker(plain)
	if compiled || string(cleaned) != string(plain) {
		t.Fatalf("ordinary output changed: compiled=%v output=%q", compiled, cleaned)
	}
}

func TestSandboxRejectsUntrustedRuntimeAndImageTokens(t *testing.T) {
	t.Parallel()

	request := dockerSandboxTestRequest()
	request.RuntimeVersion = "25; touch /tmp/injected"
	if err := validateSandboxRequest(request); err == nil {
		t.Fatal("runtime version accepted shell metacharacters")
	}

	request = dockerSandboxTestRequest()
	request.ImageRef = "--privileged@sha256:" + strings.Repeat("a", 64)
	if _, err := dockerCreateArguments(request, filepath.Join(t.TempDir(), "workspace")); err == nil {
		t.Fatal("flag-like image reference was accepted")
	}
}


func TestDockerSandboxCopyFailureAbortsExecutionAndCleansContainerAndHostSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fake := &fakeDockerCLI{
		copyErr: errors.New("docker cp failed"),
	}
	sandbox, err := NewDockerSandbox(fake, root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want ErrDockerCommandFailed", err)
	}
	if !fake.created || !fake.removed {
		t.Fatalf("copy failure did not clean up the created container: %+v", fake)
	}
	if fake.startExitCode != 0 || fake.copyDestination == "" {
		t.Fatal("execution should not start after a failed source copy")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("private host source staging remains after copy failure: %v", entries)
	}
}
