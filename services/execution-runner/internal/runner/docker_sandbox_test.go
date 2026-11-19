package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

type fakeDockerCLI struct {
	preflightErr   error
	preflightImages []string
	createArgs     []string
	containerID    string
	createErr      error
	waitCreateForContext bool
	startExitCode  int
	startErr       error
	stdout         []byte
	stderr         []byte
	waitForContext bool
	state          DockerContainerState
	inspectErr     error
	removeErr      error
	removeErrors   []error
	removeCalls    int
	created        bool
	removed        bool
	stdin          []byte
}

func (fake *fakeDockerCLI) Preflight(_ context.Context, imageRefs []string) error {
	fake.preflightImages = append([]string(nil), imageRefs...)
	return fake.preflightErr
}

func (fake *fakeDockerCLI) Create(ctx context.Context, args []string) (string, error) {
	fake.created = true
	fake.createArgs = append([]string(nil), args...)
	if fake.waitCreateForContext {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if fake.createErr != nil {
		return "", fake.createErr
	}
	if fake.containerID == "" {
		fake.containerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
	fake.removeCalls++
	fake.removed = true
	if fake.removeCalls <= len(fake.removeErrors) {
		return fake.removeErrors[fake.removeCalls-1]
	}
	return fake.removeErr
}

type closeJournalOnRemoveDockerCLI struct {
	*fakeDockerCLI
	journal *sandboxjournal.Journal
}

func (cli *closeJournalOnRemoveDockerCLI) Remove(_ context.Context, id string) error {
	if id != cli.containerID {
		return ErrDockerCommandFailed
	}
	cli.removed = true
	return cli.journal.Close()
}

func privateJournalTestPath(t *testing.T, name string) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, name)
}

func newJournaledTestSandbox(t *testing.T, cli DockerCLI) (*DockerSandbox, error) {
	t.Helper()
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "sandbox-lifecycle.jsonl"))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close sandbox lifecycle journal: %v", err)
		}
	})
	return NewJournaledDockerSandbox(cli, journal, strings.Repeat("a", 32))
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

func hasLabelPrefix(args []string, prefix string) bool {
	for index, argument := range args {
		if argument == "--label" && index+1 < len(args) && strings.HasPrefix(args[index+1], prefix) {
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

func TestOSCommandDockerCLIPreflightInspectsRunscAndNeverPulls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Docker sandbox targets Linux hosts")
	}
	logPath := filepath.Join(t.TempDir(), "docker-commands.log")
	binaryPath := filepath.Join(t.TempDir(), "docker-stub")
	script := strings.Join([]string{
		"#!/bin/sh",
		"printf '%s\\n' \"$*\" >> \"$DOCKER_TEST_LOG\"",
		"if [ \"$1\" = \"info\" ]; then",
		"  if [ \"$DOCKER_TEST_NO_RUNSC\" = \"1\" ]; then",
		"    printf '%s' '{\"runc\":{\"path\":\"runc\"}}'",
		"  else",
		"    printf '%s' '{\"runsc\":{\"path\":\"runsc\"},\"runc\":{\"path\":\"runc\"}}'",
		"  fi",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"image\" ] && [ \"$2\" = \"inspect\" ]; then",
		"  [ \"$DOCKER_TEST_IMAGE_FAIL\" != \"1\" ] || exit 1",
		"  printf '%s' 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
		"  exit 0",
		"fi",
		"exit 91",
	}, "\n")
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_TEST_LOG", logPath)
	t.Setenv("DOCKER_TEST_NO_RUNSC", "0")
	t.Setenv("DOCKER_TEST_IMAGE_FAIL", "0")

	cli := OSCommandDockerCLI{Binary: binaryPath}
	images := []string{
		"registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		"registry.example/sky-high/python@sha256:" + strings.Repeat("b", 64),
	}
	if err := cli.Preflight(context.Background(), images); err != nil {
		t.Fatalf("preflight with runsc and both local images: %v", err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(log)), "\n")
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "info --format ") ||
		!strings.HasPrefix(calls[1], "image inspect --format ") ||
		!strings.HasPrefix(calls[2], "image inspect --format ") {
		t.Fatalf("preflight invoked unexpected Docker commands: %q", log)
	}
	if strings.Contains(string(log), "pull") {
		t.Fatalf("preflight must never pull images: %q", log)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_TEST_NO_RUNSC", "1")
	if err := cli.Preflight(context.Background(), images); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("missing runsc runtime was accepted: %v", err)
	}
	log, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(log), "\n") != 1 || !strings.HasPrefix(string(log), "info --format ") {
		t.Fatalf("image inspection continued without runsc: %q", log)
	}

	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_TEST_NO_RUNSC", "0")
	t.Setenv("DOCKER_TEST_IMAGE_FAIL", "1")
	if err := cli.Preflight(context.Background(), images); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("missing digest-pinned image was accepted: %v", err)
	}
}

func TestOSCommandDockerCLICreateCancellationCleansPartialContainer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker sandbox targets Linux hosts")
	}
	logPath := filepath.Join(t.TempDir(), "docker-remove.log")
	binaryPath := filepath.Join(t.TempDir(), "docker-stub")
	containerID := strings.Repeat("a", 64)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"create\" ]; then",
		"  printf '%s\\n' '"+containerID+"'",
		"  exec sleep 5",
		"fi",
		"if [ \"$1\" = \"rm\" ]; then",
		"  printf '%s\\n' \"$3\" >> \"$DOCKER_TEST_REMOVE_LOG\"",
		"  exit 0",
		"fi",
		"exit 91",
	}, "\n")
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_TEST_REMOVE_LOG", logPath)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := (OSCommandDockerCLI{Binary: binaryPath}).Create(ctx, []string{"--name", "test"})
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("cancelled create error = %v, want ErrDockerCommandFailed", err)
	}
	removed, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("partial container cleanup was not attempted: %v", readErr)
	}
	if strings.TrimSpace(string(removed)) != containerID {
		t.Fatalf("removed container ID = %q, want %q", strings.TrimSpace(string(removed)), containerID)
	}
}

func TestDockerSandboxPreflightRequiresBothPinnedRuntimeImages(t *testing.T) {
	t.Parallel()
	fake := &fakeDockerCLI{}
	sandbox, err := NewDockerSandbox(fake)
	if err != nil {
		t.Fatal(err)
	}
	runtimes := RuntimeConfiguration{
		JavaImageRef: "registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		PythonImageRef: "registry.example/sky-high/python@sha256:" + strings.Repeat("b", 64),
	}
	if err := sandbox.Preflight(context.Background(), runtimes); err != nil {
		t.Fatal(err)
	}
	if len(fake.preflightImages) != 2 ||
		fake.preflightImages[0] != runtimes.JavaImageRef ||
		fake.preflightImages[1] != runtimes.PythonImageRef {
		t.Fatalf("preflight images = %v, want both exact digest pins", fake.preflightImages)
	}

	fake.preflightErr = ErrDockerCommandFailed
	if err := sandbox.Preflight(context.Background(), runtimes); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("missing runsc/image preflight was not propagated: %v", err)
	}
}

func TestDockerSandboxRejectsNilContextsWithoutCallingDocker(t *testing.T) {
	fake := &fakeDockerCLI{}
	sandbox, err := newJournaledTestSandbox(t, fake)
	if err != nil {
		t.Fatal(err)
	}
	runtimes := RuntimeConfiguration{
		JavaImageRef:   "registry.example/sky-high/java@sha256:" + strings.Repeat("a", 64),
		PythonImageRef: "registry.example/sky-high/python@sha256:" + strings.Repeat("b", 64),
	}
	if err := sandbox.Preflight(nil, runtimes); !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("Preflight with nil context error = %v, want ErrSandboxNotConfigured", err)
	}
	if len(fake.preflightImages) != 0 {
		t.Fatalf("Preflight invoked Docker with nil context: %v", fake.preflightImages)
	}
	if _, err := sandbox.RunCase(nil, dockerSandboxTestRequest()); !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("RunCase with nil context error = %v, want ErrSandboxNotConfigured", err)
	}
	if fake.created {
		t.Fatal("RunCase created a container with nil context")
	}
	cli := OSCommandDockerCLI{}
	if err := cli.Preflight(nil, []string{
		runtimes.JavaImageRef,
		runtimes.PythonImageRef,
	}); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("Docker CLI Preflight with nil context error = %v, want ErrDockerCommandFailed", err)
	}
	validContainerID := strings.Repeat("1", 64)
	if _, err := cli.Create(nil, nil); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("Docker CLI Create with nil context error = %v, want ErrDockerCommandFailed", err)
	}
	if _, err := cli.StartAttached(nil, validContainerID, nil, nil, nil); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("Docker CLI StartAttached with nil context error = %v, want ErrDockerCommandFailed", err)
	}
	if _, err := cli.Inspect(nil, validContainerID); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("Docker CLI Inspect with nil context error = %v, want ErrDockerCommandFailed", err)
	}
	if err := cli.Remove(nil, validContainerID); !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("Docker CLI Remove with nil context error = %v, want ErrDockerCommandFailed", err)
	}
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
	if !strings.Contains(workspaceTmpfs, "noexec,nosuid,nodev") ||
		!strings.Contains(workspaceTmpfs, "uid=65532,gid=65532,mode=0700") {
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
	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "program output\n"),
		stderr: []byte("program warning\n"),
		state:  DockerContainerState{Status: "exited", ExitCode: 0},
	}
	sandbox, err := newJournaledTestSandbox(t, fake)
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
	wantStdin := append(append([]byte(nil), request.SourceBytes...), request.StandardInput...)
	if string(fake.stdin) != string(wantStdin) {
		t.Fatalf("stdin = %q, want source bytes followed by test input %q", fake.stdin, wantStdin)
	}
	if containsArgument(fake.createArgs, "--mount") {
		t.Fatalf("host source path unexpectedly passed to Docker: %v", fake.createArgs)
	}
	if !containsArgument(fake.createArgs, "com.skyhigh.runner-instance="+strings.Repeat("a", 32)) {
		t.Fatalf("container missing runner-instance ownership label: %v", fake.createArgs)
	}
	if !hasLabelPrefix(fake.createArgs, "com.skyhigh.lifecycle-id=") {
		t.Fatalf("container missing lifecycle recovery label: %v", fake.createArgs)
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
			sandbox, err := newJournaledTestSandbox(t, &fake)
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
	sandbox, err := newJournaledTestSandbox(t, fake)
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
	sandbox, err := newJournaledTestSandbox(t, fake)
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
	sandbox, err := newJournaledTestSandbox(t, fake)
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

	javaScript := runtimeScript(protocol.LanguageJava, "25", len(dockerSandboxTestRequest().SourceBytes))
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
	if !strings.Contains(javaScript, "dd bs=1 count=") ||
		!strings.Contains(javaScript, "of=/workspace/Main.java") ||
		!strings.Contains(javaScript, "chmod 0444 /workspace/Main.java") ||
		!strings.Contains(javaScript, "chmod 0555 /workspace") {
		t.Fatalf("Java wrapper does not stage exact source bytes into private tmpfs: %s", javaScript)
	}
	if strings.Index(javaScript, "printf '") > strings.Index(javaScript, "exec java ") {
		t.Fatal("Java compile marker must be emitted before the program starts")
	}

	pythonScript := runtimeScript(protocol.LanguagePython, "3.14", 64)
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
	if !strings.Contains(pythonScript, "dd bs=1 count=64") ||
		!strings.Contains(pythonScript, "of=/workspace/main.py") ||
		!strings.Contains(pythonScript, "chmod 0444 /workspace/main.py") ||
		!strings.Contains(pythonScript, "chmod 0555 /workspace") {
		t.Fatalf("Python wrapper does not stage exact source bytes into private tmpfs: %s", pythonScript)
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
	if _, err := dockerCreateArguments(request); err == nil {
		t.Fatal("flag-like image reference was accepted")
	}
}



func TestDockerSandboxPersistsCreateIntentBeforeDockerCreate(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	fake := &fakeDockerCLI{createErr: errors.New("daemon unavailable")}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want Docker command failure", err)
	}
	if !fake.created {
		t.Fatal("Docker create was not attempted")
	}
	if !containsArgument(fake.createArgs, "com.skyhigh.runner-instance="+strings.Repeat("c", 32)) ||
		!hasLabelPrefix(fake.createArgs, "com.skyhigh.lifecycle-id=") {
		t.Fatalf("Docker create did not receive ownership and lifecycle labels: %v", fake.createArgs)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned {
		t.Fatalf("failed create intent should remain visible for reconciliation: %+v", pending)
	}
}

func TestDockerSandboxCancellationDuringCreatePreservesUnresolvedIntent(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "cancelled-create.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	fake := &fakeDockerCLI{waitCreateForContext: true}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = sandbox.RunCase(ctx, dockerSandboxTestRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled create error = %v, want context.DeadlineExceeded", err)
	}
	if !fake.created {
		t.Fatal("Docker create was not attempted")
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != "" {
		t.Fatalf("cancelled create must preserve unresolved intent for reconciliation: %+v", pending)
	}
}

func TestDockerSandboxRecordsCleanupOnlyAfterDockerConfirmsRemoval(t *testing.T) {
	path := privateJournalTestPath(t, "lifecycle.jsonl")
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "ok"),
		state: DockerContainerState{Status: "exited", ExitCode: 0},
	}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if err != nil {
		t.Fatalf("RunCase: %v", err)
	}
	if !observation.CleanupSucceeded || !fake.removed {
		t.Fatalf("cleanup was not confirmed: %+v", observation)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("confirmed cleanup remained pending: %+v", pending)
	}
}

func TestDockerSandboxDeferredCleanupRetryRecordsConfirmedRemoval(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "deferred-cleanup-retry.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "ok"),
		state: DockerContainerState{Status: "exited", ExitCode: 0},
		removeErrors: []error{
			errors.New("transient daemon failure on primary removal"),
			nil,
		},
	}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("e", 32))
	if err != nil {
		t.Fatal(err)
	}

	observation, runErr := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(runErr, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want conservative Docker failure after primary removal error", runErr)
	}
	if observation.CleanupSucceeded {
		t.Fatal("primary removal failure must not be rewritten as a successful execution observation")
	}
	if fake.removeCalls != 2 {
		t.Fatalf("removal attempts = %d, want primary attempt plus one deferred retry", fake.removeCalls)
	}

	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("successful deferred removal must be durably recorded as CLEANED: %+v", pending)
	}
}

func TestDockerSandboxLeavesCreatedLifecyclePendingWhenRemovalFails(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "ok"),
		state: DockerContainerState{Status: "exited", ExitCode: 0},
		removeErr: errors.New("daemon unavailable during remove"),
	}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("e", 32))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want Docker command failure", err)
	}
	if observation.CleanupSucceeded {
		t.Fatal("failed removal was reported as successful")
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != fake.containerID {
		t.Fatalf("failed cleanup must retain full container identity: %+v", pending)
	}
}

func TestDockerSandboxRequiresDurableLifecycleJournal(t *testing.T) {
	fake := &fakeDockerCLI{}
	sandbox, err := NewDockerSandbox(fake)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("unjournaled sandbox RunCase error = %v, want ErrSandboxNotConfigured", err)
	}
	if fake.created {
		t.Fatal("unjournaled sandbox created a container")
	}
}

func TestDockerSandboxRunCaseRejectsNilSandbox(t *testing.T) {
	t.Parallel()

	var sandbox *DockerSandbox
	_, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("RunCase error = %v, want ErrSandboxNotConfigured", err)
	}
}

func TestDockerSandboxRunCaseRejectsMissingCLI(t *testing.T) {
	t.Parallel()

	sandbox := &DockerSandbox{}
	_, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrSandboxNotConfigured) {
		t.Fatalf("RunCase error = %v, want ErrSandboxNotConfigured", err)
	}
}


func TestDockerSandboxStartFailureStillConfirmsAndJournalsCleanup(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "start-failure.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	fake := &fakeDockerCLI{
		startErr: errors.New("docker start stream failed"),
	}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("f", 32))
	if err != nil {
		t.Fatal(err)
	}

	observation, err := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want Docker command failure", err)
	}
	if !fake.created || !fake.removed || !observation.CleanupSucceeded {
		t.Fatalf("start failure cleanup was not confirmed: created=%v removed=%v observation=%+v",
			fake.created, fake.removed, observation)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("confirmed removal after start failure must be journaled as clean: %+v", pending)
	}
}

func TestDockerSandboxInspectFailureDoesNotInventPendingContainerAfterConfirmedRemoval(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "inspect-failure.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	fake := &fakeDockerCLI{
		stdout:     []byte(compileSuccessMarker + "output"),
		inspectErr: errors.New("docker inspect unavailable"),
	}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}

	_, err = sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want Docker command failure", err)
	}
	if !fake.removed {
		t.Fatal("container removal was not attempted after inspect failure")
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("confirmed container removal should leave no pending lifecycle: %+v", pending)
	}
}


func TestDockerSandboxPreservesCreateIntentWhenCreatedRecordRejectsContainerID(t *testing.T) {
	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "invalid-created-id.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	// The Docker CLI boundary accepts abbreviated IDs for ordinary commands,
	// but the durable lifecycle journal requires the full 64-character ID.
	// This forces the post-create journal transition to fail without adding a
	// production-only fault-injection hook.
	fake := &fakeDockerCLI{containerID: strings.Repeat("a", 12)}
	sandbox, err := NewJournaledDockerSandbox(fake, journal, strings.Repeat("2", 32))
	if err != nil {
		t.Fatal(err)
	}

	_, err = sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if err == nil {
		t.Fatal("journal accepted a non-full container ID")
	}
	if !fake.created || !fake.removed {
		t.Fatalf("post-create failure did not attempt exact-ID cleanup: created=%v removed=%v",
			fake.created, fake.removed)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != "" {
		t.Fatalf("failed CREATED transition must preserve unresolved CREATE_INTENT: %+v", pending)
	}
}


func TestOSCommandDockerCLICreateCleansPartialContainerWhenDaemonReturnsFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker sandbox targets Linux hosts")
	}
	directory := t.TempDir()
	logPath := filepath.Join(directory, "docker-remove.log")
	binaryPath := filepath.Join(directory, "docker-stub")
	containerID := strings.Repeat("b", 64)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"create\" ]; then",
		"  printf '%s\\n' '" + containerID + "'",
		"  printf '%s\\n' 'daemon disconnected after create' >&2",
		"  exit 1",
		"fi",
		"if [ \"$1\" = \"rm\" ]; then",
		"  printf '%s\\n' \"$3\" >> \"$DOCKER_TEST_REMOVE_LOG\"",
		"  exit 0",
		"fi",
		"exit 91",
	}, "\n")
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_TEST_REMOVE_LOG", logPath)

	id, err := (OSCommandDockerCLI{Binary: binaryPath}).Create(
		context.Background(), []string{"--name", "test"},
	)
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("failed create error = %v, want ErrDockerCommandFailed", err)
	}
	if id != "" {
		t.Fatalf("failed create returned container ID %q; unresolved create must remain with caller", id)
	}
	removed, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("cleanup of partial container was not attempted: %v", readErr)
	}
	if strings.TrimSpace(string(removed)) != containerID {
		t.Fatalf("removed container ID = %q, want exact partial ID %q",
			strings.TrimSpace(string(removed)), containerID)
	}
}


func TestDockerSandboxFailedCreateWithUnconfirmedCleanupRemainsDiscoverable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker sandbox targets Linux hosts")
	}
	runnerID := strings.Repeat("c", 32)
	containerID := strings.Repeat("d", 64)
	dockerPath := filepath.Join(t.TempDir(), "docker-stub")
	script := strings.Join([]string{
		"#!/bin/sh",
		"case \"$1\" in",
		"  create)",
		"    for arg in \"$@\"; do case \"$arg\" in " + lifecycleIDLabel + "=*) printf '%s\\n' \"${arg#*=}\" > \"$DOCKER_TEST_LIFECYCLE_ID\" ;; esac; done",
		"    printf '%s\\n' '" + containerID + "'",
		"    printf '%s\\n' 'daemon disconnected after container creation' >&2",
		"    exit 1",
		"    ;;",
		"  rm)",
		"    printf '%s\\n' 'daemon unavailable during cleanup' >&2",
		"    exit 1",
		"    ;;",
		"  ps)",
		"    printf '%s\\n' '" + containerID + "'",
		"    exit 0",
		"    ;;",
		"  inspect)",
		"    lifecycle_id=$(cat \"$DOCKER_TEST_LIFECYCLE_ID\")",
		"    printf '{\"Id\":\"%s\",\"Config\":{\"Labels\":{\"%s\":\"%s\",\"%s\":\"%s\"}},\"State\":{\"Status\":\"created\"}}\\n' '" + containerID + "' '" + runnerInstanceLabel + "' '" + runnerID + "' '" + lifecycleIDLabel + "' \"$lifecycle_id\"",
		"    exit 0",
		"    ;;",
		"esac",
		"exit 90",
	}, "\n")
	if err := os.WriteFile(dockerPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	journal, err := sandboxjournal.Open(privateJournalTestPath(t, "failed-create-recovery.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	lifecycleIDPath := filepath.Join(t.TempDir(), "lifecycle-id")
	t.Setenv("DOCKER_TEST_LIFECYCLE_ID", lifecycleIDPath)
	cli := OSCommandDockerCLI{Binary: dockerPath}
	sandbox, err := NewJournaledDockerSandbox(cli, journal, runnerID)
	if err != nil {
		t.Fatal(err)
	}

	_, runErr := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(runErr, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want Docker command failure", runErr)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != "" {
		t.Fatalf("failed create with unconfirmed cleanup must preserve CREATE_INTENT: %+v", pending)
	}

	findings, err := DiscoverPendingDockerLifecycles(context.Background(), journal, cli, runnerID)
	if err != nil {
		t.Fatalf("discover container after failed create cleanup: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Assessment != "CREATE_INTENT_MATCH — crash-window candidate; operator review required" ||
		len(findings[0].Containers) != 1 ||
		findings[0].Containers[0].ID != containerID {
		t.Fatalf("failed-create recovery finding = %+v", findings)
	}
	pending, err = journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != "" {
		t.Fatalf("read-only recovery must preserve unresolved CREATE_INTENT: %+v", pending)
	}
}


func TestDockerSandboxRemovalSuccessWithCleanedAppendFailureRemainsPending(t *testing.T) {
	journalPath := privateJournalTestPath(t, "cleaned-append-failure.jsonl")
	journal, err := sandboxjournal.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeDockerCLI{
		stdout: []byte(compileSuccessMarker + "ok"),
		state: DockerContainerState{Status: "exited", ExitCode: 0},
	}
	cli := &closeJournalOnRemoveDockerCLI{fakeDockerCLI: fake, journal: journal}
	sandbox, err := NewJournaledDockerSandbox(cli, journal, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}

	observation, runErr := sandbox.RunCase(context.Background(), dockerSandboxTestRequest())
	if !errors.Is(runErr, ErrDockerCommandFailed) {
		t.Fatalf("RunCase error = %v, want cleanup-journal persistence failure", runErr)
	}
	if !fake.removed {
		t.Fatal("Docker removal was not confirmed")
	}
	if observation.CleanupSucceeded {
		t.Fatal("cleanup was reported successful without durable CLEANED confirmation")
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close already-closed journal: %v", err)
	}

	reopened, err := sandboxjournal.Open(journalPath)
	if err != nil {
		t.Fatalf("reopen journal after CLEANED append failure: %v", err)
	}
	defer reopened.Close()
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != fake.containerID {
		t.Fatalf("failed CLEANED append must preserve CREATED lifecycle identity: %+v", pending)
	}

	findings, err := DiscoverPendingDockerLifecycles(
		context.Background(), reopened,
		&fakeLifecycleDiscoverer{}, strings.Repeat("a", 32),
	)
	if err != nil {
		t.Fatalf("inspect pending lifecycle after failed CLEANED append: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Assessment != "JOURNALED_CONTAINER_NOT_FOUND — operator review required" {
		t.Fatalf("post-removal recovery assessment = %+v", findings)
	}
	pending, err = reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != fake.containerID {
		t.Fatalf("read-only recovery must not infer CLEANED from missing inventory: %+v", pending)
	}
}
