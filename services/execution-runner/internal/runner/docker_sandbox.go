package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

var (
	ErrDockerCommandFailed = errors.New("docker sandbox command failed")
	containerIDPattern     = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
)

const compileSuccessMarker = "__SKYHIGH_COMPILE_OK__\n"

type DockerContainerState struct {
	Status    string `json:"Status"`
	ExitCode  int    `json:"ExitCode"`
	OOMKilled bool   `json:"OOMKilled"`
}

// DockerCLI isolates the Docker command boundary so policy and lifecycle
// behavior can be tested without running untrusted code on the host.
type DockerCLI interface {
	Create(context.Context, []string) (string, error)
	StartAttached(context.Context, string, io.Reader, io.Writer, io.Writer) (int, error)
	Inspect(context.Context, string) (DockerContainerState, error)
	Remove(context.Context, string) error
}

type OSCommandDockerCLI struct {
	Binary string
}

func (cli OSCommandDockerCLI) binary() string {
	if cli.Binary != "" {
		return cli.Binary
	}
	return "docker"
}

func (cli OSCommandDockerCLI) Create(ctx context.Context, args []string) (string, error) {
	command := exec.CommandContext(ctx, cli.binary(), append([]string{"create"}, args...)...)
	output, commandErr := command.Output()
	id := strings.TrimSpace(string(output))
	if !containerIDPattern.MatchString(id) {
		return "", ErrDockerCommandFailed
	}
	if commandErr != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = cli.Remove(cleanupContext, id)
		cancel()
		return "", ErrDockerCommandFailed
	}
	return id, nil
}

func (cli OSCommandDockerCLI) StartAttached(
	ctx context.Context,
	id string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	if !containerIDPattern.MatchString(id) {
		return 0, ErrDockerCommandFailed
	}
	command := exec.CommandContext(ctx, cli.binary(), "start", "--attach", "--interactive", id)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if err == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && ctx.Err() == nil {
		return exitError.ExitCode(), nil
	}
	return 0, ErrDockerCommandFailed
}

func (cli OSCommandDockerCLI) Inspect(ctx context.Context, id string) (DockerContainerState, error) {
	if !containerIDPattern.MatchString(id) {
		return DockerContainerState{}, ErrDockerCommandFailed
	}
	command := exec.CommandContext(
		ctx,
		cli.binary(),
		"inspect",
		"--format",
		"{{json .State}}",
		id,
	)
	output, err := command.Output()
	if err != nil {
		return DockerContainerState{}, ErrDockerCommandFailed
	}
	var state DockerContainerState
	if err := json.Unmarshal(output, &state); err != nil {
		return DockerContainerState{}, ErrDockerCommandFailed
	}
	return state, nil
}

func (cli OSCommandDockerCLI) Remove(ctx context.Context, id string) error {
	if !containerIDPattern.MatchString(id) {
		return ErrDockerCommandFailed
	}
	command := exec.CommandContext(ctx, cli.binary(), "rm", "--force", id)
	if err := command.Run(); err != nil {
		return ErrDockerCommandFailed
	}
	return nil
}

type DockerSandbox struct {
	cli            DockerCLI
	temporaryRoot  string
	cleanupTimeout time.Duration
}

func NewDockerSandbox(cli DockerCLI, temporaryRoot string) (*DockerSandbox, error) {
	if cli == nil {
		return nil, ErrSandboxNotConfigured
	}
	if temporaryRoot == "" {
		temporaryRoot = os.TempDir()
	}
	info, err := os.Stat(temporaryRoot)
	if err != nil || !info.IsDir() {
		return nil, ErrSandboxNotConfigured
	}
	return &DockerSandbox{
		cli:            cli,
		temporaryRoot:  temporaryRoot,
		cleanupTimeout: 5 * time.Second,
	}, nil
}

func (sandbox *DockerSandbox) RunCase(
	parent context.Context,
	request SandboxRequest,
) (SandboxObservation, error) {
	if err := validateSandboxRequest(request); err != nil {
		return SandboxObservation{}, err
	}

	workspace, err := os.MkdirTemp(sandbox.temporaryRoot, "sky-high-exec-")
	if err != nil {
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	cleanupWorkspace := true
	defer func() {
		if cleanupWorkspace {
			_ = os.RemoveAll(workspace)
		}
	}()
	if err := os.Chmod(workspace, 0711); err != nil {
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	sourcePath := filepath.Join(workspace, request.SourceName)
	file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	if _, err := file.Write(request.SourceBytes); err != nil {
		_ = file.Close()
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	if err := file.Close(); err != nil {
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	if err := os.Chmod(sourcePath, 0444); err != nil {
		return SandboxObservation{}, ErrDockerCommandFailed
	}

	wallClock := time.Duration(request.Limits.WallTimeMillis) * time.Millisecond
	runContext, cancel := context.WithTimeout(parent, wallClock)
	defer cancel()
	output := newBoundedOutput(request.Limits.OutputBytes, cancel)

	args, err := dockerCreateArguments(request, workspace)
	if err != nil {
		return SandboxObservation{}, err
	}
	containerID, err := sandbox.cli.Create(runContext, args)
	if err != nil {
		if parent.Err() != nil {
			return SandboxObservation{}, parent.Err()
		}
		if runContext.Err() != nil {
			return SandboxObservation{}, runContext.Err()
		}
		return SandboxObservation{}, ErrDockerCommandFailed
	}
	if !containerIDPattern.MatchString(containerID) {
		return SandboxObservation{}, ErrDockerCommandFailed
	}

	startedAt := time.Now()
	exitCode, startErr := sandbox.cli.StartAttached(
		runContext,
		containerID,
		bytes.NewReader(request.StandardInput),
		output.StdoutWriter(),
		output.StderrWriter(),
	)
	elapsed := time.Since(startedAt)

	// Inspect before removal only when the command completed normally. For
	// cancellation/timeout, removal itself is the kill operation.
	state := DockerContainerState{}
	var inspectErr error
	if startErr == nil && runContext.Err() == nil {
		inspectContext, inspectCancel := context.WithTimeout(context.Background(), sandbox.cleanupTimeout)
		state, inspectErr = sandbox.cli.Inspect(inspectContext, containerID)
		inspectCancel()
	}

	cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), sandbox.cleanupTimeout)
	removeErr := sandbox.cli.Remove(cleanupContext, containerID)
	cleanupCancel()
	removeWorkspaceErr := os.RemoveAll(workspace)
	if removeWorkspaceErr == nil {
		cleanupWorkspace = false
	}

	cleanupSucceeded := removeErr == nil && removeWorkspaceErr == nil
	standardOutput := output.StdoutBytes()
	compiled, standardOutput := removeCompileSuccessMarker(standardOutput)
	observation := SandboxObservation{
		StandardOutput:    standardOutput,
		StandardError:     output.StderrBytes(),
		CompilationStatus: CompilationNotStarted,
		ElapsedMillis:     elapsed.Milliseconds(),
		CleanupSucceeded:  cleanupSucceeded,
	}
	if compiled {
		observation.CompilationStatus = CompilationSucceeded
	}
	if parent.Err() != nil {
		return observation, parent.Err()
	}
	if !cleanupSucceeded {
		return observation, ErrDockerCommandFailed
	}
	if output.Exceeded() {
		observation.Status = SandboxOutputLimit
		return observation, nil
	}
	if errors.Is(runContext.Err(), context.DeadlineExceeded) {
		observation.Status = SandboxTimeLimit
		return observation, nil
	}
	if runContext.Err() != nil {
		return observation, runContext.Err()
	}
	if startErr != nil || inspectErr != nil || state.Status != "exited" || state.ExitCode != exitCode {
		return observation, ErrDockerCommandFailed
	}
	if state.OOMKilled {
		observation.Status = SandboxMemoryLimit
		return observation, nil
	}

	switch {
	case exitCode == 86 && !compiled:
		observation.Status = SandboxCompileError
		observation.CompilationStatus = CompilationFailed
	case exitCode == 87 && !compiled:
		return observation, ErrDockerCommandFailed
	case exitCode == 0:
		if !compiled {
			return observation, ErrDockerCommandFailed
		}
		observation.Status = SandboxSucceeded
	default:
		if !compiled {
			return observation, ErrDockerCommandFailed
		}
		observation.Status = SandboxRuntimeError
	}
	return observation, nil
}

func validateSandboxRequest(request SandboxRequest) error {
	if !containerSafeID(request.ExecutionID) ||
		(request.Language != protocol.LanguageJava && request.Language != protocol.LanguagePython) ||
		!imageReferencePattern.MatchString(request.ImageRef) {
		return protocol.ErrInvalidRequest
	}
	expectedName := sourceFileName(request.Language)
	if request.SourceName != expectedName || !runtimeVersionPattern.MatchString(request.RuntimeVersion) ||
		len(request.SourceBytes) == 0 || len(request.SourceBytes) > maximumSourceBytes {
		return protocol.ErrInvalidRequest
	}
	return validateExecutionLimits(request.Limits)
}

func containerSafeID(value string) bool {
	return artifactCaseIDPattern.MatchString(value)
}

func dockerCreateArguments(request SandboxRequest, workspace string) ([]string, error) {
	if !imageReferencePattern.MatchString(request.ImageRef) ||
		strings.ContainsAny(workspace, ",\r\n") {
		return nil, ErrInvalidRuntimeConfig
	}
	cpuValue := strconv.FormatFloat(float64(request.Limits.CPUQuotaMillis)/1000, 'f', 3, 64)
	memoryValue := strconv.FormatInt(request.Limits.MemoryBytes, 10)
	processValue := strconv.FormatInt(request.Limits.ProcessLimit, 10)
	tmpfsSize := "64m"
	if request.Limits.MemoryBytes < 128*1024*1024 {
		tmpfsSize = "16m"
	}

	script := runtimeScript(request.Language, request.RuntimeVersion)
	args := []string{
		"--runtime=runsc",
		"--network=none",
		"--ipc=none",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + tmpfsSize,
		"--memory=" + memoryValue,
		"--memory-swap=" + memoryValue,
		"--cpus=" + cpuValue,
		"--pids-limit=" + processValue,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user=65532:65532",
		"--ulimit", "core=0:0",
		"--interactive",
		"--env=HOME=/tmp",
		"--mount", "type=bind,src=" + workspace + ",dst=/workspace,readonly",
		"--workdir=/workspace",
		"--label", "com.skyhigh.execution-id=" + request.ExecutionID,
		"--entrypoint=/bin/sh",
		request.ImageRef,
		"-c",
		script,
	}
	return args, nil
}

func removeCompileSuccessMarker(output []byte) (bool, []byte) {
	marker := []byte(compileSuccessMarker)
	if !bytes.HasPrefix(output, marker) {
		return false, output
	}
	return true, append([]byte(nil), output[len(marker):]...)
}

func runtimeScript(language protocol.Language, runtimeVersion string) string {
	// RuntimeVersion is validated against runtimeVersionPattern before this
	// value enters the fixed shell program; student source is never interpolated.
	switch language {
	case protocol.LanguageJava:
		return strings.Join([]string{
			"set -eu",
			"command -v javac >/dev/null 2>&1 || exit 87",
			"command -v java >/dev/null 2>&1 || exit 87",
			"java_version=\"$(java -version 2>&1)\" || exit 87",
			"case \"$java_version\" in *'version \"" + runtimeVersion + "'*) ;; *) exit 87 ;; esac",
			"mkdir -p /tmp/classes || exit 87",
			"if javac -J-XX:MaxRAMPercentage=50 -proc:none -d /tmp/classes /workspace/Main.java; then",
			"printf '" + compileSuccessMarker + "'",
			"  exec java -XX:MaxRAMPercentage=75 -Djava.io.tmpdir=/tmp -cp /tmp/classes Main",
			"else",
			"  exit 86",
			"fi",
		}, "\n")
	case protocol.LanguagePython:
		return strings.Join([]string{
			"set -eu",
			"command -v python3 >/dev/null 2>&1 || exit 87",
			"python_version=\"$(python3 --version 2>&1)\" || exit 87",
			"case \"$python_version\" in 'Python " + runtimeVersion + "'*) ;; *) exit 87 ;; esac",
			"python3 -I -B -c 'import pathlib; compile(pathlib.Path(\"/workspace/main.py\").read_bytes(), \"/workspace/main.py\", \"exec\")' || exit 86",
			"printf '" + compileSuccessMarker + "'",
			"exec python3 -I -B /workspace/main.py",
		}, "\n")
	default:
		return "exit 87"
	}
}

type boundedOutput struct {
	mu       sync.Mutex
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	total    int64
	maximum  int64
	exceeded bool
	cancel   context.CancelFunc
}

type boundedStream struct {
	parent   *boundedOutput
	isStderr bool
}

func newBoundedOutput(maximum int64, cancel context.CancelFunc) *boundedOutput {
	return &boundedOutput{maximum: maximum, cancel: cancel}
}

func (writer *boundedOutput) StdoutWriter() io.Writer {
	return boundedStream{parent: writer}
}

func (writer *boundedOutput) StderrWriter() io.Writer {
	return boundedStream{parent: writer, isStderr: true}
}

func (stream boundedStream) Write(value []byte) (int, error) {
	writer := stream.parent
	writer.mu.Lock()
	defer writer.mu.Unlock()
	originalLength := len(value)
	remaining := writer.maximum - writer.total
	if remaining > 0 {
		toWrite := value
		if int64(len(toWrite)) > remaining {
			toWrite = toWrite[:remaining]
		}
		if stream.isStderr {
			_, _ = writer.stderr.Write(toWrite)
		} else {
			_, _ = writer.stdout.Write(toWrite)
		}
		writer.total += int64(len(toWrite))
	}
	if int64(originalLength) > remaining && !writer.exceeded {
		writer.exceeded = true
		writer.cancel()
	}
	return originalLength, nil
}

func (writer *boundedOutput) StdoutBytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.stdout.Bytes()...)
}

func (writer *boundedOutput) StderrBytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.stderr.Bytes()...)
}

func (writer *boundedOutput) Exceeded() bool {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.exceeded
}
