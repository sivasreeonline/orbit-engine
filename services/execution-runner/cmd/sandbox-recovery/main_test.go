package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/hostlock"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runner"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

type fakeDiscoverer struct {
	containers []runner.DiscoveredDockerContainer
	err error
	calls int
}

func (fake *fakeDiscoverer) DiscoverByRunnerLabel(_ context.Context, _ string) ([]runner.DiscoveredDockerContainer, error) {
	fake.calls++
	return append([]runner.DiscoveredDockerContainer(nil), fake.containers...), fake.err
}

func recoveryEnvironment(path string) environment {
	values := map[string]string{
		"RUNNER_INSTANCE_ID": strings.Repeat("a", 32),
		"RUNNER_SANDBOX_JOURNAL_PATH": path,
		"RUNNER_HOST_LOCK_PATH": path + ".host.lock",
	}
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func createPendingJournal(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sandbox-lifecycle.jsonl")
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	lifecycleID, err := journal.Begin(runnerID, "exec_recovery_cli")
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("b", 64)
	if err := journal.Created(lifecycleID, containerID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return path, lifecycleID, containerID
}

func TestRecoveryCommandRejectsNilContextWithoutPanicking(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer

	err := run(nil, recoveryEnvironment(path), discoverer, &output)
	if err == nil || !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("nil context error = %v, want explicit context-required error", err)
	}
	if discoverer.calls != 0 {
		t.Fatalf("discovery calls = %d, want 0 for nil context", discoverer.calls)
	}
	if output.Len() != 0 {
		t.Fatalf("nil-context recovery emitted a report: %s", output.String())
	}
}

func TestRecoveryCommandProducesDryRunReportWithoutMutatingJournal(t *testing.T) {
	path, lifecycleID, containerID := createPendingJournal(t)
	runnerID := strings.Repeat("a", 32)
	discoverer := &fakeDiscoverer{containers: []runner.DiscoveredDockerContainer{{
		ID: containerID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "exited",
	}}}
	var output bytes.Buffer

	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &output); err != nil {
		t.Fatal(err)
	}
	var report recoveryReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v; output=%s", err, output.String())
	}
	if report.Mode != "DRY_RUN" || report.DeletionPerformed || report.PendingCount != 1 ||
		len(report.Findings) != 1 || report.Findings[0].LifecycleID != lifecycleID ||
		report.Findings[0].ContainerID != containerID {
		t.Fatalf("unexpected recovery report: %+v", report)
	}
	if discoverer.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoverer.calls)
	}

	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Cleaned {
		t.Fatalf("dry-run command mutated lifecycle journal: %+v", pending)
	}
}

func TestRecoveryCommandRefusesActiveJournalOwnerBeforeDockerDiscovery(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer
	err = run(context.Background(), recoveryEnvironment(path), discoverer, &output)
	if err == nil {
		t.Fatal("recovery command accepted an actively owned journal")
	}
	if discoverer.calls != 0 {
		t.Fatalf("Docker discovery ran while journal owner was active: %d calls", discoverer.calls)
	}
}

func TestRecoveryCommandRejectsMissingSymlinkAndInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.jsonl")
	if err := run(context.Background(), recoveryEnvironment(missing), &fakeDiscoverer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing journal was accepted")
	}

	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err == nil {
		if err := run(context.Background(), recoveryEnvironment(link), &fakeDiscoverer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("symlink journal was accepted")
		}
	}

	invalidEnv := func(string) (string, bool) { return "", false }
	if err := run(context.Background(), invalidEnv, &fakeDiscoverer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing recovery identity was accepted")
	}
}

func TestRecoveryCommandDoesNotRepairIncompleteJournalTail(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"incomplete":`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer
	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &output); err == nil {
		t.Fatal("read-only recovery accepted an incomplete journal tail")
	}
	if discoverer.calls != 0 {
		t.Fatal("Docker discovery ran against an invalid journal")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only recovery modified the incomplete journal")
	}
}

func TestRecoveryCommandRefusesActiveHostOwnerBeforeJournalOrDockerInspection(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	hostPath := path + ".host.lock"
	owner, err := hostlock.Acquire(hostPath, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()

	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer
	err = run(context.Background(), recoveryEnvironment(path), discoverer, &output)
	if err == nil {
		t.Fatal("recovery command accepted an active host owner")
	}
	if discoverer.calls != 0 {
		t.Fatal("Docker discovery ran while another host owner held the lock")
	}
}


func TestRecoveryCommandReportsCreateIntentCrashWindowWithoutCleanup(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sandbox-lifecycle.jsonl")
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	lifecycleID, err := journal.Begin(runnerID, "exec_create_crash_window")
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	containerID := strings.Repeat("b", 64)
	discoverer := &fakeDiscoverer{containers: []runner.DiscoveredDockerContainer{{
		ID: containerID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "created",
	}}}
	var output bytes.Buffer
	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &output); err != nil {
		t.Fatal(err)
	}
	var report recoveryReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.PendingCount != 1 || len(report.Findings) != 1 ||
		report.Findings[0].Assessment != "CREATE_INTENT_MATCH — crash-window candidate; operator review required" ||
		report.Findings[0].ContainerID != "" || report.DeletionPerformed {
		t.Fatalf("create-intent crash window was not conservatively reported: %+v", report)
	}

	// Reopening proves the recovery command left the original intent untouched.
	reopened, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID || pending[0].ContainerID != "" {
		t.Fatalf("recovery changed create-intent journal state: %+v", pending)
	}
}

func TestRecoveryCommandReportsMissingCreateIntentWithoutResolvingIt(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sandbox-lifecycle.jsonl")
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	lifecycleID, err := journal.Begin(runnerID, "exec_create_without_container")
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer
	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &output); err != nil {
		t.Fatal(err)
	}
	var report recoveryReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode recovery report: %v; output=%s", err, output.String())
	}
	if report.Mode != "DRY_RUN" || report.DeletionPerformed ||
		report.PendingCount != 1 || len(report.Findings) != 1 ||
		report.Findings[0].LifecycleID != lifecycleID ||
		report.Findings[0].Assessment != "CREATE_INTENT_NO_CONTAINER_MATCH — operator review required" {
		t.Fatalf("missing create-intent report is not conservative: %+v", report)
	}
	if discoverer.calls != 1 {
		t.Fatalf("Docker inventory calls = %d, want 1", discoverer.calls)
	}

	reopened, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		pending[0].Created || pending[0].Cleaned || pending[0].ContainerID != "" {
		t.Fatalf("recovery command resolved or mutated the intent: %+v", pending)
	}
}

func TestRecoveryCommandDaemonFailureProducesNoCleanReportAndLeavesJournalUsable(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	discoverer := &fakeDiscoverer{err: errors.New("docker daemon unavailable")}
	var output bytes.Buffer
	err := run(context.Background(), recoveryEnvironment(path), discoverer, &output)
	if err == nil {
		t.Fatal("daemon failure was reported as successful recovery inspection")
	}
	if output.Len() != 0 {
		t.Fatalf("daemon failure emitted a potentially misleading report: %s", output.String())
	}
	if discoverer.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoverer.calls)
	}

	// Both ownership locks must have been released despite the failed inspection.
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatalf("journal remained locked after daemon failure: %v", err)
	}
	defer journal.Close()
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("daemon failure changed pending journal state: %+v", pending)
	}
}


type failingRecoveryWriter struct {
	written int
}

func (writer *failingRecoveryWriter) Write(value []byte) (int, error) {
	if writer.written > 0 {
		return 0, errors.New("injected output failure")
	}
	writer.written++
	return len(value) / 2, errors.New("injected output failure")
}

func TestRecoveryCommandPropagatesReportWriterFailure(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	discoverer := &fakeDiscoverer{containers: []runner.DiscoveredDockerContainer{}}
	writer := &failingRecoveryWriter{}

	err := run(context.Background(), recoveryEnvironment(path), discoverer, writer)
	if err == nil {
		t.Fatal("recovery command ignored report writer failure")
	}
	if !strings.Contains(err.Error(), "write recovery inspection report") {
		t.Fatalf("writer failure was not identified: %v", err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoverer.calls)
	}

	// A failed report write must still release both ownership locks.
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatalf("journal remained locked after report write failure: %v", err)
	}
	defer journal.Close()
}

func TestRecoveryCommandReportIsStableForEquivalentFindings(t *testing.T) {
	path, lifecycleID, containerID := createPendingJournal(t)
	runnerID := strings.Repeat("a", 32)
	discoverer := &fakeDiscoverer{containers: []runner.DiscoveredDockerContainer{{
		ID: containerID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "exited",
	}}}

	var first bytes.Buffer
	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &first); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := run(context.Background(), recoveryEnvironment(path), discoverer, &second); err != nil {
		t.Fatal(err)
	}

	var firstReport, secondReport recoveryReport
	if err := json.Unmarshal(first.Bytes(), &firstReport); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Bytes(), &secondReport); err != nil {
		t.Fatal(err)
	}
	// checkedAt intentionally changes between invocations; the evidence
	// findings and their serialized order must remain identical.
	firstReport.CheckedAt = firstReport.CheckedAt.UTC()
	secondReport.CheckedAt = secondReport.CheckedAt.UTC()
	firstFindings, err := json.Marshal(firstReport.Findings)
	if err != nil {
		t.Fatal(err)
	}
	secondFindings, err := json.Marshal(secondReport.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstFindings, secondFindings) {
		t.Fatalf("equivalent recovery findings changed: first=%s second=%s", firstFindings, secondFindings)
	}
}


type contextBlockingDiscoverer struct {
	calls int
}

func (discoverer *contextBlockingDiscoverer) DiscoverByRunnerLabel(ctx context.Context, _ string) ([]runner.DiscoveredDockerContainer, error) {
	discoverer.calls++
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRecoveryCommandDeadlineDuringDockerDiscoveryEmitsNoReport(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	discoverer := &contextBlockingDiscoverer{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var output bytes.Buffer

	err := run(ctx, recoveryEnvironment(path), discoverer, &output)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v, want context.DeadlineExceeded", err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoverer.calls)
	}
	if output.Len() != 0 {
		t.Fatalf("deadline during discovery emitted a partial report: %s", output.String())
	}

	// Cancellation must release both ownership locks for a later operator run.
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatalf("journal remained locked after deadline: %v", err)
	}
	defer journal.Close()
}


type deadlineIgnoringDiscoverer struct {
	calls   int
	started chan struct{}
	release chan struct{}
}

func (discoverer *deadlineIgnoringDiscoverer) DiscoverByRunnerLabel(_ context.Context, _ string) ([]runner.DiscoveredDockerContainer, error) {
	discoverer.calls++
	close(discoverer.started)
	<-discoverer.release // Deliberately ignore context cancellation.
	return []runner.DiscoveredDockerContainer{}, nil
}

func TestRecoveryCommandRejectsLateSuccessAfterDeadline(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	discoverer := &deadlineIgnoringDiscoverer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var output bytes.Buffer
	result := make(chan error, 1)
	go func() {
		result <- run(ctx, recoveryEnvironment(path), discoverer, &output)
	}()

	// Wait until discovery has definitely started before allowing the parent
	// deadline to expire. This avoids a scheduler-dependent short-timeout race.
	<-discoverer.started
	<-ctx.Done()
	close(discoverer.release)
	err := <-result
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late discovery success error = %v, want context.DeadlineExceeded", err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("discovery calls = %d, want 1", discoverer.calls)
	}
	if output.Len() != 0 {
		t.Fatalf("late success after deadline emitted a report: %s", output.String())
	}

	// A discoverer that ignores cancellation must not leave either ownership
	// lock held when the command rejects its late result.
	journal, err := sandboxjournal.Open(path)
	if err != nil {
		t.Fatalf("journal remained locked after late discovery result: %v", err)
	}
	defer journal.Close()
}


func TestRecoveryCommandDeadlineDuringConfigurationDoesNotAcquireHostLock(t *testing.T) {
	path, _, _ := createPendingJournal(t)
	values := recoveryEnvironment(path)
	hostLockPath := path + ".host.lock"
	lookup := func(name string) (string, bool) {
		if name == "RUNNER_HOST_LOCK_PATH" {
			time.Sleep(40 * time.Millisecond)
		}
		return values(name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	discoverer := &fakeDiscoverer{}
	var output bytes.Buffer

	err := run(ctx, lookup, discoverer, &output)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("configuration deadline error = %v, want context.DeadlineExceeded", err)
	}
	if discoverer.calls != 0 || output.Len() != 0 {
		t.Fatalf("expired setup continued into discovery or report: calls=%d output=%q", discoverer.calls, output.String())
	}
	if _, err := os.Lstat(hostLockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host lock was acquired after configuration deadline: %v", err)
	}
}
