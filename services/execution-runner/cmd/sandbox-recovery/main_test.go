package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/hostlock"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runner"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

type fakeDiscoverer struct {
	containers []runner.DiscoveredDockerContainer
	calls int
}

func (fake *fakeDiscoverer) DiscoverByLifecycleLabels(
	_ context.Context,
	_, _ string,
) ([]runner.DiscoveredDockerContainer, error) {
	fake.calls++
	return append([]runner.DiscoveredDockerContainer(nil), fake.containers...), nil
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
