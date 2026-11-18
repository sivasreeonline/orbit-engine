package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

type fakeLifecycleDiscoverer struct {
	containers []DiscoveredDockerContainer
	err error
	calls int
	runnerID string
	}

func (fake *fakeLifecycleDiscoverer) DiscoverByRunnerLabel(_ context.Context, runnerID string) ([]DiscoveredDockerContainer, error) {
	fake.calls++
	fake.runnerID = runnerID
		return append([]DiscoveredDockerContainer(nil), fake.containers...), fake.err
}

func TestDiscoverPendingDockerLifecyclesIsDryRunAndCorrelatesExactIdentity(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	lifecycleID, err := sandbox.journal.Begin(runnerID, "exec_recovery_test")
	if err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("b", 64)
	if err := sandbox.journal.Created(lifecycleID, containerID); err != nil {
		t.Fatal(err)
	}
	discoverer := &fakeLifecycleDiscoverer{containers: []DiscoveredDockerContainer{{
		ID: containerID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "exited",
	}}}

	results, err := DiscoverPendingDockerLifecycles(context.Background(), sandbox.journal, discoverer, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Assessment != "PENDING_CONTAINER_MATCH — operator review required" {
		t.Fatalf("discovery result = %+v", results)
	}
	if discoverer.calls != 1 || discoverer.runnerID != runnerID {
		t.Fatalf("discovery did not use exact journal identity: %+v", discoverer)
	}
	pending, err := sandbox.journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Cleaned {
		t.Fatalf("dry-run discovery mutated journal state: %+v", pending)
	}
}

func TestDiscoverPendingDockerLifecyclesUsesOneInventoryForMultiplePendingRecords(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	firstLifecycle, err := sandbox.journal.Begin(runnerID, "exec_first")
	if err != nil {
		t.Fatal(err)
	}
	if err := sandbox.journal.Created(firstLifecycle, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	secondLifecycle, err := sandbox.journal.Begin(runnerID, "exec_second")
	if err != nil {
		t.Fatal(err)
	}
	containers := []DiscoveredDockerContainer{
		{ID: strings.Repeat("b", 64), RunnerInstanceID: runnerID, LifecycleID: firstLifecycle, State: "exited"},
		{ID: strings.Repeat("c", 64), RunnerInstanceID: runnerID, LifecycleID: secondLifecycle, State: "created"},
	}
	discoverer := &fakeLifecycleDiscoverer{containers: containers}
	results, err := DiscoverPendingDockerLifecycles(context.Background(), sandbox.journal, discoverer, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if discoverer.calls != 1 {
		t.Fatalf("Docker inventory calls = %d, want one for both lifecycles", discoverer.calls)
	}
	if len(results) != 2 {
		t.Fatalf("recovery findings = %+v, want two", results)
	}
	for _, result := range results {
		if len(result.Containers) != 1 || result.Containers[0].LifecycleID != result.Lifecycle.LifecycleID {
			t.Fatalf("container was not correlated to its exact lifecycle: %+v", result)
		}
	}
}

func TestDiscoverPendingDockerLifecyclesFailsClosedOnRunnerMismatch(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sandbox.journal.Begin(strings.Repeat("a", 32), "exec_recovery_test"); err != nil {
		t.Fatal(err)
	}
	discoverer := &fakeLifecycleDiscoverer{}
	_, err = DiscoverPendingDockerLifecycles(context.Background(), sandbox.journal, discoverer, strings.Repeat("c", 32))
	if err == nil {
		t.Fatal("runner identity mismatch was accepted")
	}
	if discoverer.calls != 0 {
		t.Fatal("Docker discovery ran after runner identity mismatch")
	}
}

func TestDiscoverPendingDockerLifecyclesReportsCreateIntentWithoutDeletion(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	if _, err := sandbox.journal.Begin(runnerID, "exec_create_gap"); err != nil {
		t.Fatal(err)
	}
	discoverer := &fakeLifecycleDiscoverer{}
	results, err := DiscoverPendingDockerLifecycles(context.Background(), sandbox.journal, discoverer, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Assessment != "NO_CONTAINER_MATCH — operator review required" {
		t.Fatalf("create-intent discovery result = %+v", results)
	}
}

func TestOSCommandDockerCLIDiscoveryUsesExactLabelsAndVerifiesInspect(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	binary := filepath.Join(t.TempDir(), "docker-stub")
	id := strings.Repeat("a", 64)
	runnerID := strings.Repeat("b", 32)
	lifecycleID := strings.Repeat("c", 32)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"ps\" ]; then",
		"  [ \"$2\" = \"--all\" ] || exit 81",
		"  [ \"$3\" = \"--no-trunc\" ] || exit 82",
		"  [ \"$4\" = \"--filter\" ] || exit 83",
		"  [ \"$5\" = \"label=com.skyhigh.runner-instance=" + runnerID + "\" ] || exit 84",
		"  [ \"$6\" = \"--format\" ] || exit 85",
		"  [ \"$7\" = \"{{.ID}}\" ] || exit 86",
		"  printf '%s\n' \"" + id + "\"",
		"  exit 0",
		"fi",
		"if [ \"$1\" = \"inspect\" ]; then",
		"  [ \"$4\" = \"" + id + "\" ] || exit 87",
		"  printf '%s' '{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"" + lifecycleID + "\"}},\"State\":{\"Status\":\"exited\"}}'",
		"  exit 0",
		"fi",
		"exit 88",
	}, "\n")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(context.Background(), runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != id || found[0].State != "exited" {
		t.Fatalf("discovered containers = %+v", found)
	}
}

func TestOSCommandDockerCLIDiscoveryRejectsInspectLabelMismatch(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	binary := filepath.Join(t.TempDir(), "docker-stub")
	id := strings.Repeat("a", 64)
	runnerID := strings.Repeat("b", 32)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"ps\" ]; then printf '%s\n' \"" + id + "\"; exit 0; fi",
		"if [ \"$1\" = \"inspect\" ]; then printf '%s' '{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"wrong\"}},\"State\":{\"Status\":\"exited\"}}'; exit 0; fi",
		"exit 89",
	}, "\n")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(context.Background(), runnerID)
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("mismatched inspect labels error = %v, want ErrDockerCommandFailed", err)
	}
}


func TestDiscoverPendingDockerLifecyclesFlagsAmbiguousAndMismatchedContainers(t *testing.T) {
	tests := []struct {
		name string
		containers []DiscoveredDockerContainer
		want string
	}{
		{
			name: "multiple exact-label matches",
			containers: []DiscoveredDockerContainer{
				{ID: strings.Repeat("b", 64), State: "running"},
				{ID: strings.Repeat("c", 64), State: "exited"},
			},
			want: "AMBIGUOUS_MULTIPLE_MATCHES — operator review required",
		},
		{
			name: "journal container ID differs",
			containers: []DiscoveredDockerContainer{
				{ID: strings.Repeat("c", 64), State: "exited"},
			},
			want: "CONTAINER_ID_MISMATCH — operator review required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
			if err != nil {
				t.Fatal(err)
			}
			runnerID := strings.Repeat("a", 32)
			lifecycleID, err := sandbox.journal.Begin(runnerID, "exec_recovery_test")
			if err != nil {
				t.Fatal(err)
			}
			if err := sandbox.journal.Created(lifecycleID, strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
			containers := test.containers
			for i := range containers {
				containers[i].RunnerInstanceID = runnerID
				containers[i].LifecycleID = lifecycleID
			}
			discoverer := &fakeLifecycleDiscoverer{containers: containers}
			results, err := DiscoverPendingDockerLifecycles(context.Background(), sandbox.journal, discoverer, runnerID)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].Assessment != test.want {
				t.Fatalf("assessment = %+v, want %q", results, test.want)
			}
		})
	}
}


func TestOSCommandDockerCLIDiscoveryFailsClosedOnUntrustedDockerResponses(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	id := strings.Repeat("a", 64)
	runnerID := strings.Repeat("b", 32)
	lifecycleID := strings.Repeat("c", 32)
	validInspect := `{"Id":"` + id + `","Config":{"Labels":{"com.skyhigh.runner-instance":"` + runnerID + `","com.skyhigh.lifecycle-id":"` + lifecycleID + `"}},"State":{"Status":"exited"}}`

	tests := []struct {
		name string
		script string
	}{
		{
			name: "daemon unavailable during list",
			script: "#!/bin/sh\nexit 41\n",
		},
		{
			name: "malformed short container id",
			script: "#!/bin/sh\nprintf 'abc123\n'\n",
		},
		{
			name: "duplicate container ids",
			script: "#!/bin/sh\nprintf '" + id + "\n" + id + "\n'\n",
		},
		{
			name: "daemon unavailable during inspect",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\n'; exit 0; fi\nexit 42\n",
		},
		{
			name: "malformed inspect json",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\n'; exit 0; fi\nprintf '{not-json'\n",
		},
		{
			name: "inspect id differs from queried id",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\n'; exit 0; fi\nprintf '%s' '{\"Id\":\"" + strings.Repeat("d", 64) + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"" + lifecycleID + "\"}},\"State\":{\"Status\":\"exited\"}}'\n",
		},
		{
			name: "inspect state missing",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\n'; exit 0; fi\nprintf '%s' '{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"" + lifecycleID + "\"}},\"State\":{}}'\n",
		},
		{
			name: "inspect valid ownership",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\n'; exit 0; fi\nprintf '%s' '" + validInspect + "'\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "docker-stub")
			if err := os.WriteFile(binary, []byte(test.script), 0o700); err != nil {
				t.Fatal(err)
			}
			found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(context.Background(), runnerID)
			if test.name == "inspect valid ownership" {
				if err != nil || len(found) != 1 || found[0].ID != id {
					t.Fatalf("valid discovery = %+v, %v", found, err)
				}
				return
			}
			if !errors.Is(err, ErrDockerCommandFailed) {
				t.Fatalf("discovery error = %v, want ErrDockerCommandFailed", err)
			}
			if len(found) != 0 {
				t.Fatalf("untrusted Docker response produced findings: %+v", found)
			}
		})
	}
}


func TestOSCommandDockerCLIDiscoveryInspectsInBoundedBatches(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "docker-stub")
	logPath := filepath.Join(directory, "inspect-calls.log")
	runnerID := strings.Repeat("b", 32)
	lifecycleID := strings.Repeat("c", 32)
	ids := make([]string, dockerInspectBatchSize+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	script := strings.Join([]string{
		"#!/bin/sh",
		`if [ "$1" = "ps" ]; then printf '%s\n' '` + strings.Join(ids, "' '") + `'; exit 0; fi`,
		`if [ "$1" = "inspect" ]; then`,
		`  [ "$2" = "--format" ] || exit 91`,
		`  [ "$3" = "{{json .}}" ] || exit 92`,
		`  shift 3`,
		`  [ "$#" -ge 1 ] && [ "$#" -le ` + fmt.Sprint(dockerInspectBatchSize) + ` ] || exit 93`,
		`  printf 'call\n' >> '` + logPath + `'`,
		`  for id in "$@"; do printf '{"Id":"%s","Config":{"Labels":{"com.skyhigh.runner-instance":"` + runnerID + `","com.skyhigh.lifecycle-id":"` + lifecycleID + `"}},"State":{"Status":"exited"}}\n' "$id"; done`,
		"  exit 0",
		"fi",
		"exit 94",
	}, "\n")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("batched Docker discovery failed: %v\\nfixture:\\n%s", err, script)
	}
	if len(found) != len(ids) {
		t.Fatalf("discovered %d containers, want %d", len(found), len(ids))
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(calls), "call"); got != 2 {
		t.Fatalf("inspect process count = %d, want 2 bounded batches", got)
	}
	for i, container := range found {
		if container.ID != ids[i] || container.RunnerInstanceID != runnerID ||
			container.LifecycleID != lifecycleID || container.State != "exited" {
			t.Fatalf("container %d failed exact identity validation: %+v", i, container)
		}
	}
}


func TestOSCommandDockerCLIDiscoveryRejectsIncompleteOrUntrustedInspectBatches(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	runnerID := strings.Repeat("b", 32)
	lifecycleID := strings.Repeat("c", 32)
	ids := make([]string, dockerInspectBatchSize+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}

	tests := []struct {
		name        string
		secondBatch string
	}{
		{name: "second batch command fails", secondBatch: `exit 95`},
		{name: "second batch omits requested id", secondBatch: `exit 0`},
		{name: "second batch duplicates requested id", secondBatch: `emit "$1"; emit "$1"`},
		{name: "second batch returns unexpected id", secondBatch: `emit "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"`},
		{name: "second batch returns malformed trailing json", secondBatch: `printf '{broken-json}\n'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "docker-stub")
			emit := fmt.Sprintf(`emit() { printf '{"Id":"%%s","Config":{"Labels":{"com.skyhigh.runner-instance":"%s","com.skyhigh.lifecycle-id":"%s"}},"State":{"Status":"exited"}}\n' "$1"; }`, runnerID, lifecycleID)
			script := strings.Join([]string{
				"#!/bin/sh",
				emit,
				`if [ "$1" = "ps" ]; then printf '%s\n' '` + strings.Join(ids, "' '") + `'; exit 0; fi`,
				`if [ "$1" = "inspect" ]; then shift 3; if [ "$#" -eq 1 ]; then ` + test.secondBatch + `; exit 0; fi; for id in "$@"; do emit "$id"; done; exit 0; fi`,
				"exit 96",
			}, "\n")
			if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(context.Background(), runnerID)
			if !errors.Is(err, ErrDockerCommandFailed) {
				t.Fatalf("discovery error = %v, want ErrDockerCommandFailed", err)
			}
			if found != nil {
				t.Fatalf("untrusted second batch returned partial findings: %+v", found)
			}
		})
	}
}
func TestOSCommandDockerCLIDiscoveryHonorsCancellationDuringInspect(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	binary := filepath.Join(t.TempDir(), "docker-stub")
	id := strings.Repeat("a", 64)
	script := strings.Join([]string{
		"#!/bin/sh",
		\`if [ "$1" = "ps" ]; then printf '%s\n' "\` + id + \`"; exit 0; fi\`,
		\`if [ "$1" = "inspect" ]; then sleep 2; exit 0; fi\`,
		"exit 97",
	}, "\n")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(ctx, strings.Repeat("b", 32))
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("cancelled inspect error = %v, want ErrDockerCommandFailed", err)
	}
	if found != nil {
		t.Fatalf("cancelled inspect returned partial findings: %+v", found)
	}
}

func TestOSCommandDockerCLIDiscoveryHonorsCancellation(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Docker lifecycle discovery targets Linux hosts")
	}
	binary := filepath.Join(t.TempDir(), "docker-stub")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByRunnerLabel(ctx, strings.Repeat("a", 32))
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("cancelled discovery error = %v, want ErrDockerCommandFailed", err)
	}
}



func TestCreateIntentSurvivesAbruptProcessExitAndIsDiscoverableAfterOperatorUnlock(t *testing.T) {
	if os.Getenv("SKYHIGH_CREATE_CRASH_HELPER") == "1" {
		journalPath := os.Getenv("SKYHIGH_CREATE_CRASH_JOURNAL")
		markerPath := os.Getenv("SKYHIGH_CREATE_CRASH_MARKER")
		runnerID := strings.Repeat("a", 32)
		journal, err := sandboxjournal.Open(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		lifecycleID, err := journal.Begin(runnerID, "exec_process_crash")
		if err != nil {
			t.Fatal(err)
		}
		// Simulate Docker returning a full container ID after CREATE_INTENT
		// was fsynced, then terminate before journal.Created can be appended.
		containerID := strings.Repeat("d", 64)
		if err := os.WriteFile(markerPath, []byte(lifecycleID+"\n"+containerID), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}

	journalPath := privateJournalTestPath(t, "process-crash.jsonl")
	markerPath := filepath.Join(filepath.Dir(journalPath), "docker-created.marker")
	command := exec.Command(os.Args[0], "-test.run=^TestCreateIntentSurvivesAbruptProcessExitAndIsDiscoverableAfterOperatorUnlock$")
	command.Env = append(os.Environ(),
		"SKYHIGH_CREATE_CRASH_HELPER=1",
		"SKYHIGH_CREATE_CRASH_JOURNAL="+journalPath,
		"SKYHIGH_CREATE_CRASH_MARKER="+markerPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("crash helper failed: %v\n%s", err, output)
	}

	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(marker)), "\n")
	if len(parts) != 2 {
		t.Fatalf("crash marker = %q, want lifecycle and container IDs", marker)
	}
	lifecycleID, containerID := parts[0], parts[1]
	if len(lifecycleID) != 32 || len(containerID) != 64 {
		t.Fatalf("crash marker contains invalid IDs: %q", marker)
	}

	// The journal's exclusive lock is deliberately not stolen by Open.
	// The operator may remove this exact stale lock only after independently
	// confirming the former owner process has exited (the child has exited).
	lockPath := journalPath + ".lock"
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("abrupt process exit did not preserve journal lock for review: %v", err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("operator-reviewed stale lock removal: %v", err)
	}

	journal, err := sandboxjournal.OpenReadOnly(journalPath)
	if err != nil {
		t.Fatalf("read-only reopen after operator lock review: %v", err)
	}
	defer journal.Close()

	runnerID := strings.Repeat("a", 32)
	discoverer := &fakeLifecycleDiscoverer{containers: []DiscoveredDockerContainer{{
		ID: containerID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "created",
	}}}
	results, err := DiscoverPendingDockerLifecycles(context.Background(), journal, discoverer, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 ||
		results[0].Assessment != "CREATE_INTENT_MATCH — crash-window candidate; operator review required" ||
		len(results[0].Containers) != 1 || results[0].Containers[0].ID != containerID {
		t.Fatalf("process-crash recovery finding = %+v", results)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		pending[0].Created || pending[0].Cleaned || pending[0].ContainerID != "" {
		t.Fatalf("read-only recovery must preserve intent-only journal: %+v", pending)
	}
}

func TestDiscoverPendingDockerLifecyclesCorrelatesCreateIntentCrashWindow(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	lifecycleID, err := sandbox.journal.Begin(runnerID, "exec_create_gap")
	if err != nil {
		t.Fatal(err)
	}

	// Model the durable CREATE_INTENT surviving a process crash after Docker
	// created the container but before the CREATED event reached the journal.
	// Discovery must correlate exact labels, but it must not repair the journal
	// or interpret the match as permission to remove the container.
	containerID := strings.Repeat("d", 64)
	discoverer := &fakeLifecycleDiscoverer{containers: []DiscoveredDockerContainer{{
		ID: containerID,
		RunnerInstanceID: runnerID,
		LifecycleID: lifecycleID,
		State: "created",
	}}}

	results, err := DiscoverPendingDockerLifecycles(
		context.Background(), sandbox.journal, discoverer, runnerID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 ||
		results[0].Assessment != "CREATE_INTENT_MATCH — crash-window candidate; operator review required" ||
		len(results[0].Containers) != 1 ||
		results[0].Containers[0].ID != containerID {
		t.Fatalf("create-intent crash-window finding = %+v", results)
	}
	pending, err := sandbox.journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != "" {
		t.Fatalf("discovery must preserve the original intent-only journal state: %+v", pending)
	}
}

func TestDiscoverPendingDockerLifecyclesReturnsNoPartialReportOnLaterDiscoveryFailure(t *testing.T) {
	sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
	if err != nil {
		t.Fatal(err)
	}
	runnerID := strings.Repeat("a", 32)
	if _, err := sandbox.journal.Begin(runnerID, "exec_first_gap"); err != nil {
		t.Fatal(err)
	}
	if _, err := sandbox.journal.Begin(runnerID, "exec_second_gap"); err != nil {
		t.Fatal(err)
	}

	discoverer := &sequencedLifecycleDiscoverer{
		err: errors.New("Docker daemon became unavailable"),
	}

	results, err := DiscoverPendingDockerLifecycles(
		context.Background(), sandbox.journal, discoverer, runnerID,
	)
	if err == nil {
		t.Fatal("failed inventory unexpectedly returned a clean report")
	}
	if results != nil {
		t.Fatalf("inventory failure returned partial findings: %+v", results)
	}
	if discoverer.calls != 1 {
		t.Fatalf("Docker inventory calls = %d, want exactly one", discoverer.calls)
	}
	pending, pendingErr := sandbox.journal.Pending()
	if pendingErr != nil {
		t.Fatal(pendingErr)
	}
	if len(pending) != 2 {
		t.Fatalf("failed discovery mutated pending journal records: %+v", pending)
	}
}

type sequencedLifecycleDiscoverer struct {
	err error
	calls int
}

func (discoverer *sequencedLifecycleDiscoverer) DiscoverByRunnerLabel(
	_ context.Context,
	_ string,
) ([]DiscoveredDockerContainer, error) {
	discoverer.calls++
	return nil, discoverer.err
}
