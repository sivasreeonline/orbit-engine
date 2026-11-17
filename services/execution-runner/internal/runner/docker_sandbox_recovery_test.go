package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeLifecycleDiscoverer struct {
	containers []DiscoveredDockerContainer
	err error
	calls int
	runnerID string
	lifecycleID string
}

func (fake *fakeLifecycleDiscoverer) DiscoverByLifecycleLabels(
	_ context.Context,
	runnerID string,
	lifecycleID string,
) ([]DiscoveredDockerContainer, error) {
	fake.calls++
	fake.runnerID = runnerID
	fake.lifecycleID = lifecycleID
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
	if discoverer.calls != 1 || discoverer.runnerID != runnerID || discoverer.lifecycleID != lifecycleID {
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
		"  [ \"$6\" = \"--filter\" ] || exit 85",
		"  [ \"$7\" = \"label=com.skyhigh.lifecycle-id=" + lifecycleID + "\" ] || exit 86",
		"  printf '%s\\n' \"" + id + "\"",
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
	found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByLifecycleLabels(context.Background(), runnerID, lifecycleID)
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
	lifecycleID := strings.Repeat("c", 32)
	script := strings.Join([]string{
		"#!/bin/sh",
		"if [ \"$1\" = \"ps\" ]; then printf '%s\\n' \"" + id + "\"; exit 0; fi",
		"if [ \"$1\" = \"inspect\" ]; then printf '%s' '{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"wrong\"}},\"State\":{\"Status\":\"exited\"}}'; exit 0; fi",
		"exit 89",
	}, "\n")
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByLifecycleLabels(context.Background(), runnerID, lifecycleID)
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
			script: "#!/bin/sh\nprintf 'abc123\\n'\n",
		},
		{
			name: "duplicate container ids",
			script: "#!/bin/sh\nprintf '" + id + "\\n" + id + "\\n'\n",
		},
		{
			name: "daemon unavailable during inspect",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\\n'; exit 0; fi\nexit 42\n",
		},
		{
			name: "malformed inspect json",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\\n'; exit 0; fi\nprintf '{not-json'\n",
		},
		{
			name: "inspect id differs from queried id",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\\n'; exit 0; fi\nprintf '%s' '{\"Id\":\"" + strings.Repeat("d", 64) + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"" + lifecycleID + "\"}},\"State\":{\"Status\":\"exited\"}}'\n",
		},
		{
			name: "inspect state missing",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\\n'; exit 0; fi\nprintf '%s' '{\"Id\":\"" + id + "\",\"Config\":{\"Labels\":{\"com.skyhigh.runner-instance\":\"" + runnerID + "\",\"com.skyhigh.lifecycle-id\":\"" + lifecycleID + "\"}},\"State\":{}}'\n",
		},
		{
			name: "inspect valid ownership",
			script: "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then printf '" + id + "\\n'; exit 0; fi\nprintf '%s' '" + validInspect + "'\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "docker-stub")
			if err := os.WriteFile(binary, []byte(test.script), 0o700); err != nil {
				t.Fatal(err)
			}
			found, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByLifecycleLabels(
				context.Background(), runnerID, lifecycleID,
			)
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
	_, err := (OSCommandDockerCLI{Binary: binary}).DiscoverByLifecycleLabels(
		ctx, strings.Repeat("a", 32), strings.Repeat("b", 32),
	)
	if !errors.Is(err, ErrDockerCommandFailed) {
		t.Fatalf("cancelled discovery error = %v, want ErrDockerCommandFailed", err)
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
	firstID, err := sandbox.journal.Begin(runnerID, "exec_first_gap")
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := sandbox.journal.Begin(runnerID, "exec_second_gap")
	if err != nil {
		t.Fatal(err)
	}
	_ = firstID

	discoverer := &sequencedLifecycleDiscoverer{
		responses: [][]DiscoveredDockerContainer{
			{{
				ID: strings.Repeat("b", 64),
				RunnerInstanceID: runnerID,
				LifecycleID: secondID,
				State: "exited",
			}},
		},
		errors: []error{nil, errors.New("Docker daemon became unavailable")},
	}

	results, err := DiscoverPendingDockerLifecycles(
		context.Background(), sandbox.journal, discoverer, runnerID,
	)
	if err == nil {
		t.Fatal("partial discovery unexpectedly returned a clean report")
	}
	if results != nil {
		t.Fatalf("discovery failure returned partial findings: %+v", results)
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
	responses [][]DiscoveredDockerContainer
	errors []error
	calls int
}

func (discoverer *sequencedLifecycleDiscoverer) DiscoverByLifecycleLabels(
	_ context.Context,
	_, _ string,
) ([]DiscoveredDockerContainer, error) {
	index := discoverer.calls
	discoverer.calls++
	if index < len(discoverer.errors) && discoverer.errors[index] != nil {
		return nil, discoverer.errors[index]
	}
	if index >= len(discoverer.responses) {
		return nil, nil
	}
	return append([]DiscoveredDockerContainer(nil), discoverer.responses[index]...), nil
}
