package runner

import (
	"context"
	"strings"
	"testing"
)

func TestDiscoverPendingDockerLifecyclesRejectsUntrustedDiscovererMetadata(t *testing.T) {
	tests := []struct {
		name       string
		containers func(runnerID, lifecycleID string) []DiscoveredDockerContainer
	}{
		{
			name: "foreign runner identity",
			containers: func(_, lifecycleID string) []DiscoveredDockerContainer {
				return []DiscoveredDockerContainer{{
					ID: strings.Repeat("b", 64), RunnerInstanceID: strings.Repeat("c", 32),
					LifecycleID: lifecycleID, State: "exited",
				}}
			},
		},
		{
			name: "foreign lifecycle identity",
			containers: func(runnerID, _ string) []DiscoveredDockerContainer {
				return []DiscoveredDockerContainer{{
					ID: strings.Repeat("b", 64), RunnerInstanceID: runnerID,
					LifecycleID: strings.Repeat("c", 32), State: "exited",
				}}
			},
		},
		{
			name: "malformed container ID",
			containers: func(runnerID, lifecycleID string) []DiscoveredDockerContainer {
				return []DiscoveredDockerContainer{{
					ID: "short", RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: "exited",
				}}
			},
		},
		{
			name: "missing container state",
			containers: func(runnerID, lifecycleID string) []DiscoveredDockerContainer {
				return []DiscoveredDockerContainer{{
					ID: strings.Repeat("b", 64), RunnerInstanceID: runnerID,
					LifecycleID: lifecycleID, State: " ",
				}}
			},
		},
		{
			name: "duplicate container IDs",
			containers: func(runnerID, lifecycleID string) []DiscoveredDockerContainer {
				container := DiscoveredDockerContainer{
					ID: strings.Repeat("b", 64), RunnerInstanceID: runnerID,
					LifecycleID: lifecycleID, State: "exited",
				}
				return []DiscoveredDockerContainer{container, container}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sandbox, err := newJournaledTestSandbox(t, &fakeDockerCLI{})
			if err != nil {
				t.Fatal(err)
			}
			runnerID := strings.Repeat("a", 32)
			lifecycleID, err := sandbox.journal.Begin(runnerID, "exec_untrusted_discovery")
			if err != nil {
				t.Fatal(err)
			}
			if err := sandbox.journal.Created(lifecycleID, strings.Repeat("b", 64)); err != nil {
				t.Fatal(err)
			}
			discoverer := &fakeLifecycleDiscoverer{
				containers: test.containers(runnerID, lifecycleID),
			}
			results, err := DiscoverPendingDockerLifecycles(
				context.Background(), sandbox.journal, discoverer, runnerID,
			)
			if err == nil {
				t.Fatalf("untrusted metadata was accepted: %+v", results)
			}
			if len(results) != 0 {
				t.Fatalf("partial recovery findings escaped after invalid metadata: %+v", results)
			}
			pending, pendingErr := sandbox.journal.Pending()
			if pendingErr != nil {
				t.Fatal(pendingErr)
			}
			if len(pending) != 1 || pending[0].Cleaned {
				t.Fatalf("failed dry-run mutated journal: %+v", pending)
			}
		})
	}
}
