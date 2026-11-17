package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

const (
	runnerInstanceLabel = "com.skyhigh.runner-instance"
	lifecycleIDLabel    = "com.skyhigh.lifecycle-id"
	dockerInspectBatchSize = 32
)

// DiscoveredDockerContainer contains only identity and state metadata. It never
// includes student source, stdin, stdout, stderr or hidden-test material.
type DiscoveredDockerContainer struct {
	ID               string `json:"id"`
	RunnerInstanceID string `json:"runnerInstanceId"`
	LifecycleID      string `json:"lifecycleId"`
	State            string `json:"state"`
}

// DockerLifecycleDiscoverer returns the complete read-only inventory for one
// exact runner-instance label. Callers correlate lifecycle labels in memory.
type DockerLifecycleDiscoverer interface {
	DiscoverByRunnerLabel(context.Context, string) ([]DiscoveredDockerContainer, error)
}

// LifecycleDiscovery is a dry-run result. No method in this file removes or
// changes a Docker container.
type LifecycleDiscovery struct {
	Lifecycle  sandboxjournal.Lifecycle
	Containers []DiscoveredDockerContainer
	Assessment string
}

// DiscoverPendingDockerLifecycles correlates pending journal entries with
// containers carrying both exact ownership labels. The caller must first open
// the journal successfully; its exclusive journal lock prevents concurrent
// journal owners. CREATE_INTENT records with no container ID are still reported
// for operator review, never treated as authorization to delete.
func DiscoverPendingDockerLifecycles(
	ctx context.Context,
	journal *sandboxjournal.Journal,
	discoverer DockerLifecycleDiscoverer,
	runnerID string,
) ([]LifecycleDiscovery, error) {
	if journal == nil || discoverer == nil || !runnerInstanceIDPattern.MatchString(runnerID) {
		return nil, ErrSandboxNotConfigured
	}
	pending, err := journal.Pending()
	if err != nil {
		return nil, fmt.Errorf("read pending sandbox lifecycles: %w", err)
	}
	pendingLifecycleIDs := make(map[string]struct{}, len(pending))
	for _, lifecycle := range pending {
		if lifecycle.RunnerInstanceID != runnerID {
			return nil, errors.New("pending lifecycle belongs to a different runner instance")
		}
		pendingLifecycleIDs[lifecycle.LifecycleID] = struct{}{}
	}

	// Inventory once, then correlate in memory. A failed or incomplete Docker
	// inventory must never produce a partial recovery report.
	containers, err := discoverer.DiscoverByRunnerLabel(ctx, runnerID)
	if err != nil {
		return nil, fmt.Errorf("discover runner containers: %w", err)
	}
	byLifecycle := make(map[string][]DiscoveredDockerContainer, len(pending))
	seen := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if len(container.ID) != 64 ||
			!containerIDPattern.MatchString(container.ID) ||
			container.RunnerInstanceID != runnerID ||
			!runnerInstanceIDPattern.MatchString(container.LifecycleID) ||
			strings.TrimSpace(container.State) == "" {
			return nil, errors.New("Docker discovery returned invalid or foreign container metadata")
		}
		if _, exists := seen[container.ID]; exists {
			return nil, errors.New("Docker discovery returned duplicate container IDs")
		}
		seen[container.ID] = struct{}{}
		if _, exists := pendingLifecycleIDs[container.LifecycleID]; !exists {
			return nil, errors.New("Docker discovery returned a container without a pending journal lifecycle")
		}
		byLifecycle[container.LifecycleID] = append(byLifecycle[container.LifecycleID], container)
	}

	results := make([]LifecycleDiscovery, 0, len(pending))
	for _, lifecycle := range pending {
		matches := byLifecycle[lifecycle.LifecycleID]
		sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
		result := LifecycleDiscovery{Lifecycle: lifecycle, Containers: matches}
		switch {
		case len(matches) == 0:
			result.Assessment = "NO_CONTAINER_MATCH — operator review required"
		case len(matches) > 1:
			result.Assessment = "AMBIGUOUS_MULTIPLE_MATCHES — operator review required"
		case lifecycle.ContainerID != "" && matches[0].ID != lifecycle.ContainerID:
			result.Assessment = "CONTAINER_ID_MISMATCH — operator review required"
		case lifecycle.ContainerID == "":
			result.Assessment = "CREATE_INTENT_MATCH — crash-window candidate; operator review required"
		default:
			result.Assessment = "PENDING_CONTAINER_MATCH — operator review required"
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Lifecycle.LifecycleID < results[j].Lifecycle.LifecycleID
	})
	return results, nil
}

// DiscoverByRunnerLabel performs one read-only inventory query for an exact
// runner-instance label, then independently inspects every full container ID.
func (cli OSCommandDockerCLI) DiscoverByRunnerLabel(
	ctx context.Context,
	runnerID string,
) ([]DiscoveredDockerContainer, error) {
	if !runnerInstanceIDPattern.MatchString(runnerID) {
		return nil, ErrDockerCommandFailed
	}
	command := exec.CommandContext(
		ctx,
		cli.binary(),
		"ps", "--all", "--no-trunc",
		"--filter", "label="+runnerInstanceLabel+"="+runnerID,
		"--format", "{{.ID}}",
	)
	output, err := command.Output()
	if err != nil {
		return nil, ErrDockerCommandFailed
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return []DiscoveredDockerContainer{}, nil
	}
	lines := strings.Split(trimmed, "\n")
	seen := make(map[string]struct{}, len(lines))
	ids := make([]string, 0, len(lines))
	for _, id := range lines {
		id = strings.TrimSpace(id)
		if len(id) != 64 || !containerIDPattern.MatchString(id) {
			return nil, ErrDockerCommandFailed
		}
		if _, exists := seen[id]; exists {
			return nil, ErrDockerCommandFailed
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	containers := make([]DiscoveredDockerContainer, 0, len(ids))
	for offset := 0; offset < len(ids); offset += dockerInspectBatchSize {
		end := offset + dockerInspectBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[offset:end]
		args := []string{"inspect", "--format", "{{json .}}"}
		args = append(args, batch...)
		inspect := exec.CommandContext(ctx, cli.binary(), args...)
		inspected, err := inspect.Output()
		if err != nil {
			return nil, ErrDockerCommandFailed
		}

		// Docker emits one JSON object per requested container. Decode the
		// complete stream and require an exact one-to-one ID match; never
		// accept omitted, duplicated, or unexpected inspect records.
		expected := make(map[string]struct{}, len(batch))
		for _, id := range batch {
			expected[id] = struct{}{}
		}
		decoder := json.NewDecoder(strings.NewReader(string(inspected)))
		batchContainers := make([]DiscoveredDockerContainer, 0, len(batch))
		for decoder.More() {
			var item struct {
				ID string `json:"Id"`
				Config struct {
					Labels map[string]string `json:"Labels"`
				} `json:"Config"`
				State struct {
					Status string `json:"Status"`
				} `json:"State"`
			}
			if err := decoder.Decode(&item); err != nil {
				return nil, ErrDockerCommandFailed
			}
			if _, ok := expected[item.ID]; !ok {
				return nil, ErrDockerCommandFailed
			}
			delete(expected, item.ID)
			lifecycleID := item.Config.Labels[lifecycleIDLabel]
			if item.ID == "" ||
				item.Config.Labels[runnerInstanceLabel] != runnerID ||
				!runnerInstanceIDPattern.MatchString(lifecycleID) ||
				strings.TrimSpace(item.State.Status) == "" {
				return nil, ErrDockerCommandFailed
			}
			batchContainers = append(batchContainers, DiscoveredDockerContainer{
				ID: item.ID, RunnerInstanceID: runnerID, LifecycleID: lifecycleID, State: item.State.Status,
			})
		}
		if len(expected) != 0 {
			return nil, ErrDockerCommandFailed
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, ErrDockerCommandFailed
		}
		containers = append(containers, batchContainers...)
	}
	return containers, nil
}
