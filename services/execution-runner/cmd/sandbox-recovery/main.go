package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runner"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

var runnerIDPattern = regexp.MustCompile("^[a-f0-9]{32}$")

type environment func(string) (string, bool)

type recoveryReport struct {
	SchemaVersion     int                `json:"schemaVersion"`
	Mode              string             `json:"mode"`
	RunnerInstanceID  string             `json:"runnerInstanceId"`
	CheckedAt         time.Time          `json:"checkedAt"`
	PendingCount      int                `json:"pendingCount"`
	Findings          []recoveryFinding  `json:"findings"`
	DeletionPerformed bool               `json:"deletionPerformed"`
}

type recoveryFinding struct {
	LifecycleID string                         `json:"lifecycleId"`
	ExecutionID string                         `json:"executionId"`
	ContainerID string                         `json:"containerId,omitempty"`
	Containers  []runner.DiscoveredDockerContainer `json:"containers"`
	Assessment  string                         `json:"assessment"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.LookupEnv, runner.OSCommandDockerCLI{}, os.Stdout); err != nil {
		log.Printf("sandbox recovery inspection failed: %v", err)
		os.Exit(1)
	}
}

// run is deliberately read-only. Opening the same exclusive journal used by
// the foreground runner proves that no process currently owns that journal.
// The operator must stop the runner before invoking this command.
func run(
	ctx context.Context,
	lookup environment,
	discoverer runner.DockerLifecycleDiscoverer,
	output io.Writer,
) error {
	if lookup == nil || discoverer == nil || output == nil {
		return errors.New("recovery inspection dependencies are required")
	}
	runnerID, ok := lookup("RUNNER_INSTANCE_ID")
	if !ok || !runnerIDPattern.MatchString(runnerID) {
		return errors.New("RUNNER_INSTANCE_ID must be 32 lowercase hexadecimal characters")
	}
	journalPath, ok := lookup("RUNNER_SANDBOX_JOURNAL_PATH")
	if !ok || journalPath == "" || !filepath.IsAbs(journalPath) ||
		filepath.Clean(journalPath) == string(filepath.Separator) {
		return errors.New("RUNNER_SANDBOX_JOURNAL_PATH must be an absolute non-root path")
	}

	// Recovery must inspect an existing journal, never silently create a new
	// empty one and report a misleading clean state.
	info, err := os.Lstat(journalPath)
	if err != nil {
		return fmt.Errorf("inspect existing sandbox journal: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("sandbox journal must be an existing regular non-symlink file")
	}

	journal, err := sandboxjournal.OpenReadOnly(journalPath)
	if err != nil {
		return fmt.Errorf("acquire exclusive sandbox journal ownership: %w", err)
	}
	inspectionContext, cancelInspection := context.WithTimeout(ctx, 30*time.Second)
	defer cancelInspection()
	findings, discoveryErr := runner.DiscoverPendingDockerLifecycles(
		inspectionContext, journal, discoverer, runnerID,
	)
	closeErr := journal.Close()
	if discoveryErr != nil || closeErr != nil {
		return errors.Join(discoveryErr, closeErr)
	}

	report := recoveryReport{
		SchemaVersion: 1,
		Mode: "DRY_RUN",
		RunnerInstanceID: runnerID,
		CheckedAt: time.Now().UTC(),
		PendingCount: len(findings),
		Findings: make([]recoveryFinding, 0, len(findings)),
		DeletionPerformed: false,
	}
	for _, finding := range findings {
		report.Findings = append(report.Findings, recoveryFinding{
			LifecycleID: finding.Lifecycle.LifecycleID,
			ExecutionID: finding.Lifecycle.ExecutionID,
			ContainerID: finding.Lifecycle.ContainerID,
			Containers: finding.Containers,
			Assessment: finding.Assessment,
		})
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write recovery inspection report: %w", err)
	}
	return nil
}
