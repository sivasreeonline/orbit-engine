package main

import (
	"bytes"
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

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/hostlock"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runner"
	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/sandboxjournal"
)

var runnerIDPattern = regexp.MustCompile("^[a-f0-9]{32}$")

type environment func(string) (string, bool)

const maxRecoveryReportBytes = 8 << 20

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
) (returnErr error) {
	if ctx == nil {
		return errors.New("recovery inspection context is required")
	}
	if lookup == nil || discoverer == nil || output == nil {
		return errors.New("recovery inspection dependencies are required")
	}
	// Start the deadline before lock acquisition and filesystem inspection so
	// setup time is part of the same bounded recovery operation.
	inspectionContext, cancelInspection := context.WithTimeout(ctx, 30*time.Second)
	defer cancelInspection()
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
	}
	runnerID, ok := lookup("RUNNER_INSTANCE_ID")
	if !ok || !runnerIDPattern.MatchString(runnerID) {
		return errors.New("RUNNER_INSTANCE_ID must be 32 lowercase hexadecimal characters")
	}
	hostLockPath, ok := lookup("RUNNER_HOST_LOCK_PATH")
	if !ok || hostLockPath == "" || !filepath.IsAbs(hostLockPath) ||
		filepath.Clean(hostLockPath) == string(filepath.Separator) {
		return errors.New("RUNNER_HOST_LOCK_PATH must be an absolute non-root path")
	}
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
	}
	hostOwnershipLock, err := hostlock.Acquire(hostLockPath, runnerID)
	if err != nil {
		return fmt.Errorf("acquire exclusive host ownership lock: %w", err)
	}
	defer func() {
		if err := hostOwnershipLock.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release host ownership lock: %w", err))
		}
	}()
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
	}

	journalPath, ok := lookup("RUNNER_SANDBOX_JOURNAL_PATH")
	if !ok || journalPath == "" || !filepath.IsAbs(journalPath) ||
		filepath.Clean(journalPath) == string(filepath.Separator) {
		return errors.New("RUNNER_SANDBOX_JOURNAL_PATH must be an absolute non-root path")
	}
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
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
	if err := inspectionContext.Err(); err != nil {
		return errors.Join(fmt.Errorf("recovery inspection deadline: %w", err), journal.Close())
	}
	findings, discoveryErr := runner.DiscoverPendingDockerLifecycles(
		inspectionContext, journal, discoverer, runnerID,
	)
	closeErr := journal.Close()
	if deadlineErr := inspectionContext.Err(); deadlineErr != nil {
		return errors.Join(fmt.Errorf("recovery inspection deadline: %w", deadlineErr), discoveryErr, closeErr)
	}
	if discoveryErr != nil || closeErr != nil {
		return errors.Join(discoveryErr, closeErr)
	}

	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
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
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode recovery inspection report: %w", err)
	}
	payload = append(payload, '\n')
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
	}
	if len(payload) > maxRecoveryReportBytes {
		return errors.New("recovery inspection report exceeds output safety limit")
	}
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline: %w", err)
	}
	if _, err := io.Copy(output, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("write recovery inspection report: %w", err)
	}
	if err := inspectionContext.Err(); err != nil {
		return fmt.Errorf("recovery inspection deadline after report write: %w", err)
	}
	return nil
}
