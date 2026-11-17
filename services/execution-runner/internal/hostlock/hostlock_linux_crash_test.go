//go:build linux

package hostlock

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	crashHelperPathEnv  = "SKYHIGH_HOSTLOCK_CRASH_HELPER_PATH"
	crashHelperOwnerEnv = "SKYHIGH_HOSTLOCK_CRASH_HELPER_OWNER"
)

// TestHostLockCrashHelper runs only as a subprocess of
// TestHostLockIsReleasedAfterAbruptProcessDeath.
func TestHostLockCrashHelper(t *testing.T) {
	path := os.Getenv(crashHelperPathEnv)
	ownerID := os.Getenv(crashHelperOwnerEnv)
	if path == "" || ownerID == "" {
		t.Skip("subprocess helper")
	}
	_, err := Acquire(path, ownerID)
	if err != nil {
		t.Fatalf("child could not acquire host lock: %v", err)
	}
	// Deliberately do not Close: the parent kills this process to model
	// SIGKILL/power-loss semantics where deferred cleanup cannot run.
	if _, err := fmt.Fprintln(os.Stdout, "HOSTLOCK_READY"); err != nil {
		t.Fatalf("signal lock readiness: %v", err)
	}
	select {}
}

func TestHostLockIsReleasedAfterAbruptProcessDeath(t *testing.T) {
	path := filepath.Join(privateLockDir(t), "runner-host.lock")
	firstOwner := strings.Repeat("d", 32)
	secondOwner := strings.Repeat("e", 32)

	command := exec.Command(os.Args[0], "-test.run=^TestHostLockCrashHelper$")
	command.Env = append(os.Environ(),
		crashHelperPathEnv+"="+path,
		crashHelperOwnerEnv+"="+firstOwner,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	childFinished := false
	defer func() {
		if !childFinished && command.Process != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "HOSTLOCK_READY" {
		t.Fatalf("child did not confirm lock ownership: line=%q err=%v stderr=%s", line, err, stderr.String())
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("child did not create persistent lock file: %v", err)
	}
	if _, err := Acquire(path, secondOwner); !errors.Is(err, ErrLocked) {
		t.Fatalf("concurrent parent acquisition error = %v, want ErrLocked", err)
	}

	if err := command.Process.Kill(); err != nil {
		t.Fatalf("kill lock-owning child: %v", err)
	}
	waitErr := command.Wait()
	childFinished = true
	if waitErr == nil {
		t.Fatal("killed child unexpectedly exited successfully")
	}

	// flock is kernel-owned: process death must release it even though
	// release metadata was never written and Lock.Close never ran.
	recovered, err := Acquire(path, secondOwner)
	if err != nil {
		t.Fatalf("host lock remained stuck after child death: %v", err)
	}
	defer recovered.Close()

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("host lock inode changed after crash recovery; persistent lock file must not be replaced")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata lockMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.RunnerInstanceID != secondOwner || metadata.PID != os.Getpid() || metadata.AcquiredAt.IsZero() || metadata.ReleasedAt != nil {
		t.Fatalf("recovered owner metadata = %+v", metadata)
	}
}
