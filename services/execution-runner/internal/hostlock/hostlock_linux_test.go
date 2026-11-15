//go:build linux

package hostlock

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func privateLockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestHostLockExcludesConcurrentOwnersAndPersistsReleaseMetadata(t *testing.T) {
	path := filepath.Join(privateLockDir(t), "runner-host.lock")
	ownerID := strings.Repeat("a", 32)
	lock, err := Acquire(path, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path, strings.Repeat("b", 32)); !errors.Is(err, ErrLocked) {
		t.Fatalf("second owner error = %v, want ErrLocked", err)
	}

	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("host lock file was removed instead of retained: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("host lock permissions = %o, want owner-only", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata lockMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.RunnerInstanceID != ownerID || metadata.ReleasedAt == nil || metadata.ReleasedAt.IsZero() {
		t.Fatalf("release metadata = %+v", metadata)
	}

	next, err := Acquire(path, strings.Repeat("b", 32))
	if err != nil {
		t.Fatalf("kernel lock was not released: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostLockRejectsInvalidOwnerPathSymlinkAndPermissiveFile(t *testing.T) {
	dir := privateLockDir(t)
	if _, err := Acquire(filepath.Join(dir, "lock"), "not-an-id"); err == nil {
		t.Fatal("invalid owner ID was accepted")
	}
	if _, err := Acquire("relative.lock", strings.Repeat("a", 32)); err == nil {
		t.Fatal("relative host lock path was accepted")
	}

	target := filepath.Join(dir, "target.lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Acquire(link, strings.Repeat("a", 32)); err == nil {
			t.Fatal("symlinked host lock was accepted")
		}
	}

	permissive := filepath.Join(dir, "permissive.lock")
	if err := os.WriteFile(permissive, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(permissive, strings.Repeat("a", 32)); err == nil {
		t.Fatal("group/other-readable host lock was accepted")
	}
}

func TestHostLockCloseIsIdempotent(t *testing.T) {
	lock, err := Acquire(filepath.Join(privateLockDir(t), "runner-host.lock"), strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	_ = time.Now()
}
