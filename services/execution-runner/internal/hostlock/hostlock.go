// Package hostlock provides a kernel-enforced exclusive lock shared by all
// Sky High runner processes configured with the same host lock path.
package hostlock

import (
	"errors"
	"os"
	"sync"
)

var (
	ErrLocked = errors.New("Sky High runner host lock is already held")
	ErrUnsupported = errors.New("host ownership locking is supported only on Linux")
)

// Lock remains open for the full protected process lifetime. The lock file is
// intentionally persistent; deleting it while a process holds the inode can
// create split-brain ownership.
type Lock struct {
	mu sync.Mutex
	file *os.File
	ownerID string
}

// Acquire takes a non-blocking exclusive host lock and records only the runner
// installation ID and process metadata. ownerID must be a stable opaque ID.
func Acquire(path, ownerID string) (*Lock, error) {
	return acquirePlatformLock(path, ownerID)
}

// Close records release metadata, releases the kernel lock, and closes the
// descriptor. It never removes the lock file.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	return releasePlatformLock(file, lock.ownerID)
}
