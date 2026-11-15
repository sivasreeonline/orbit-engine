//go:build linux

package hostlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var ownerIDPattern = regexp.MustCompile("^[a-f0-9]{32}$")

type lockMetadata struct {
	PID int `json:"pid"`
	RunnerInstanceID string `json:"runnerInstanceId"`
	AcquiredAt time.Time `json:"acquiredAt"`
	ReleasedAt *time.Time `json:"releasedAt,omitempty"`
}

func acquirePlatformLock(path, ownerID string) (*Lock, error) {
	if !ownerIDPattern.MatchString(ownerID) {
		return nil, errors.New("host lock owner ID must be 32 lowercase hexadecimal characters")
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, errors.New("host lock path must be an absolute non-root path")
	}
	canonical, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve host lock path: %w", err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(canonical))
	if err != nil {
		return nil, fmt.Errorf("resolve host lock directory: %w", err)
	}
	canonical = filepath.Join(directory, filepath.Base(canonical))

	before, beforeErr := os.Lstat(canonical)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect host lock path: %w", beforeErr)
	}
	if beforeErr == nil && (before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular()) {
		return nil, errors.New("host lock must be a regular non-symlink file")
	}

	fd, err := syscall.Open(canonical, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open host lock without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), canonical)
	fail := func(cause error) (*Lock, error) {
		_ = file.Close()
		return nil, cause
	}
	info, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat host lock: %w", err))
	}
	current, err := os.Lstat(canonical)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(info, current) || (beforeErr == nil && !os.SameFile(before, info)) {
		return fail(errors.New("host lock path changed during open"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fail(errors.New("host lock permissions must exclude group and other access"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return fail(errors.New("host lock must be owned by the runner user and have exactly one hard link"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fail(fmt.Errorf("%w: %s", ErrLocked, canonical))
		}
		return fail(fmt.Errorf("acquire kernel host lock: %w", err))
	}
	lock := &Lock{file: file, ownerID: ownerID}
	if err := writeMetadata(file, lockMetadata{
		PID: os.Getpid(), RunnerInstanceID: ownerID, AcquiredAt: time.Now().UTC(),
	}); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return fail(fmt.Errorf("persist host lock owner metadata: %w", err))
	}
	return lock, nil
}

func writeMetadata(file *os.File, metadata lockMetadata) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	written, err := file.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return errors.New("short write of host lock metadata")
	}
	return file.Sync()
}

func releasePlatformLock(file *os.File, ownerID string) error {
	var metadata lockMetadata
	_, seekErr := file.Seek(0, 0)
	payload, readErr := io.ReadAll(file)
	if seekErr == nil && readErr == nil {
		readErr = json.Unmarshal(payload, &metadata)
	}
	if readErr == nil && metadata.RunnerInstanceID != ownerID {
		readErr = errors.New("host lock owner metadata changed while held")
	}
	var writeErr error
	if seekErr == nil && readErr == nil {
		metadata.PID = os.Getpid()
		metadata.ReleasedAt = ptrTime(time.Now().UTC())
		writeErr = writeMetadata(file, metadata)
	}
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	return errors.Join(seekErr, readErr, writeErr, unlockErr, closeErr)
}

func ptrTime(value time.Time) *time.Time { return &value }
