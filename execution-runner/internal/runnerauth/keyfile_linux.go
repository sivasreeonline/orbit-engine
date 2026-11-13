//go:build linux

package runnerauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// loadPrivateKeyFile accepts exactly a canonical base64 encoding of a
// 64-byte Ed25519 private key, followed by at most one LF newline.
func loadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	if path == "" || strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: path is required", ErrInvalidPrivateKeyFile)
	}

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect path: %v", ErrInvalidPrivateKeyFile, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: expected a regular non-symlink file", ErrInvalidPrivateKeyFile)
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open without following symlinks: %v", ErrInvalidPrivateKeyFile, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: open returned an invalid file descriptor", ErrInvalidPrivateKeyFile)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: inspect opened file: %v", ErrInvalidPrivateKeyFile, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		return nil, fmt.Errorf("%w: file changed while opening", ErrInvalidPrivateKeyFile)
	}
	permissions := info.Mode().Perm()
	if permissions&0o077 != 0 || permissions&0o100 != 0 || permissions&0o400 == 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, fmt.Errorf("%w: file must be owner-readable and have no group or other permissions", ErrInvalidPrivateKeyFile)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("%w: file must be owned by the runner user", ErrInvalidPrivateKeyFile)
	}
	if stat.Nlink != 1 {
		return nil, fmt.Errorf("%w: hard-linked key files are not accepted", ErrInvalidPrivateKeyFile)
	}
	if info.Size() != 88 && info.Size() != 89 {
		return nil, fmt.Errorf("%w: expected an 88-byte base64 key with an optional newline", ErrInvalidPrivateKeyFile)
	}

	contents, err := io.ReadAll(io.LimitReader(file, 90))
	if err != nil {
		return nil, fmt.Errorf("%w: read key file: %v", ErrInvalidPrivateKeyFile, err)
	}
	if len(contents) == 89 && contents[88] == '\n' {
		contents = contents[:88]
	}
	if len(contents) != 88 || bytes.ContainsAny(contents, " \t\r\n") {
		return nil, ErrInvalidPrivateKeyFile
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(contents))
	if err != nil || len(decoded) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(decoded) != string(contents) {
		return nil, ErrInvalidPrivateKeyFile
	}
	privateKey := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
	if !bytes.Equal(privateKey, decoded) {
		return nil, errors.Join(ErrInvalidPrivateKeyFile, errors.New("Ed25519 public key does not match the supplied seed"))
	}
	return privateKey, nil
}
