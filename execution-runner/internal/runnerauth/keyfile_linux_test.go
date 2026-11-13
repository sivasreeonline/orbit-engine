//go:build linux

package runnerauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeTestPrivateKey(t *testing.T, path string, key ed25519.PrivateKey, mode os.FileMode) {
	t.Helper()
	contents := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPrivateKeyFileValidatesAndReturnsEd25519Key(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runner.key")
	writeTestPrivateKey(t, path, privateKey, 0o600)

	loaded, err := LoadPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, privateKey) {
		t.Fatal("loaded private key does not match the generated key")
	}
	if !bytes.Equal(loaded.Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("loaded private key derived a different public key")
	}
}

func TestLoadPrivateKeyFileAcceptsOwnerReadOnlyPermissions(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runner.key")
	writeTestPrivateKey(t, path, privateKey, 0o400)

	if _, err := LoadPrivateKeyFile(path); err != nil {
		t.Fatalf("owner-read-only key file was rejected: %v", err)
	}
}

func TestLoadPrivateKeyFileRejectsWeakPermissionsAndSymlinks(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "runner.key")
	writeTestPrivateKey(t, path, privateKey, 0o644)

	if _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrInvalidPrivateKeyFile) {
		t.Fatalf("world-readable key file was accepted: %v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "runner-key-link")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Skipf("symlink creation is not available: %v", err)
	}
	if _, err := LoadPrivateKeyFile(symlinkPath); !errors.Is(err, ErrInvalidPrivateKeyFile) {
		t.Fatalf("symlink key path was accepted: %v", err)
	}
}

func TestLoadPrivateKeyFileRejectsHardLinks(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "runner.key")
	writeTestPrivateKey(t, path, privateKey, 0o600)
	if err := os.Link(path, filepath.Join(directory, "runner-key-copy")); err != nil {
		t.Skipf("hard link creation is not available: %v", err)
	}

	if _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrInvalidPrivateKeyFile) {
		t.Fatalf("hard-linked key file was accepted: %v", err)
	}
}

func TestLoadPrivateKeyFileRejectsMalformedAndMismatchedKeys(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runner.key")
	if err := os.WriteFile(path, []byte("not-base64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrInvalidPrivateKeyFile) {
		t.Fatalf("malformed key file was accepted: %v", err)
	}

	mismatched := append(ed25519.PrivateKey(nil), privateKey...)
	mismatched[len(mismatched)-1] ^= 0xff
	writeTestPrivateKey(t, path, mismatched, 0o600)
	if _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrInvalidPrivateKeyFile) {
		t.Fatalf("private key with mismatched public half was accepted: %v", err)
	}
}
