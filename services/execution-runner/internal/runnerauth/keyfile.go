package runnerauth

import (
	"crypto/ed25519"
	"errors"
)

var (
	ErrInvalidPrivateKeyFile     = errors.New("invalid or insecure runner private key file")
	ErrPrivateKeyFileUnsupported = errors.New("secure runner private-key file loading is supported only on Linux")
)

// LoadPrivateKeyFile loads a base64-encoded 64-byte Ed25519 private key from a
// protected file. The Linux implementation verifies file type, ownership,
// permissions, link count and key consistency before returning key material.
// Non-Linux builds fail closed rather than silently weakening those checks.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	return loadPrivateKeyFile(path)
}
