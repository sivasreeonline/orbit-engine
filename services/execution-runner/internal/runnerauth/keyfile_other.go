//go:build !linux

package runnerauth

import "crypto/ed25519"

func loadPrivateKeyFile(_ string) (ed25519.PrivateKey, error) {
	return nil, ErrPrivateKeyFileUnsupported
}
