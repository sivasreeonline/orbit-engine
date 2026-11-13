package runnerclient

import (
	"crypto/ed25519"
	"testing"
)

func TestCloseZeroesSigningKey(t *testing.T) {
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for index := range key {
		key[index] = byte(index + 1)
	}
	client := &Client{privateKey: append(ed25519.PrivateKey(nil), key...)}
	ownedKey := client.privateKey

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	for index, value := range ownedKey {
		if value != 0 {
			t.Fatalf("private key byte %d was not zeroed", index)
		}
	}
	if client.privateKey != nil {
		t.Fatal("private key reference should be cleared")
	}
}
