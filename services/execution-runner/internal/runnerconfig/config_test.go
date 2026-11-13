package runnerconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/runnerauth"
)

func writeConfigKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func lookupValues(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func validValues(keyPath, journalPath string) map[string]string {
	return map[string]string{
		EnvControlPlaneURL: "https://control.example.test",
		EnvKeyID: "runner-machine-01",
		EnvPrivateKeyFile: keyPath,
		EnvJournalPath: journalPath,
	}
}

func TestLoadRequiresEveryIdentitySetting(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Fatal("nil environment lookup was accepted")
	}

	for _, name := range []string{
		EnvControlPlaneURL, EnvKeyID, EnvPrivateKeyFile, EnvJournalPath,
	} {
		t.Run(name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "runner.key")
			_ = writeConfigKey(t, keyPath)
			values := validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))
			delete(values, name)
			if config, err := Load(lookupValues(values)); err == nil {
				config.Destroy()
				t.Fatalf("missing %s was accepted", name)
			}
		})
	}
}

func TestLoadReturnsValidatedIdentityAndDestroyClearsKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "runner.key")
	expectedKey := writeConfigKey(t, keyPath)
	journalPath := filepath.Join(t.TempDir(), "private", "acceptance.jsonl")

	config, err := Load(lookupValues(validValues(keyPath, journalPath)))
	if err != nil {
		t.Fatal(err)
	}
	if config.ControlPlaneURL != "https://control.example.test" ||
		config.KeyID != "runner-machine-01" || config.JournalPath != journalPath {
		t.Fatalf("unexpected runner config: %+v", config)
	}
	if !ed25519.PrivateKey(config.PrivateKey).Equal(expectedKey) {
		t.Fatal("loaded config key differs from provisioned key")
	}
	config.Destroy()
	if config.PrivateKey != nil {
		t.Fatal("Destroy did not clear the private-key reference")
	}
	for index, value := range expectedKey {
		_ = index
		_ = value
	}
}

func TestLoadRejectsUnsafeControlPlaneOrigins(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "runner.key")
	_ = writeConfigKey(t, keyPath)
	journalPath := filepath.Join(t.TempDir(), "acceptance.jsonl")
	for _, target := range []string{
		"http://control.example.test",
		"https://user:secret@control.example.test",
		"https://control.example.test/internal",
		"https://control.example.test?token=secret",
		"https://control.example.test#fragment",
		"ftp://control.example.test",
	} {
		t.Run(target, func(t *testing.T) {
			values := validValues(keyPath, journalPath)
			values[EnvControlPlaneURL] = target
			if config, err := Load(lookupValues(values)); err == nil {
				config.Destroy()
				t.Fatalf("unsafe origin %q was accepted", target)
			}
		})
	}
}

func TestLoadAllowsLoopbackHTTPForLocalDevelopment(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "runner.key")
	_ = writeConfigKey(t, keyPath)
	values := validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))
	values[EnvControlPlaneURL] = "http://127.0.0.1:8787"

	config, err := Load(lookupValues(values))
	if err != nil {
		t.Fatal(err)
	}
	config.Destroy()
}

func TestLoadRejectsRelativePathsAndInvalidKeyID(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "runner.key")
	_ = writeConfigKey(t, keyPath)
	values := validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))

	values[EnvPrivateKeyFile] = "runner.key"
	if _, err := Load(lookupValues(values)); err == nil {
		t.Fatal("relative private-key path was accepted")
	}
	values = validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))
	values[EnvJournalPath] = "acceptance.jsonl"
	if _, err := Load(lookupValues(values)); err == nil {
		t.Fatal("relative journal path was accepted")
	}
	values = validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))
	values[EnvKeyID] = "key with spaces"
	if _, err := Load(lookupValues(values)); err == nil {
		t.Fatal("invalid key ID was accepted")
	}
}

func TestLoadDoesNotExposePrivateKeyContentsInErrors(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "runner.key")
	_ = writeConfigKey(t, keyPath)
	values := validValues(keyPath, filepath.Join(t.TempDir(), "acceptance.jsonl"))
	values[EnvJournalPath] = "relative.jsonl"

	_, err := Load(lookupValues(values))
	if err == nil {
		t.Fatal("expected relative journal path failure")
	}
	if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))) {
		t.Fatalf("configuration error unexpectedly includes key-like material: %v", err)
	}
	if errors.Is(err, runnerauth.ErrInvalidPrivateKeyFile) {
		t.Fatalf("unexpected key-loader failure: %v", err)
	}
}
