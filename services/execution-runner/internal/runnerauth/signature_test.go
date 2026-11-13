package runnerauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type sharedFixture struct {
	KeyID              string `json:"keyId"`
	Method             string `json:"method"`
	Path               string `json:"path"`
	Timestamp          string `json:"timestamp"`
	Nonce              string `json:"nonce"`
	BodyUTF8           string `json:"bodyUtf8"`
	BodySHA256         string `json:"bodySha256"`
	CanonicalUTF8      string `json:"canonicalUtf8"`
	PublicKeyBase64URL string `json:"publicKeyBase64Url"`
	SignatureBase64URL string `json:"signatureBase64Url"`
}

func loadSharedFixture(t *testing.T) sharedFixture {
	t.Helper()
	contents, err := os.ReadFile("../../../../test-fixtures/runner-ed25519-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sharedFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func requestFromFixture(fixture sharedFixture) SignedRequest {
	return SignedRequest{
		KeyID: fixture.KeyID, Method: fixture.Method, Path: fixture.Path,
		Timestamp: fixture.Timestamp, Nonce: fixture.Nonce,
		Body: []byte(fixture.BodyUTF8),
	}
}

func TestSharedWorkerVectorCanonicalizationAndVerification(t *testing.T) {
	fixture := loadSharedFixture(t)
	request := requestFromFixture(fixture)

	message, err := CanonicalMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	if string(message) != fixture.CanonicalUTF8 {
		t.Fatalf("canonical message mismatch\nwant: %q\n got: %q", fixture.CanonicalUTF8, message)
	}

	digest := sha256Sum([]byte(fixture.BodyUTF8))
	if digest != fixture.BodySHA256 {
		t.Fatalf("body digest mismatch: want %s, got %s", fixture.BodySHA256, digest)
	}

	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(fixture.PublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRequest(ed25519.PublicKey(publicKeyBytes), request, fixture.SignatureBase64URL) {
		t.Fatal("Go did not verify the shared Web Crypto signature vector")
	}
}

func TestGoSignatureMatchesSharedWorkerVector(t *testing.T) {
	fixture := loadSharedFixture(t)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)

	signature, err := SignRequest(privateKey, requestFromFixture(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if signature != fixture.SignatureBase64URL {
		t.Fatalf("signature mismatch: want %s, got %s", fixture.SignatureBase64URL, signature)
	}
}

func TestSignatureBindsEveryRequestFieldAndBody(t *testing.T) {
	fixture := loadSharedFixture(t)
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(fixture.PublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.PublicKey(publicKeyBytes)
	original := requestFromFixture(fixture)

	if !VerifyRequest(publicKey, original, fixture.SignatureBase64URL) {
		t.Fatal("expected fixture signature to verify")
	}

	mutations := []func(*SignedRequest){
		func(request *SignedRequest) { request.KeyID = "runner-other-key" },
		func(request *SignedRequest) { request.Method = "GET" },
		func(request *SignedRequest) { request.Path += "?other=1" },
		func(request *SignedRequest) { request.Timestamp = "1794535201" },
		func(request *SignedRequest) { request.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		func(request *SignedRequest) { request.Body = []byte("{\"requestedSlots\":2}") },
	}
	for index, mutate := range mutations {
		candidate := original
		candidate.Body = append([]byte(nil), original.Body...)
		mutate(&candidate)
		if VerifyRequest(publicKey, candidate, fixture.SignatureBase64URL) {
			t.Fatalf("mutation %d unexpectedly verified", index)
		}
	}
}

func TestRejectsMalformedKeysSignaturesAndRequestFields(t *testing.T) {
	fixture := loadSharedFixture(t)
	request := requestFromFixture(fixture)
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)

	if VerifyRequest(publicKey[:31], request, fixture.SignatureBase64URL) {
		t.Fatal("accepted a short public key")
	}
	if VerifyRequest(publicKey, request, "bad") {
		t.Fatal("accepted a malformed signature")
	}
	request.Nonce = "bad"
	if _, err := CanonicalMessage(request); err == nil {
		t.Fatal("accepted malformed nonce")
	}
	request.Nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
	if _, err := CanonicalMessage(request); err == nil {
		t.Fatal("accepted non-canonical base64url nonce")
	}
}

func sha256Sum(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
