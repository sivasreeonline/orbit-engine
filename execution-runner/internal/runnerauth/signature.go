package runnerauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var (
	ErrInvalidSignedRequest = errors.New("invalid signed runner request")
	keyIDPattern            = regexp.MustCompile("^[A-Za-z0-9._:-]{1,128}$")
	methodPattern           = regexp.MustCompile("^[A-Z]{3,10}$")
	timestampPattern        = regexp.MustCompile("^[1-9][0-9]{9}$")
	noncePattern            = regexp.MustCompile("^[A-Za-z0-9_-]{43}$")
)

const maxSignedBodyBytes = 256 * 1024

type SignedRequest struct {
	KeyID     string
	Method    string
	Path      string
	Timestamp string
	Nonce     string
	Body      []byte
}

func CanonicalMessage(request SignedRequest) ([]byte, error) {
	if !keyIDPattern.MatchString(request.KeyID) ||
		!methodPattern.MatchString(request.Method) ||
		!strings.HasPrefix(request.Path, "/") ||
		strings.IndexFunc(request.Path, unicode.IsSpace) >= 0 ||
		!timestampPattern.MatchString(request.Timestamp) ||
		!noncePattern.MatchString(request.Nonce) ||
		len(request.Body) > maxSignedBodyBytes {
		return nil, ErrInvalidSignedRequest
	}

	nonce, err := base64.RawURLEncoding.Strict().DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 {
		return nil, ErrInvalidSignedRequest
	}

	digest := sha256.Sum256(request.Body)
	canonical := strings.Join([]string{
		"SKYHIGH-RUNNER-REQUEST-V1",
		request.KeyID,
		request.Method,
		request.Path,
		request.Timestamp,
		request.Nonce,
		hex.EncodeToString(digest[:]),
	}, "\n")
	return []byte(canonical), nil
}

func SignRequest(privateKey ed25519.PrivateKey, request SignedRequest) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", ErrInvalidSignedRequest
	}
	message, err := CanonicalMessage(request)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, message)
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func VerifyRequest(publicKey ed25519.PublicKey, request SignedRequest, encodedSignature string) bool {
	if len(publicKey) != ed25519.PublicKeySize ||
		encodedSignature == "" || strings.Contains(encodedSignature, "=") {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	message, err := CanonicalMessage(request)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}
