package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidV2Request = errors.New("invalid protocol v2 execution request")
	v2UUIDPattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
	v2UUIDv4Pattern = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
	v2DigestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	v2HexDigestPattern = regexp.MustCompile("^[0-9a-f]{64}$")
	v2CancelPattern = regexp.MustCompile("^cxl_[0-9a-f]{32}$")
	v2TestBundlePattern = regexp.MustCompile("^[A-Za-z0-9_-]{1,128}$")
)

type ResourceLimitsV2 struct {
	CPUQuotaMillis int64 `json:"cpuQuotaMillis"`
	MemoryBytes int64 `json:"memoryBytes"`
	WallTimeMillis int64 `json:"wallTimeMillis"`
	ProcessLimit int64 `json:"processLimit"`
	OutputBytes int64 `json:"outputBytes"`
	ScratchBytes int64 `json:"scratchBytes"`
	ScratchInodes int64 `json:"scratchInodes"`
}

type ExecutionRequestV2 struct {
	ProtocolVersion string `json:"protocolVersion"`
	CorrelationID string `json:"correlationId"`
	ExecutionID string `json:"executionId"`
	AttemptID string `json:"attemptId"`
	ProblemVersionID string `json:"problemVersionId"`
	Action Action `json:"action"`
	Language Language `json:"language"`
	RuntimeVersion string `json:"runtimeVersion"`
	RuntimeImageDigest string `json:"runtimeImageDigest"`
	SourceArtifactID string `json:"sourceArtifactId"`
	SourceSHA256 string `json:"sourceSha256"`
	TestBundleID string `json:"testBundleId"`
	ComparisonPolicy string `json:"comparisonPolicy"`
	DeadlineAt time.Time `json:"deadlineAt"`
	CancellationRef string `json:"cancellationRef"`
	Limits ResourceLimitsV2 `json:"limits"`
}

// DecodeV2Request verifies the digest over the exact transport bytes before
// strict decoding. Unknown, missing, duplicate, trailing and malformed JSON
// fields fail closed; no reserialization is used as the integrity input.
func DecodeV2Request(raw []byte, expectedSHA256 string, now time.Time) (ExecutionRequestV2, error) {
	var request ExecutionRequestV2
	if len(raw) == 0 || len(raw) > 16*1024 || !v2HexDigestPattern.MatchString(expectedSHA256) {
		return request, ErrInvalidV2Request
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expectedSHA256 {
		return request, fmt.Errorf("%w: request digest mismatch", ErrInvalidV2Request)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return request, fmt.Errorf("%w: duplicate or malformed JSON keys", ErrInvalidV2Request)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf("%w: %v", ErrInvalidV2Request, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return request, fmt.Errorf("%w: trailing JSON data", ErrInvalidV2Request)
	}
	if err := request.Validate(now); err != nil {
		return request, err
	}
	return request, nil
}

func (request ExecutionRequestV2) Validate(now time.Time) error {
	if request.ProtocolVersion != "v2" ||
		!v2UUIDv4Pattern.MatchString(request.CorrelationID) ||
		!v2UUIDPattern.MatchString(request.ExecutionID) ||
		!v2UUIDPattern.MatchString(request.AttemptID) ||
		!v2UUIDPattern.MatchString(request.ProblemVersionID) ||
		!v2UUIDPattern.MatchString(request.SourceArtifactID) {
		return ErrInvalidV2Request
	}
	if request.Action != ActionRun && request.Action != ActionSubmit {
		return ErrInvalidV2Request
	}
	if request.Language != LanguageJava && request.Language != LanguagePython {
		return ErrInvalidV2Request
	}
	if !isBoundedToken(request.RuntimeVersion, 1, 32) ||
		!v2DigestPattern.MatchString(request.RuntimeImageDigest) ||
		!v2HexDigestPattern.MatchString(request.SourceSHA256) ||
		!v2TestBundlePattern.MatchString(request.TestBundleID) ||
		request.ComparisonPolicy != "EXACT_BYTES" ||
		!v2CancelPattern.MatchString(request.CancellationRef) {
		return ErrInvalidV2Request
	}
	if request.DeadlineAt.IsZero() || !request.DeadlineAt.After(now) ||
		request.DeadlineAt.After(now.Add(10*time.Minute)) {
		return ErrInvalidV2Request
	}
	limits := request.Limits
	if limits.CPUQuotaMillis <= 0 || limits.MemoryBytes <= 0 ||
		limits.WallTimeMillis <= 0 || limits.WallTimeMillis > 600000 ||
		limits.ProcessLimit <= 0 || limits.OutputBytes <= 0 ||
		limits.ScratchBytes <= 0 || limits.ScratchBytes > 512*1024*1024 ||
		limits.ScratchInodes <= 0 || limits.ScratchInodes > 8192 {
		return ErrInvalidV2Request
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil { return err }
	delim, ok := token.(json.Delim)
	if !ok { return nil }
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil { return err }
			key, ok := keyToken.(string)
			if !ok { return errors.New("object key is not a string") }
			if _, exists := seen[key]; exists { return errors.New("duplicate object key") }
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil { return err }
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') { return errors.New("unterminated object") }
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil { return err }
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') { return errors.New("unterminated array") }
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}

// Keep strings in request metadata bounded and whitespace-canonical.
func isV2CanonicalText(value string, max int) bool {
	return len(value) > 0 && len(value) <= max && strings.TrimSpace(value) == value
}
