package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidRequest = errors.New("invalid execution request")

const (
	maximumRequestSourceBytes = int64(200 * 1024)
	maximumFutureClockSkew    = 30 * time.Second
)

func (request ExecutionRequest) Validate() error {
	return request.ValidateAt(time.Now().UTC())
}

// ValidateAt allows deterministic validation tests while preserving the same
// expiry and clock-skew rules used by the live runner.
func (request ExecutionRequest) ValidateAt(now time.Time) error {
	if request.ProtocolVersion != "v1" {
		return fieldError("protocolVersion", "must be v1")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"requestId", request.RequestID},
		{"executionId", request.ExecutionID},
		{"attemptId", request.AttemptID},
		{"problemVersionId", request.ProblemVersionID},
		{"sourceArtifactId", request.SourceArtifactID},
		{"testBundleId", request.TestBundleID},
		{"traceId", request.TraceID},
	} {
		if err := validateOpaqueID(field.name, field.value); err != nil {
			return err
		}
	}

	if request.Action != ActionRun && request.Action != ActionSubmit {
		return fieldError("action", "must be RUN or SUBMIT")
	}
	if request.Language != LanguageJava && request.Language != LanguagePython {
		return fieldError("language", "must be java or python")
	}
	if !isBoundedToken(request.RuntimeVersion, 1, 32) {
		return fieldError("runtimeVersion", "must contain 1 to 32 non-whitespace characters")
	}

	digest, err := hex.DecodeString(request.SourceSHA256)
	if err != nil || len(digest) != 32 || request.SourceSHA256 != strings.ToLower(request.SourceSHA256) {
		return fieldError("sourceSha256", "must be a lowercase 64-character hexadecimal SHA-256 digest")
	}
	if request.SourceByteLength <= 0 || request.SourceByteLength > maximumRequestSourceBytes {
		return fieldError("sourceByteLength", "must be positive and within the runner source-size limit")
	}

	if request.IssuedAt.IsZero() || request.ExpiresAt.IsZero() {
		return fieldError("issuedAt/expiresAt", "must both be present")
	}
	_, issuedOffset := request.IssuedAt.Zone()
	_, expiresOffset := request.ExpiresAt.Zone()
	if issuedOffset != 0 || expiresOffset != 0 {
		return fieldError("issuedAt/expiresAt", "must use UTC")
	}
	if request.IssuedAt.After(now.Add(maximumFutureClockSkew)) {
		return fieldError("issuedAt", "is too far in the future")
	}
	if !request.ExpiresAt.After(request.IssuedAt) {
		return fieldError("expiresAt", "must be later than issuedAt")
	}
	if !request.ExpiresAt.After(now) {
		return fieldError("expiresAt", "request has expired")
	}

	if request.Limits.CPUQuotaMillis <= 0 {
		return fieldError("limits.cpuQuotaMillis", "must be positive")
	}
	if request.Limits.MemoryBytes <= 0 {
		return fieldError("limits.memoryBytes", "must be positive")
	}
	if request.Limits.WallTimeMillis <= 0 {
		return fieldError("limits.wallTimeMillis", "must be positive")
	}
	if request.Limits.ProcessLimit <= 0 {
		return fieldError("limits.processLimit", "must be positive")
	}
	if request.Limits.OutputBytes <= 0 {
		return fieldError("limits.outputBytes", "must be positive")
	}

	return nil
}

func validateOpaqueID(field string, value string) error {
	if !isBoundedToken(value, 1, 128) {
		return fieldError(field, "must contain 1 to 128 non-whitespace characters")
	}

	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '-' && character != '_' {
			return fieldError(field, "contains an unsupported character")
		}
	}

	return nil
}

func isBoundedToken(value string, minLength int, maxLength int) bool {
	trimmed := strings.TrimSpace(value)
	return len(trimmed) >= minLength && len(trimmed) <= maxLength && trimmed == value
}

func fieldError(field string, detail string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidRequest, field, detail)
}
