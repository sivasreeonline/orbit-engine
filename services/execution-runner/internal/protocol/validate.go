package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidRequest = errors.New("invalid execution request")

// Validate checks protocol shape and basic field bounds only. It does not
// authorize the request or establish that runtime/resource values match a
// server-owned profile; callers must perform those checks at the trusted boundary.
func (request ExecutionRequest) Validate() error {
	if request.ProtocolVersion != "v1" {
		return fieldError("protocolVersion", "must be v1")
	}
	if err := validateOpaqueID("executionId", request.ExecutionID); err != nil {
		return err
	}
	if err := validateOpaqueID("attemptId", request.AttemptID); err != nil {
		return err
	}
	if err := validateOpaqueID("problemVersionId", request.ProblemVersionID); err != nil {
		return err
	}
	if err := validateOpaqueID("sourceArtifactId", request.SourceArtifactID); err != nil {
		return err
	}
	if err := validateOpaqueID("testBundleId", request.TestBundleID); err != nil {
		return err
	}

	if request.Action != ActionRun && request.Action != ActionSubmit {
		return fieldError("action", "must be RUN or SUBMIT")
	}
	if request.Language != LanguageJava && request.Language != LanguagePython {
		return fieldError("language", "must be java or python")
	}
	if !isRuntimeVersionToken(request.RuntimeVersion) {
		return fieldError("runtimeVersion", "must contain 1 to 32 ASCII letters, digits, dots, hyphens, underscores or plus signs")
	}

	digest, err := hex.DecodeString(request.SourceSHA256)
	if err != nil || len(digest) != 32 || request.SourceSHA256 != strings.ToLower(request.SourceSHA256) {
		return fieldError("sourceSha256", "must be a 64-character lowercase hexadecimal SHA-256 digest")
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

func isRuntimeVersionToken(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') &&
			character != '.' && character != '-' && character != '_' && character != '+' {
			return false
		}
	}
	return true
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
