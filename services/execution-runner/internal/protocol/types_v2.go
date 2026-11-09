package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProtocolVersionV2       = "v2"
	ComparisonExactBytes    = "EXACT_BYTES"
	MaxExecutionBudget      = 10 * time.Minute
	DefaultScratchBytes     = int64(256 * 1024 * 1024)
	MaxScratchBytes         = int64(512 * 1024 * 1024)
	DefaultScratchInodes    = int64(4096)
	MaxScratchInodes        = int64(8192)
)

type ResourceLimitsV2 struct {
	CPUQuotaMillis int64 `json:"cpuQuotaMillis"`
	MemoryBytes    int64 `json:"memoryBytes"`
	WallTimeMillis int64 `json:"wallTimeMillis"`
	ProcessLimit   int64 `json:"processLimit"`
	OutputBytes    int64 `json:"outputBytes"`
	ScratchBytes   int64 `json:"scratchBytes"`
	ScratchInodes  int64 `json:"scratchInodes"`
}

// ExecutionRequestV2 is the complete, versioned control-plane-to-runner request.
// It carries references and trusted policy only; source and hidden test contents
// must never be embedded in this message.
type ExecutionRequestV2 struct {
	ProtocolVersion   string           `json:"protocolVersion"`
	CorrelationID     string           `json:"correlationId"`
	ExecutionID       string           `json:"executionId"`
	AttemptID         string           `json:"attemptId"`
	ProblemVersionID  string           `json:"problemVersionId"`
	Action             Action           `json:"action"`
	Language           Language         `json:"language"`
	RuntimeVersion     string           `json:"runtimeVersion"`
	RuntimeImageDigest string           `json:"runtimeImageDigest"`
	SourceArtifactID   string           `json:"sourceArtifactId"`
	SourceSHA256       string           `json:"sourceSha256"`
	TestBundleID       string           `json:"testBundleId"`
	ComparisonPolicy   string           `json:"comparisonPolicy"`
	DeadlineAt         string           `json:"deadlineAt"`
	CancellationRef    string           `json:"cancellationRef"`
	Limits             ResourceLimitsV2 `json:"limits"`
}

func (request ExecutionRequestV2) Validate() error {
	return request.ValidateAt(time.Now().UTC())
}

// ValidateAt is exposed for deterministic boundary tests and replay validation.
// The caller must pass a trusted current time; the runner uses a monotonic timer
// separately once execution starts.
func (request ExecutionRequestV2) ValidateAt(now time.Time) error {
	if request.ProtocolVersion != ProtocolVersionV2 {
		return fieldError("protocolVersion", "must be v2")
	}
	if !isCanonicalUUID(request.CorrelationID) {
		return fieldError("correlationId", "must be a canonical lowercase UUID")
	}
	for field, value := range map[string]string{
		"executionId": request.ExecutionID,
		"attemptId": request.AttemptID,
		"problemVersionId": request.ProblemVersionID,
		"sourceArtifactId": request.SourceArtifactID,
		"testBundleId": request.TestBundleID,
	} {
		if err := validateOpaqueID(field, value); err != nil {
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
	if !isSHA256Digest(request.RuntimeImageDigest, true) {
		return fieldError("runtimeImageDigest", "must be a lowercase sha256 OCI digest")
	}
	if !isSHA256Digest(request.SourceSHA256, false) {
		return fieldError("sourceSha256", "must be a lowercase 64-character SHA-256 digest")
	}
	if request.ComparisonPolicy != ComparisonExactBytes {
		return fieldError("comparisonPolicy", "must be EXACT_BYTES")
	}
	if !isCancellationRef(request.CancellationRef) {
		return fieldError("cancellationRef", "must be cxl_ followed by 128 bits of lowercase hexadecimal entropy")
	}

	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !strings.HasSuffix(request.DeadlineAt, "Z") ||
		(deadline.Format(time.RFC3339Nano) != request.DeadlineAt) {
		return fieldError("deadlineAt", "must be a canonical RFC3339 UTC timestamp")
	}
	if !deadline.After(now) {
		return fieldError("deadlineAt", "must be in the future; expired requests must not start")
	}
	if deadline.After(now.Add(MaxExecutionBudget)) {
		return fieldError("deadlineAt", "must not exceed the 10-minute end-to-end request budget")
	}

	limits := request.Limits
	if limits.CPUQuotaMillis <= 0 {
		return fieldError("limits.cpuQuotaMillis", "must be positive")
	}
	if limits.MemoryBytes <= 0 {
		return fieldError("limits.memoryBytes", "must be positive")
	}
	if limits.WallTimeMillis <= 0 {
		return fieldError("limits.wallTimeMillis", "must be positive")
	}
	if limits.ProcessLimit <= 0 {
		return fieldError("limits.processLimit", "must be positive")
	}
	if limits.OutputBytes <= 0 {
		return fieldError("limits.outputBytes", "must be positive")
	}
	if limits.ScratchBytes <= 0 || limits.ScratchBytes > MaxScratchBytes {
		return fieldError("limits.scratchBytes", "must be between 1 byte and 512 MiB")
	}
	if limits.ScratchInodes <= 0 || limits.ScratchInodes > MaxScratchInodes {
		return fieldError("limits.scratchInodes", "must be between 1 and 8192")
	}
	return nil
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || strings.ToLower(value) != value {
		return false
	}
	for index, character := range value {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}

func isSHA256Digest(value string, withPrefix bool) bool {
	if withPrefix {
		if !strings.HasPrefix(value, "sha256:") {
			return false
		}
		value = strings.TrimPrefix(value, "sha256:")
	}
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func isCancellationRef(value string) bool {
	if !strings.HasPrefix(value, "cxl_") || len(value) != 36 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "cxl_"))
	return err == nil && len(decoded) == 16 && strings.ToLower(value) == value
}

var _ = errors.Is
var _ = fmt.Sprintf
