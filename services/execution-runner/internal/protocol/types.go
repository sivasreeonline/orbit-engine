package protocol

import "time"

type Action string

const (
	ActionRun    Action = "RUN"
	ActionSubmit Action = "SUBMIT"
)

type Language string

const (
	LanguageJava   Language = "java"
	LanguagePython Language = "python"
)

type ResourceLimits struct {
	CPUQuotaMillis int64 `json:"cpuQuotaMillis"`
	MemoryBytes    int64 `json:"memoryBytes"`
	WallTimeMillis int64 `json:"wallTimeMillis"`
	ProcessLimit   int64 `json:"processLimit"`
	OutputBytes    int64 `json:"outputBytes"`
}

// ExecutionRequest is an internal control-plane contract.
// Source code and hidden test contents are not embedded in this request.
// Artifact references must be opaque IDs resolved by an authenticated service.
type ExecutionRequest struct {
	ProtocolVersion  string         `json:"protocolVersion"`
	RequestID        string         `json:"requestId"`
	ExecutionID      string         `json:"executionId"`
	AttemptID        string         `json:"attemptId"`
	ProblemVersionID string         `json:"problemVersionId"`
	Action           Action         `json:"action"`
	Language         Language       `json:"language"`
	RuntimeVersion   string         `json:"runtimeVersion"`
	SourceArtifactID string         `json:"sourceArtifactId"`
	SourceSHA256     string         `json:"sourceSha256"`
	SourceByteLength int64          `json:"sourceByteLength"`
	TestBundleID     string         `json:"testBundleId"`
	TraceID          string         `json:"traceId"`
	IssuedAt         time.Time      `json:"issuedAt"`
	ExpiresAt        time.Time      `json:"expiresAt"`
	Limits           ResourceLimits `json:"limits"`
}
