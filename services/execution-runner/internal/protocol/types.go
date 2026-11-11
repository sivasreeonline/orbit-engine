package protocol

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

// ResourceLimits is protocol data, not execution authority. A future trusted host
// boundary must resolve and enforce immutable server-owned profile limits; it must
// never apply these values directly from an untrusted caller.
type ResourceLimits struct {
	CPUQuotaMillis int64 `json:"cpuQuotaMillis"`
	MemoryBytes    int64 `json:"memoryBytes"`
	WallTimeMillis int64 `json:"wallTimeMillis"`
	ProcessLimit   int64 `json:"processLimit"`
	OutputBytes    int64 `json:"outputBytes"`
}

// ExecutionRequest is an internal control-plane message, not a public API.
// Its runtimeVersion and limits fields are claims to validate against an approved
// server-owned profile, never instructions to select runtime or resource policy.
// Validate performs structural checks only; it does not authenticate the caller,
// authorize an attempt, resolve artifacts, or approve a profile.
// Source code and hidden test contents are not embedded in this request.
// Artifact references must be opaque IDs resolved by an authenticated service.
type ExecutionRequest struct {
	ProtocolVersion  string         `json:"protocolVersion"`
	ExecutionID      string         `json:"executionId"`
	AttemptID        string         `json:"attemptId"`
	ProblemVersionID string         `json:"problemVersionId"`
	Action           Action         `json:"action"`
	Language         Language       `json:"language"`
	RuntimeVersion   string         `json:"runtimeVersion"`
	SourceArtifactID string         `json:"sourceArtifactId"`
	SourceSHA256     string         `json:"sourceSha256"`
	TestBundleID     string         `json:"testBundleId"`
	Limits           ResourceLimits `json:"limits"`
}
