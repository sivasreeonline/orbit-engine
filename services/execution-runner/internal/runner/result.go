package runner

import "time"

type InfrastructureStatus string

const (
	InfrastructureSucceeded InfrastructureStatus = "SUCCEEDED"
	InfrastructureFailed    InfrastructureStatus = "FAILED"
)

type CompilationStatus string

const (
	CompilationNotStarted CompilationStatus = "NOT_STARTED"
	CompilationSucceeded  CompilationStatus = "SUCCEEDED"
	CompilationFailed     CompilationStatus = "FAILED"
)

type Verdict string

const (
	VerdictNotEvaluated      Verdict = "NOT_EVALUATED"
	VerdictAccepted          Verdict = "ACCEPTED"
	VerdictWrongAnswer       Verdict = "WRONG_ANSWER"
	VerdictCompilationError  Verdict = "COMPILATION_ERROR"
	VerdictRuntimeError      Verdict = "RUNTIME_ERROR"
	VerdictTimeLimitExceeded Verdict = "TIME_LIMIT_EXCEEDED"
	VerdictMemoryLimitExceeded Verdict = "MEMORY_LIMIT_EXCEEDED"
	VerdictOutputLimitExceeded Verdict = "OUTPUT_LIMIT_EXCEEDED"
	VerdictInternalError     Verdict = "INTERNAL_ERROR"
)

type CleanupStatus string

const (
	CleanupSucceeded CleanupStatus = "SUCCEEDED"
	CleanupFailed    CleanupStatus = "FAILED"
	CleanupUnknown   CleanupStatus = "UNKNOWN"
)

type PublicTestStatus string

const (
	PublicTestPassed PublicTestStatus = "PASSED"
	PublicTestFailed PublicTestStatus = "FAILED"
	PublicTestRuntimeError PublicTestStatus = "RUNTIME_ERROR"
	PublicTestTimeLimitExceeded PublicTestStatus = "TIME_LIMIT_EXCEEDED"
	PublicTestMemoryLimitExceeded PublicTestStatus = "MEMORY_LIMIT_EXCEEDED"
	PublicTestOutputLimitExceeded PublicTestStatus = "OUTPUT_LIMIT_EXCEEDED"
)

type PublicTestResult struct {
	CaseID        string           `json:"caseId"`
	Status        PublicTestStatus `json:"status"`
	StandardOutput []byte           `json:"standardOutput,omitempty"`
	StandardError  []byte           `json:"standardError,omitempty"`
	ElapsedMillis int64            `json:"elapsedMillis"`
}

// Result contains deterministic execution evidence. Public test output is
// included only for PUBLIC cases; hidden case inputs, outputs and identifiers
// never leave the test-bundle resolver/runner boundary.
type Result struct {
	ExecutionID             string               `json:"executionId"`
	SourceSHA256             string               `json:"sourceSha256"`
	InfrastructureStatus    InfrastructureStatus `json:"infrastructureStatus"`
	InfrastructureErrorCode string               `json:"infrastructureErrorCode,omitempty"`
	CompilationStatus       CompilationStatus    `json:"compilationStatus"`
	Verdict                 Verdict               `json:"verdict"`
	CleanupStatus           CleanupStatus         `json:"cleanupStatus"`
	TestsTotal              int                  `json:"testsTotal"`
	TestsPassed             int                  `json:"testsPassed"`
	ElapsedMillis           int64                `json:"elapsedMillis"`
	PeakMemoryBytes         *int64               `json:"peakMemoryBytes,omitempty"`
	RunnerVersion           string               `json:"runnerVersion"`
	RuntimeImageDigest      string               `json:"runtimeImageDigest"`
	StartedAt               time.Time            `json:"startedAt"`
	CompletedAt             time.Time            `json:"completedAt"`
	CompilationOutput       []byte               `json:"compilationOutput,omitempty"`
	PublicTestResults       []PublicTestResult   `json:"publicTestResults,omitempty"`
	ResultSHA256            string               `json:"resultSha256"`
}
