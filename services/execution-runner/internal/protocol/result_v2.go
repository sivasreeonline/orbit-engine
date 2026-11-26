package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// CanonicalResultV2 is the exact ordered JSON envelope used for v2 result
// attestation. Keep field order, names, nulls and timestamp precision aligned
// with apps/api/src/security/execution-protocol-v2-result.ts.
type CanonicalResultV2 struct {
	Format                  string  `json:"format"`
	ExecutionID             string  `json:"executionId"`
	AttemptID               string  `json:"attemptId"`
	DispatchID              string  `json:"dispatchId"`
	RunnerID                string  `json:"runnerId"`
	KeyID                   string  `json:"keyId"`
	RequestSHA256           string  `json:"requestSha256"`
	PolicyRevision          string  `json:"policyRevision"`
	RuntimeImageDigest      string  `json:"runtimeImageDigest"`
	InfrastructureStatus    string  `json:"infrastructureStatus"`
	InfrastructureErrorCode *string `json:"infrastructureErrorCode"`
	CompilationStatus       string  `json:"compilationStatus"`
	Verdict                 string  `json:"verdict"`
	CleanupStatus           string  `json:"cleanupStatus"`
	TestsTotal              int64   `json:"testsTotal"`
	TestsPassed             int64   `json:"testsPassed"`
	ElapsedMs               int64   `json:"elapsedMs"`
	PeakMemoryBytes         *int64  `json:"peakMemoryBytes"`
	RunnerVersion           string  `json:"runnerVersion"`
	StartedAt               string  `json:"startedAt"`
	CompletedAt             string  `json:"completedAt"`
}

func CanonicalResultV2Digest(input CanonicalResultV2) (string, error) {
	if input.Format != "SKYHIGH-RUNNER-RESULT-V2" ||
		input.ExecutionID == "" || input.AttemptID == "" || input.DispatchID == "" ||
		input.RunnerID == "" || input.KeyID == "" || input.RequestSHA256 == "" ||
		input.PolicyRevision == "" || input.RuntimeImageDigest == "" {
		return "", errors.New("v2 canonical result binding is incomplete")
	}
	for _, timestamp := range []*string{&input.StartedAt, &input.CompletedAt} {
		parsed, err := time.Parse(time.RFC3339Nano, *timestamp)
		if err != nil {
			return "", errors.New("v2 canonical result timestamp is invalid")
		}
		*timestamp = parsed.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
