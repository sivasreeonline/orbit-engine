package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// Golden fixtures below were computed independently with SHA-256 over the
// exact canonical JSON bytes, not via CanonicalResultV2Digest.

const goldenJSONBase = `{"format":"SKYHIGH-RUNNER-RESULT-V2","executionId":"exec_123","attemptId":"attempt_123","dispatchId":"dispatch_123","runnerId":"runner_01","keyId":"key_2026_01","requestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy_rev_7","runtimeImageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","infrastructureStatus":"OK","infrastructureErrorCode":null,"compilationStatus":"SUCCEEDED","verdict":"ACCEPTED","cleanupStatus":"CLEANED","testsTotal":3,"testsPassed":3,"elapsedMs":1234,"peakMemoryBytes":null,"runnerVersion":"0.1.0","startedAt":"2026-11-26T13:40:10.123Z","completedAt":"2026-11-26T13:40:11.987Z"}`

const goldenDigestBase = "9c85ee9b616a3a5144dd3c5e91db8d39187f721e86e023c9ac7bf27e0a585e0c"

const goldenJSONPopulated = `{"format":"SKYHIGH-RUNNER-RESULT-V2","executionId":"exec_123","attemptId":"attempt_123","dispatchId":"dispatch_123","runnerId":"runner_01","keyId":"key_2026_01","requestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy_rev_7","runtimeImageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","infrastructureStatus":"FAILED","infrastructureErrorCode":"E_INFRA_TIMEOUT","compilationStatus":"SUCCEEDED","verdict":"INTERNAL_ERROR","cleanupStatus":"CLEANED","testsTotal":3,"testsPassed":1,"elapsedMs":1234,"peakMemoryBytes":134217728,"runnerVersion":"0.1.0","startedAt":"2026-11-26T13:40:10.123Z","completedAt":"2026-11-26T13:40:11.987Z"}`

const goldenDigestPopulated = "fb263750d6c8615e6fd52963b153e86e341699415c04578401d191c9781f6cc8"

const goldenJSONNoFraction = `{"format":"SKYHIGH-RUNNER-RESULT-V2","executionId":"exec_123","attemptId":"attempt_123","dispatchId":"dispatch_123","runnerId":"runner_01","keyId":"key_2026_01","requestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy_rev_7","runtimeImageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","infrastructureStatus":"OK","infrastructureErrorCode":null,"compilationStatus":"SUCCEEDED","verdict":"ACCEPTED","cleanupStatus":"CLEANED","testsTotal":3,"testsPassed":3,"elapsedMs":1234,"peakMemoryBytes":null,"runnerVersion":"0.1.0","startedAt":"2026-11-26T13:40:10.000Z","completedAt":"2026-11-26T13:40:11.000Z"}`

const goldenDigestNoFraction = "ae518feff74e67b8abb4c788dd15b31578e0a158f7bbd29e9db683929723934c"

func stringPtr(value string) *string {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func validCanonicalResult() CanonicalResultV2 {
	return CanonicalResultV2{
		Format:                  "SKYHIGH-RUNNER-RESULT-V2",
		ExecutionID:             "exec_123",
		AttemptID:               "attempt_123",
		DispatchID:              "dispatch_123",
		RunnerID:                "runner_01",
		KeyID:                   "key_2026_01",
		RequestSHA256:           strings.Repeat("a", 64),
		PolicyRevision:          "policy_rev_7",
		RuntimeImageDigest:      "sha256:" + strings.Repeat("a", 64),
		InfrastructureStatus:    "OK",
		InfrastructureErrorCode: nil,
		CompilationStatus:       "SUCCEEDED",
		Verdict:                 "ACCEPTED",
		CleanupStatus:           "CLEANED",
		TestsTotal:              3,
		TestsPassed:             3,
		ElapsedMs:               1234,
		PeakMemoryBytes:         nil,
		RunnerVersion:           "0.1.0",
		StartedAt:               "2026-11-26T13:40:10.123456789Z",
		CompletedAt:             "2026-11-26T13:40:11.987654321Z",
	}
}

func normalizedCanonicalResult() CanonicalResultV2 {
	result := validCanonicalResult()
	result.StartedAt = "2026-11-26T13:40:10.123Z"
	result.CompletedAt = "2026-11-26T13:40:11.987Z"
	return result
}

func populatedCanonicalResult() CanonicalResultV2 {
	result := validCanonicalResult()
	result.InfrastructureStatus = "FAILED"
	result.InfrastructureErrorCode = stringPtr("E_INFRA_TIMEOUT")
	result.Verdict = "INTERNAL_ERROR"
	result.TestsPassed = 1
	result.PeakMemoryBytes = int64Ptr(134217728)
	return result
}

func normalizedPopulatedCanonicalResult() CanonicalResultV2 {
	result := populatedCanonicalResult()
	result.StartedAt = "2026-11-26T13:40:10.123Z"
	result.CompletedAt = "2026-11-26T13:40:11.987Z"
	return result
}

func TestCanonicalResultV2DigestMatchesGoldenFixture(t *testing.T) {
	t.Parallel()

	result := validCanonicalResult()
	startedAt := result.StartedAt
	completedAt := result.CompletedAt

	digest, err := CanonicalResultV2Digest(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != goldenDigestBase {
		t.Fatalf("digest = %q, want %q", digest, goldenDigestBase)
	}
	if len(digest) != 64 {
		t.Fatalf("digest length = %d, want 64", len(digest))
	}
	if result.StartedAt != startedAt || result.CompletedAt != completedAt {
		t.Fatalf("digest mutated caller input: startedAt %q -> %q, completedAt %q -> %q", startedAt, result.StartedAt, completedAt, result.CompletedAt)
	}
}

func TestCanonicalResultV2JSONBytesAreExact(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(normalizedCanonicalResult())
	if err != nil {
		t.Fatalf("marshal base result: %v", err)
	}
	if string(encoded) != goldenJSONBase {
		t.Fatalf("base JSON = %s, want %s", encoded, goldenJSONBase)
	}

	encodedPopulated, err := json.Marshal(normalizedPopulatedCanonicalResult())
	if err != nil {
		t.Fatalf("marshal populated result: %v", err)
	}
	if string(encodedPopulated) != goldenJSONPopulated {
		t.Fatalf("populated JSON = %s, want %s", encodedPopulated, goldenJSONPopulated)
	}
}

func TestCanonicalResultV2DigestPopulatedOptionalFields(t *testing.T) {
	t.Parallel()

	digest, err := CanonicalResultV2Digest(populatedCanonicalResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != goldenDigestPopulated {
		t.Fatalf("digest = %q, want %q", digest, goldenDigestPopulated)
	}

	encoded, err := json.Marshal(normalizedPopulatedCanonicalResult())
	if err != nil {
		t.Fatalf("marshal populated result: %v", err)
	}
	if !strings.Contains(string(encoded), `"infrastructureErrorCode":"E_INFRA_TIMEOUT"`) {
		t.Fatalf("populated JSON missing error code: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"peakMemoryBytes":134217728`) {
		t.Fatalf("populated JSON missing peak memory: %s", encoded)
	}
}

func TestCanonicalResultV2DigestTimestampNormalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		startedAt   string
		completedAt string
		wantDigest  string
	}{
		{
			name:        "nanoseconds truncated to milliseconds",
			startedAt:   "2026-11-26T13:40:10.123456789Z",
			completedAt: "2026-11-26T13:40:11.987654321Z",
			wantDigest:  goldenDigestBase,
		},
		{
			name:        "nanoseconds truncate not round",
			startedAt:   "2026-11-26T13:40:10.123999999Z",
			completedAt: "2026-11-26T13:40:11.987999999Z",
			wantDigest:  goldenDigestBase,
		},
		{
			name:        "offset converted to UTC",
			startedAt:   "2026-11-26T15:40:10.123456789+02:00",
			completedAt: "2026-11-26T15:40:11.987654321+02:00",
			wantDigest:  goldenDigestBase,
		},
		{
			name:        "already normalized",
			startedAt:   "2026-11-26T13:40:10.123Z",
			completedAt: "2026-11-26T13:40:11.987Z",
			wantDigest:  goldenDigestBase,
		},
		{
			name:        "no fractional seconds become .000Z",
			startedAt:   "2026-11-26T13:40:10Z",
			completedAt: "2026-11-26T13:40:11Z",
			wantDigest:  goldenDigestNoFraction,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := validCanonicalResult()
			result.StartedAt = test.startedAt
			result.CompletedAt = test.completedAt

			digest, err := CanonicalResultV2Digest(result)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if digest != test.wantDigest {
				t.Fatalf("digest = %q, want %q", digest, test.wantDigest)
			}
		})
	}
}

func TestCanonicalResultV2DigestDeterministicAcrossRepeatedCalls(t *testing.T) {
	t.Parallel()

	first, err := CanonicalResultV2Digest(validCanonicalResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != goldenDigestBase {
		t.Fatalf("first digest = %q, want %q", first, goldenDigestBase)
	}

	for i := 0; i < 5; i++ {
		digest, err := CanonicalResultV2Digest(validCanonicalResult())
		if err != nil {
			t.Fatalf("call %d unexpected error: %v", i, err)
		}
		if digest != first {
			t.Fatalf("call %d digest = %q, want %q", i, digest, first)
		}
	}
}

func TestCanonicalResultV2DigestNullHandling(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(normalizedCanonicalResult())
	if err != nil {
		t.Fatalf("marshal base result: %v", err)
	}
	if !strings.Contains(string(encoded), `"infrastructureErrorCode":null`) {
		t.Fatalf("base JSON missing null infrastructureErrorCode: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"peakMemoryBytes":null`) {
		t.Fatalf("base JSON missing null peakMemoryBytes: %s", encoded)
	}

	encodedPopulated, err := json.Marshal(normalizedPopulatedCanonicalResult())
	if err != nil {
		t.Fatalf("marshal populated result: %v", err)
	}
	if strings.Contains(string(encodedPopulated), `"infrastructureErrorCode":null`) {
		t.Fatalf("populated JSON must not contain null infrastructureErrorCode: %s", encodedPopulated)
	}
	if strings.Contains(string(encodedPopulated), `"peakMemoryBytes":null`) {
		t.Fatalf("populated JSON must not contain null peakMemoryBytes: %s", encodedPopulated)
	}
}

func TestCanonicalResultV2DigestRejectsInvalidTimestamps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CanonicalResultV2)
	}{
		{
			name:   "empty startedAt",
			mutate: func(result *CanonicalResultV2) { result.StartedAt = "" },
		},
		{
			name:   "empty completedAt",
			mutate: func(result *CanonicalResultV2) { result.CompletedAt = "" },
		},
		{
			name:   "garbage startedAt",
			mutate: func(result *CanonicalResultV2) { result.StartedAt = "not-a-timestamp" },
		},
		{
			name:   "garbage completedAt",
			mutate: func(result *CanonicalResultV2) { result.CompletedAt = "not-a-timestamp" },
		},
		{
			name:   "invalid month",
			mutate: func(result *CanonicalResultV2) { result.StartedAt = "2026-13-26T13:40:10Z" },
		},
		{
			name:   "missing timezone",
			mutate: func(result *CanonicalResultV2) { result.StartedAt = "2026-11-26T13:40:10" },
		},
		{
			name:   "space instead of T",
			mutate: func(result *CanonicalResultV2) { result.CompletedAt = "2026-11-26 13:40:11Z" },
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := validCanonicalResult()
			test.mutate(&result)

			if _, err := CanonicalResultV2Digest(result); err == nil {
				t.Fatal("expected error for invalid timestamp, got nil")
			}
		})
	}
}

func TestCanonicalResultV2DigestRejectsMissingRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CanonicalResultV2)
	}{
		{
			name:   "missing format",
			mutate: func(result *CanonicalResultV2) { result.Format = "" },
		},
		{
			name:   "missing executionId",
			mutate: func(result *CanonicalResultV2) { result.ExecutionID = "" },
		},
		{
			name:   "missing attemptId",
			mutate: func(result *CanonicalResultV2) { result.AttemptID = "" },
		},
		{
			name:   "missing dispatchId",
			mutate: func(result *CanonicalResultV2) { result.DispatchID = "" },
		},
		{
			name:   "missing runnerId",
			mutate: func(result *CanonicalResultV2) { result.RunnerID = "" },
		},
		{
			name:   "missing keyId",
			mutate: func(result *CanonicalResultV2) { result.KeyID = "" },
		},
		{
			name:   "missing requestSha256",
			mutate: func(result *CanonicalResultV2) { result.RequestSHA256 = "" },
		},
		{
			name:   "missing policyRevision",
			mutate: func(result *CanonicalResultV2) { result.PolicyRevision = "" },
		},
		{
			name:   "missing runtimeImageDigest",
			mutate: func(result *CanonicalResultV2) { result.RuntimeImageDigest = "" },
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := validCanonicalResult()
			test.mutate(&result)

			if _, err := CanonicalResultV2Digest(result); err == nil {
				t.Fatal("expected error for missing required field, got nil")
			}
		})
	}
}

func TestCanonicalResultV2DigestRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format string
	}{
		{name: "v1 format", format: "SKYHIGH-RUNNER-RESULT-V1"},
		{name: "lowercase format", format: "skyhigh-runner-result-v2"},
		{name: "trailing space", format: "SKYHIGH-RUNNER-RESULT-V2 "},
		{name: "v3 format", format: "SKYHIGH-RUNNER-RESULT-V3"},
		{name: "empty format", format: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := validCanonicalResult()
			result.Format = test.format

			if _, err := CanonicalResultV2Digest(result); err == nil {
				t.Fatalf("expected error for format %q, got nil", test.format)
			}
		})
	}
}

func TestCanonicalResultV2JSONFieldOrderAndPresence(t *testing.T) {
	t.Parallel()

	fields := []string{
		"format",
		"executionId",
		"attemptId",
		"dispatchId",
		"runnerId",
		"keyId",
		"requestSha256",
		"policyRevision",
		"runtimeImageDigest",
		"infrastructureStatus",
		"infrastructureErrorCode",
		"compilationStatus",
		"verdict",
		"cleanupStatus",
		"testsTotal",
		"testsPassed",
		"elapsedMs",
		"peakMemoryBytes",
		"runnerVersion",
		"startedAt",
		"completedAt",
	}

	if len(fields) != 21 {
		t.Fatalf("field list has %d entries, want 21", len(fields))
	}

	previous := -1
	for _, field := range fields {
		needle := `"` + field + `":`
		index := strings.Index(goldenJSONBase, needle)
		if index == -1 {
			t.Fatalf("golden JSON missing field %q", field)
		}
		if strings.Count(goldenJSONBase, needle) != 1 {
			t.Fatalf("golden JSON field %q appears more than once", field)
		}
		if index <= previous {
			t.Fatalf("field %q out of order in golden JSON", field)
		}
		previous = index
	}

	if !strings.HasPrefix(goldenJSONBase, `{"format":`) {
		t.Fatal("golden JSON must start with format field")
	}
	if !strings.HasSuffix(goldenJSONBase, "}") {
		t.Fatal("golden JSON must end with }")
	}
}
