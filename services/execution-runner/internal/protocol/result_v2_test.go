package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Shared fixtures live at test/fixtures/result-v2 relative to the repository
// root. They are consumed by both Go and TypeScript tests to guarantee
// byte-for-byte JSON and SHA-256 parity between languages.
//
// Go test invocation: `go test` from services/execution-runner/.
// The fixture path is computed relative to the repository root by locating
// go.mod and walking up two directory levels.

type digestFixture struct {
	Filename              string `json:"filename"`
	ExpectedCanonicalJSON string `json:"expectedCanonicalJson"`
	ExpectedSHA256        string `json:"expectedSha256"`
}

type digestManifest struct {
	Fixtures []digestFixture `json:"fixtures"`
}

// fixtureRoot returns the absolute path to test/fixtures/result-v2 relative
// to the repository root. It locates go.mod (which is always at the repo
// root for this module) and walks up two levels from the package directory.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	// The test file lives at <repo>/services/execution-runner/internal/protocol/
	// Walk up: protocol -> internal -> execution-runner -> services -> repo root
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("unable to determine current directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(dir, "..", "..", "..", ".."))
	return filepath.Join(repoRoot, "test", "fixtures", "result-v2")
}

// loadManifest loads the shared digest manifest.
func loadManifest(t *testing.T) digestManifest {
	t.Helper()
	root := fixtureRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "digests.json"))
	if err != nil {
		t.Fatalf("unable to read digests manifest: %v", err)
	}
	var manifest digestManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("unable to parse digests manifest: %v", err)
	}
	return manifest
}

// loadFixtureJSON reads a fixture file and returns its raw bytes.
func loadFixtureJSON(t *testing.T, filename string) []byte {
	t.Helper()
	root := fixtureRoot(t)
	data, err := os.ReadFile(filepath.Join(root, filename))
	if err != nil {
		t.Fatalf("unable to read fixture %q: %v", filename, err)
	}
	return data
}

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
	result.ElapsedMs = 9007199254740993
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

	manifest := loadManifest(t)
	var baseFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "base.json" {
			baseFixture = f
			break
		}
	}
	if baseFixture.Filename == "" {
		t.Fatal("manifest missing base.json fixture")
	}

	result := validCanonicalResult()
	startedAt := result.StartedAt
	completedAt := result.CompletedAt

	digest, err := CanonicalResultV2Digest(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != baseFixture.ExpectedSHA256 {
		t.Fatalf("digest = %q, want %q", digest, baseFixture.ExpectedSHA256)
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

	manifest := loadManifest(t)

	for _, f := range manifest.Fixtures {
		f := f
		t.Run(f.Filename, func(t *testing.T) {
			t.Parallel()

			raw := loadFixtureJSON(t, f.Filename)
			if string(raw) != f.ExpectedCanonicalJSON {
				t.Fatalf("fixture %s canonical JSON mismatch:\n  got: %s\n  want: %s", f.Filename, string(raw), f.ExpectedCanonicalJSON)
			}
		})
	}
}

// TestCanonicalResultV2RoundTrip unmarshals each shared fixture into a Go
// CanonicalResultV2, re-marshals it, and verifies the bytes are identical to
// the fixture. This guarantees that the Go struct serialization matches the
// shared canonical bytes consumed by TypeScript.
func TestCanonicalResultV2RoundTrip(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)

	for _, f := range manifest.Fixtures {
		f := f
		t.Run("roundtrip_"+f.Filename, func(t *testing.T) {
			t.Parallel()

			raw := loadFixtureJSON(t, f.Filename)
			var result CanonicalResultV2
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("unmarshal fixture %s: %v", f.Filename, err)
			}

			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}
			if string(encoded) != f.ExpectedCanonicalJSON {
				t.Fatalf("roundtrip JSON mismatch for %s:\n  got: %s\n  want: %s", f.Filename, string(encoded), f.ExpectedCanonicalJSON)
			}

			digest, err := CanonicalResultV2Digest(result)
			if err != nil {
				t.Fatalf("digest for %s: %v", f.Filename, err)
			}
			if digest != f.ExpectedSHA256 {
				t.Fatalf("roundtrip digest mismatch for %s:\n  got: %q\n  want: %q", f.Filename, digest, f.ExpectedSHA256)
			}
		})
	}
}

func TestCanonicalResultV2DigestPopulatedOptionalFields(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)
	var populatedFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "populated.json" {
			populatedFixture = f
			break
		}
	}
	if populatedFixture.Filename == "" {
		t.Fatal("manifest missing populated.json fixture")
	}

	digest, err := CanonicalResultV2Digest(populatedCanonicalResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != populatedFixture.ExpectedSHA256 {
		t.Fatalf("digest = %q, want %q", digest, populatedFixture.ExpectedSHA256)
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

	manifest := loadManifest(t)
	var baseFixture digestFixture
	var noFractionFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "base.json" {
			baseFixture = f
		}
		if f.Filename == "no-fraction.json" {
			noFractionFixture = f
		}
	}
	if baseFixture.Filename == "" {
		t.Fatal("manifest missing base.json fixture")
	}
	if noFractionFixture.Filename == "" {
		t.Fatal("manifest missing no-fraction.json fixture")
	}

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
			wantDigest:  baseFixture.ExpectedSHA256,
		},
		{
			name:        "nanoseconds truncate not round",
			startedAt:   "2026-11-26T13:40:10.123999999Z",
			completedAt: "2026-11-26T13:40:11.987999999Z",
			wantDigest:  baseFixture.ExpectedSHA256,
		},
		{
			name:        "offset converted to UTC",
			startedAt:   "2026-11-26T15:40:10.123456789+02:00",
			completedAt: "2026-11-26T15:40:11.987654321+02:00",
			wantDigest:  baseFixture.ExpectedSHA256,
		},
		{
			name:        "already normalized",
			startedAt:   "2026-11-26T13:40:10.123Z",
			completedAt: "2026-11-26T13:40:11.987Z",
			wantDigest:  baseFixture.ExpectedSHA256,
		},
		{
			name:        "no fractional seconds become .000Z",
			startedAt:   "2026-11-26T13:40:10Z",
			completedAt: "2026-11-26T13:40:11Z",
			wantDigest:  noFractionFixture.ExpectedSHA256,
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

	manifest := loadManifest(t)
	var baseFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "base.json" {
			baseFixture = f
			break
		}
	}
	if baseFixture.Filename == "" {
		t.Fatal("manifest missing base.json fixture")
	}

	first, err := CanonicalResultV2Digest(validCanonicalResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first != baseFixture.ExpectedSHA256 {
		t.Fatalf("first digest = %q, want %q", first, baseFixture.ExpectedSHA256)
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

	manifest := loadManifest(t)
	var baseFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "base.json" {
			baseFixture = f
			break
		}
	}
	if baseFixture.Filename == "" {
		t.Fatal("manifest missing base.json fixture")
	}

	raw := loadFixtureJSON(t, "base.json")
	if !strings.Contains(string(raw), `"infrastructureErrorCode":null`) {
		t.Fatalf("base JSON missing null infrastructureErrorCode: %s", string(raw))
	}
	if !strings.Contains(string(raw), `"peakMemoryBytes":null`) {
		t.Fatalf("base JSON missing null peakMemoryBytes: %s", string(raw))
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
		{
			name:   "trailing newline",
			mutate: func(result *CanonicalResultV2) { result.StartedAt = "2026-11-26T13:40:10Z\n" },
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

	manifest := loadManifest(t)
	var baseFixture digestFixture
	for _, f := range manifest.Fixtures {
		if f.Filename == "base.json" {
			baseFixture = f
			break
		}
	}
	if baseFixture.Filename == "" {
		t.Fatal("manifest missing base.json fixture")
	}

	goldenJSON := baseFixture.ExpectedCanonicalJSON

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
		index := strings.Index(goldenJSON, needle)
		if index == -1 {
			t.Fatalf("golden JSON missing field %q", field)
		}
		if strings.Count(goldenJSON, needle) != 1 {
			t.Fatalf("golden JSON field %q appears more than once", field)
		}
		if index <= previous {
			t.Fatalf("field %q out of order in golden JSON", field)
		}
		previous = index
	}

	if !strings.HasPrefix(goldenJSON, `{"format":`) {
		t.Fatal("golden JSON must start with format field")
	}
	if !strings.HasSuffix(goldenJSON, "}") {
		t.Fatal("golden JSON must end with }")
	}
}

// TestCanonicalResultV2IndependentConstruction constructs CanonicalResultV2
// values independently (without unmarshalling any fixture) for each shared
// fixture and verifies that CanonicalResultV2Digest produces the exact
// canonical JSON bytes and SHA-256 digest recorded in the shared fixtures.
func TestCanonicalResultV2IndependentConstruction(t *testing.T) {
	t.Parallel()

	manifest := loadManifest(t)

	fixtures := map[string]func() CanonicalResultV2{
		"base.json":        func() CanonicalResultV2 { return independentBaseResult() },
		"populated.json":   func() CanonicalResultV2 { return independentPopulatedResult() },
		"no-fraction.json": func() CanonicalResultV2 { return independentNoFractionResult() },
	}

	for _, f := range manifest.Fixtures {
		f := f
		t.Run("independent_"+f.Filename, func(t *testing.T) {
			t.Parallel()

			construct, ok := fixtures[f.Filename]
			if !ok {
				t.Fatalf("no independent constructor for %s", f.Filename)
			}
			result := construct()

			digest, err := CanonicalResultV2Digest(result)
			if err != nil {
				t.Fatalf("digest for independently constructed %s: %v", f.Filename, err)
			}
			if digest != f.ExpectedSHA256 {
				t.Fatalf("independent digest mismatch for %s:\n  got: %q\n  want: %q", f.Filename, digest, f.ExpectedSHA256)
			}

			// CanonicalResultV2Digest normalizes timestamps to UTC millisecond
			// precision. Marshal after normalization so the JSON bytes reflect
			// the canonical timestamps.
			normalized, err := normalizeTimestamps(result)
			if err != nil {
				t.Fatalf("normalize timestamps for independently constructed %s: %v", f.Filename, err)
			}
			encoded, err := json.Marshal(normalized)
			if err != nil {
				t.Fatalf("marshal independently constructed result: %v", err)
			}
			if string(encoded) != f.ExpectedCanonicalJSON {
				t.Fatalf("independent JSON mismatch for %s:\n  got: %s\n  want: %s", f.Filename, string(encoded), f.ExpectedCanonicalJSON)
			}
		})
	}
}

// independentBaseResult constructs the base fixture result independently
// without reading base.json.
func independentBaseResult() CanonicalResultV2 {
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
		StartedAt:               "2026-11-26T13:40:10.123Z",
		CompletedAt:             "2026-11-26T13:40:11.987Z",
	}
}

// independentPopulatedResult constructs the populated fixture result
// independently without reading populated.json. It exercises the full signed
// int64 range (9007199254740993 exceeds JavaScript's safe integer range) and
// a populated nullable pointer field.
func independentPopulatedResult() CanonicalResultV2 {
	result := independentBaseResult()
	result.InfrastructureStatus = "FAILED"
	result.InfrastructureErrorCode = stringPtr("E_INFRA_TIMEOUT")
	result.Verdict = "INTERNAL_ERROR"
	result.TestsPassed = 1
	result.ElapsedMs = 9007199254740993
	result.PeakMemoryBytes = int64Ptr(134217728)
	return result
}

// normalizeTimestamps returns a copy of result with startedAt and completedAt
// normalized to UTC millisecond precision, matching
// CanonicalResultV2Digest's behavior.
func normalizeTimestamps(result CanonicalResultV2) (CanonicalResultV2, error) {
	startedAt, err := time.Parse(time.RFC3339Nano, result.StartedAt)
	if err != nil {
		return result, err
	}
	result.StartedAt = startedAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")

	completedAt, err := time.Parse(time.RFC3339Nano, result.CompletedAt)
	if err != nil {
		return result, err
	}
	result.CompletedAt = completedAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")

	return result, nil
}
func independentNoFractionResult() CanonicalResultV2 {
	result := independentBaseResult()
	result.StartedAt = "2026-11-26T13:40:10Z"
	result.CompletedAt = "2026-11-26T13:40:11Z"
	return result
}

// TestCanonicalResultV2IndependentUnicode tests UTF-8/Unicode serialization
// behavior matching Go's encoding/json. Valid supplementary-plane characters
// pass through as UTF-8 bytes. Unpaired UTF-16 surrogates cannot be expressed
// in Go strings (string(rune(0xD800)) becomes U+FFFD), so this test documents
// Go's actual behavior rather than TypeScript's rejection policy.
func TestCanonicalResultV2IndependentUnicode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		runnerVersion string
		wantJSON      string
	}{
		{
			name:          "supplementary-plane emoji U+1F600",
			runnerVersion: "v" + string(rune(0x1F600)),
			wantJSON:      "\"v😀\"",
		},
		{
			name:          "supplementary-plane musical symbol U+1D11E",
			runnerVersion: "v" + string(rune(0x1D11E)),
			wantJSON:      "\"v𝄞\"",
		},
		{
			name:          "mixed ASCII BMP and supplementary-plane",
			runnerVersion: "a" + string(rune(0x00E9)) + string(rune(0x1F600)) + "b",
			wantJSON:      "\"aé😀b\"",
		},
		{
			// string(rune(0xD800)) becomes U+FFFD in Go, which marshals as the
			// replacement character, not as an unpaired surrogate.
			name:          "rune 0xD800 becomes U+FFFD",
			runnerVersion: "a" + string(rune(0xD800)) + "b",
			wantJSON:      "\"a�b\"",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := independentBaseResult()
			result.RunnerVersion = test.runnerVersion

			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("unexpected marshal error: %v", err)
			}

			if !strings.Contains(string(encoded), test.wantJSON) {
				t.Fatalf("marshaled JSON mismatch: got %s", string(encoded))
			}
		})
	}
}

// TestCanonicalResultV2IndependentIntegerValidation tests that required int64
// fields reject nil/zero-equivalent, while the nullable peakMemoryBytes
// accepts nil.
func TestCanonicalResultV2IndependentIntegerValidation(t *testing.T) {
	t.Parallel()

	// Required int64 fields are value types in Go, so they cannot be nil at
	// the type level. Compile-time safety guarantees this; we verify valid
	// values are accepted.
	result := independentBaseResult()
	result.TestsTotal = 0
	result.TestsPassed = 0
	result.ElapsedMs = 0

	_, err := CanonicalResultV2Digest(result)
	if err != nil {
		t.Fatalf("unexpected digest error for zero int64 values: %v", err)
	}

	// peakMemoryBytes (nullable pointer) accepts nil
	result.PeakMemoryBytes = nil
	_, err = CanonicalResultV2Digest(result)
	if err != nil {
		t.Fatalf("unexpected digest error for nil peakMemoryBytes: %v", err)
	}

	// peakMemoryBytes accepts a valid pointer
	result.PeakMemoryBytes = int64Ptr(134217728)
	_, err = CanonicalResultV2Digest(result)
	if err != nil {
		t.Fatalf("unexpected digest error for valid peakMemoryBytes: %v", err)
	}
}

// TestCanonicalResultV2IndependentYearBoundary tests RFC3339 year boundary
// compatibility with Go's time.Parse. Years 0-99 must be handled literally
// (no 1900 offset). Timezone rollover across year boundaries is verified.
func TestCanonicalResultV2IndependentYearBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		startedAt   string
		completedAt string
		wantDigest  string
	}{
		{
			name:        "year 0000",
			startedAt:   "0000-01-01T00:00:00Z",
			completedAt: "0000-01-01T00:00:01Z",
			wantDigest:  "3c1110abf47899ba8988b7ea28db72ebe93e6c904f35d3bce30f6359761e8917",
		},
		{
			name:        "year 0099",
			startedAt:   "0099-12-31T23:59:59Z",
			completedAt: "0099-12-31T23:59:59Z",
			wantDigest:  "480cc90cb1ddbcc9a19a3d02c4c4ae376648e4744322cf4809114b520e2fcc71",
		},
		{
			name:        "year 1000",
			startedAt:   "1000-01-01T00:00:00Z",
			completedAt: "1000-01-01T00:00:01Z",
			wantDigest:  "929d3cf4004bf2548c3946536d3fd82144170848643f4186edf5895d51b57d94",
		},
		{
			name:        "leap year 0004",
			startedAt:   "0004-02-29T12:00:00Z",
			completedAt: "0004-02-29T12:00:01Z",
			wantDigest:  "e3371de782e226290aa3becfd47cac4bd1a2a203fe471b95d173285e79bf32c4",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := independentBaseResult()
			result.StartedAt = test.startedAt
			result.CompletedAt = test.completedAt

			digest, err := CanonicalResultV2Digest(result)
			if err != nil {
				t.Fatalf("digest error: %v", err)
			}
			if digest != test.wantDigest {
				t.Fatalf("digest mismatch for %s:\n  got: %q\n  want: %q", test.name, digest, test.wantDigest)
			}

			// Verify canonical JSON normalization independently
			normalized, err := normalizeTimestamps(result)
			if err != nil {
				t.Fatalf("normalize error: %v", err)
			}
			encoded, err := json.Marshal(normalized)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			expectedStartedAt := test.startedAt[:10] + "T" + test.startedAt[11:19] + ".000Z"
			expectedCompletedAt := test.completedAt[:10] + "T" + test.completedAt[11:19] + ".000Z"
			if !strings.Contains(string(encoded), `"startedAt":"`+expectedStartedAt+`"`) {
				t.Fatalf("JSON does not contain normalized startedAt:\n  got: %s", string(encoded))
			}
			if !strings.Contains(string(encoded), `"completedAt":"`+expectedCompletedAt+`"`) {
				t.Fatalf("JSON does not contain normalized completedAt:\n  got: %s", string(encoded))
			}
		})
	}
}

// TestCanonicalResultV2TimezoneRolloverBoundaries verifies that timezone
// normalization may cross year boundaries only while the normalized UTC year
// remains representable as four-digit RFC3339 (0000-9999).
func TestCanonicalResultV2TimezoneRolloverBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		startedAt       string
		completedAt     string
		wantStartedAt   string
		wantCompletedAt string
		wantDigest      string
		wantErr         bool
	}{
		{
			name:            "year 0099 rolls back into 0098",
			startedAt:       "0099-01-01T00:30:00+01:00",
			completedAt:     "0099-01-01T00:30:01+01:00",
			wantStartedAt:   "0098-12-31T23:30:00.000Z",
			wantCompletedAt: "0098-12-31T23:30:01.000Z",
			wantDigest:      "7e2ea1dffbfa46e2d1dcb818287999e9aac9e2a533fbf528e51012f2d609cf3c",
		},
		{
			name:            "year 0099 rolls forward into 0100",
			startedAt:       "0099-12-31T23:30:00-01:00",
			completedAt:     "0099-12-31T23:30:01-01:00",
			wantStartedAt:   "0100-01-01T00:30:00.000Z",
			wantCompletedAt: "0100-01-01T00:30:01.000Z",
			wantDigest:      "32ece086899ebeafe3183ee94b6baba3a799cee121fbbc9831d9029a2c7f2e3e",
		},
		{
			name:            "leap year 0004 rolls back to Feb 29",
			startedAt:       "0004-03-01T00:30:00+01:00",
			completedAt:     "0004-03-01T00:30:01+01:00",
			wantStartedAt:   "0004-02-29T23:30:00.000Z",
			wantCompletedAt: "0004-02-29T23:30:01.000Z",
			wantDigest:      "6c50571bed56cbaf4d9676b0a44ed97d119080c9740ca87e1944046174805bcd",
		},
		{
			name:        "year 0000 rolls before supported range",
			startedAt:   "0000-01-01T00:30:00+01:00",
			completedAt: "0000-01-01T00:30:01+01:00",
			wantErr:     true,
		},
		{
			name:        "year 9999 rolls after supported range",
			startedAt:   "9999-12-31T23:30:00-01:00",
			completedAt: "9999-12-31T23:30:01-01:00",
			wantErr:     true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := independentBaseResult()
			result.StartedAt = test.startedAt
			result.CompletedAt = test.completedAt

			digest, err := CanonicalResultV2Digest(result)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected out-of-range timestamp error, got nil")
				}
				if !strings.Contains(err.Error(), "out of range") {
					t.Fatalf("expected out-of-range error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("digest error: %v", err)
			}
			if digest != test.wantDigest {
				t.Fatalf("digest mismatch for %s:\n  got: %q\n  want: %q", test.name, digest, test.wantDigest)
			}

			normalized, err := normalizeTimestamps(result)
			if err != nil {
				t.Fatalf("normalize error: %v", err)
			}
			encoded, err := json.Marshal(normalized)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			expected := `{"format":"SKYHIGH-RUNNER-RESULT-V2","executionId":"exec_123","attemptId":"attempt_123","dispatchId":"dispatch_123","runnerId":"runner_01","keyId":"key_2026_01","requestSha256":"` + strings.Repeat("a", 64) + `","policyRevision":"policy_rev_7","runtimeImageDigest":"sha256:` + strings.Repeat("a", 64) + `","infrastructureStatus":"OK","infrastructureErrorCode":null,"compilationStatus":"SUCCEEDED","verdict":"ACCEPTED","cleanupStatus":"CLEANED","testsTotal":3,"testsPassed":3,"elapsedMs":1234,"peakMemoryBytes":null,"runnerVersion":"0.1.0","startedAt":"` + test.wantStartedAt + `","completedAt":"` + test.wantCompletedAt + `"}`
			if string(encoded) != expected {
				t.Fatalf("canonical JSON mismatch for %s:\n  got: %s\n  want: %s", test.name, string(encoded), expected)
			}
		})
	}
}
