package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var v2TestNow = time.Date(2026, 11, 9, 17, 0, 0, 0, time.UTC)

func validRequestV2() ExecutionRequestV2 {
	return ExecutionRequestV2{
		ProtocolVersion: ProtocolVersionV2,
		CorrelationID:   "7d4c8a20-3e19-4b2c-9f10-8a7b6c5d4e3f",
		ExecutionID:     "exec_123", AttemptID: "attempt_123", ProblemVersionID: "problem_v1",
		Action: ActionRun, Language: LanguageJava, RuntimeVersion: "25",
		RuntimeImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceArtifactID:   "artifact_123", SourceSHA256: strings.Repeat("b", 64),
		TestBundleID: "bundle_123", ComparisonPolicy: ComparisonExactBytes,
		DeadlineAt:      "2026-11-09T17:05:00Z",
		CancellationRef: "cxl_0123456789abcdef0123456789abcdef",
		Limits: ResourceLimitsV2{
			CPUQuotaMillis: 1000, MemoryBytes: 128 * 1024 * 1024,
			WallTimeMillis: 5000, ProcessLimit: 64, OutputBytes: 1024 * 1024,
			ScratchBytes: DefaultScratchBytes, ScratchInodes: DefaultScratchInodes,
		},
	}
}

func TestDecodeExecutionRequestV2AcceptsGoldenFixture(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("testdata/execution-request-v2.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeExecutionRequestV2At(bytes.NewReader(body), v2TestNow)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if request != validRequestV2() {
		t.Fatalf("decoded request does not match expected contract: %+v", request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := DecodeExecutionRequestV2At(bytes.NewReader(encoded), v2TestNow)
	if err != nil {
		t.Fatalf("decode round-trip: %v", err)
	}
	if roundTrip != request {
		t.Fatalf("round-trip mismatch: got %+v want %+v", roundTrip, request)
	}
}

func TestDecodeExecutionRequestV2RejectsUnknownDuplicateAndNonCanonicalKeys(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(validRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"unknown field", func(b []byte) []byte { return bytes.Replace(b, []byte("{"), []byte("{\"futureField\":true,"), 1) }},
		{"duplicate key", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\"protocolVersion\":\"v2\""), []byte("\"protocolVersion\":\"v2\",\"protocolVersion\":\"v2\""), 1)
		}},
		{"escaped-equivalent duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\"executionId\":\"exec_123\""), []byte("\"executionId\":\"exec_123\",\"execution\\u0049d\":\"attacker\""), 1)
		}},
		{"case alias", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\"executionId\""), []byte("\"ExecutionID\""), 1)
		}},
		{"nested unknown", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\"scratchBytes\":"), []byte("\"scratchUnknown\":1,\"scratchBytes\":"), 1)
		}},
		{"nested duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\"scratchBytes\":268435456"), []byte("\"scratchBytes\":268435456,\"scratchBytes\":1"), 1)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeExecutionRequestV2At(bytes.NewReader(test.mutate(body)), v2TestNow)
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestV2RejectsMalformedBodies(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(validRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, body string }{
		{"empty", ""}, {"array", "[]"}, {"null", "null"}, {"malformed", "{\"protocolVersion\":"},
		{"multiple values", string(body) + " {}"}, {"trailing garbage", string(body) + " nope"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeExecutionRequestV2At(strings.NewReader(test.body), v2TestNow)
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestV2EnforcesBodyLimit(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte(" "), MaxExecutionRequestV2Bytes+1)
	_, err := DecodeExecutionRequestV2At(bytes.NewReader(body), v2TestNow)
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("error = %v, want ErrInvalidJSON", err)
	}
}

func TestDecodeExecutionRequestV2RejectsMissingAndNullRequiredFields(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(validRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		remove  string
		setNull string
	}{
		{"missing execution id", "executionId", ""},
		{"null comparison policy", "", "comparisonPolicy"},
		{"missing limits", "limits", ""},
		{"null limits", "", "limits"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var object map[string]json.RawMessage
			if err := json.Unmarshal(body, &object); err != nil {
				t.Fatal(err)
			}
			if test.remove != "" {
				delete(object, test.remove)
			}
			if test.setNull != "" {
				object[test.setNull] = json.RawMessage("null")
			}
			mutated, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeExecutionRequestV2At(bytes.NewReader(mutated), v2TestNow)
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestV2RejectsMissingNestedLimit(t *testing.T) {
	t.Parallel()
	var object map[string]json.RawMessage
	body, err := json.Marshal(validRequestV2())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	var limits map[string]json.RawMessage
	if err := json.Unmarshal(object["limits"], &limits); err != nil {
		t.Fatal(err)
	}
	delete(limits, "scratchInodes")
	object["limits"], err = json.Marshal(limits)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeExecutionRequestV2At(bytes.NewReader(mutated), v2TestNow)
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("error = %v, want ErrInvalidJSON", err)
	}
}

func TestExecutionRequestV2RejectsInvalidPolicyAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ExecutionRequestV2)
	}{
		{"unsupported protocol", func(r *ExecutionRequestV2) { r.ProtocolVersion = "v1" }},
		{"noncanonical correlation", func(r *ExecutionRequestV2) { r.CorrelationID = "7D4C8A20-3E19-4B2C-9F10-8A7B6C5D4E3F" }},
		{"non-v4 correlation", func(r *ExecutionRequestV2) { r.CorrelationID = "7d4c8a20-3e19-1b2c-9f10-8a7b6c5d4e3f" }},
		{"invalid UUID variant", func(r *ExecutionRequestV2) { r.CorrelationID = "7d4c8a20-3e19-4b2c-7f10-8a7b6c5d4e3f" }},
		{"mutable runtime tag", func(r *ExecutionRequestV2) { r.RuntimeImageDigest = "runtime:latest" }},
		{"uppercase source digest", func(r *ExecutionRequestV2) { r.SourceSHA256 = strings.Repeat("B", 64) }},
		{"unsupported comparison", func(r *ExecutionRequestV2) { r.ComparisonPolicy = "TRIM_WHITESPACE" }},
		{"invalid cancellation reference", func(r *ExecutionRequestV2) { r.CancellationRef = "cxl_short" }},
		{"non-UTC deadline", func(r *ExecutionRequestV2) { r.DeadlineAt = "2026-11-09T17:05:00+05:30" }},
		{"expired deadline", func(r *ExecutionRequestV2) { r.DeadlineAt = "2026-11-09T16:59:59Z" }},
		{"scratch bytes above hard maximum", func(r *ExecutionRequestV2) { r.Limits.ScratchBytes = MaxScratchBytes + 1 }},
		{"scratch inode count above hard maximum", func(r *ExecutionRequestV2) { r.Limits.ScratchInodes = MaxScratchInodes + 1 }},
		{"missing scratch quota", func(r *ExecutionRequestV2) { r.Limits.ScratchBytes = 0 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequestV2()
			test.mutate(&request)
			if err := request.ValidateAt(v2TestNow); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestExecutionRequestV2IntakeBudgetUsesTrustedTimestamp(t *testing.T) {
	t.Parallel()
	intakeAt := v2TestNow.Add(-9 * time.Minute)
	request := validRequestV2()
	request.DeadlineAt = v2TestNow.Add(time.Minute).Format(time.RFC3339)
	if err := request.ValidateIntakeBudget(intakeAt, v2TestNow); err != nil {
		t.Fatalf("valid intake budget rejected: %v", err)
	}
	request.DeadlineAt = intakeAt.Add(MaxExecutionBudget + time.Second).Format(time.RFC3339)
	if err := request.ValidateIntakeBudget(intakeAt, v2TestNow); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
}

func TestExecutionRequestV2AcceptsPythonSubmit(t *testing.T) {
	t.Parallel()
	request := validRequestV2()
	request.Action = ActionSubmit
	request.Language = LanguagePython
	request.RuntimeVersion = "3.14"
	if err := request.ValidateAt(v2TestNow); err != nil {
		t.Fatalf("valid Python SUBMIT rejected: %v", err)
	}
}
