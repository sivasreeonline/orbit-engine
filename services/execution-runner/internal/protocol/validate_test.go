package protocol

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validRequest() ExecutionRequest {
	now := time.Now().UTC()
	return ExecutionRequest{
		ProtocolVersion:  "v1",
		RequestID:        "request_123",
		ExecutionID:      "exec_123",
		AttemptID:        "attempt_123",
		ProblemVersionID: "problem_v1",
		Action:           ActionRun,
		Language:         LanguageJava,
		RuntimeVersion:   "25",
		SourceArtifactID: "artifact_123",
		SourceSHA256:     strings.Repeat("a", 64),
		SourceByteLength: 123,
		TestBundleID:     "bundle_123",
		TraceID:          "trace_123",
		IssuedAt:         now.Add(-time.Second),
		ExpiresAt:        now.Add(time.Minute),
		Limits: ResourceLimits{
			CPUQuotaMillis: 1000,
			MemoryBytes:    128 * 1024 * 1024,
			WallTimeMillis: 5000,
			ProcessLimit:   64,
			OutputBytes:    1024 * 1024,
		},
	}
}

func TestExecutionRequestValidateAcceptsValidRequest(t *testing.T) {
	t.Parallel()
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestExecutionRequestValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ExecutionRequest)
	}{
		{"unsupported protocol", func(r *ExecutionRequest) { r.ProtocolVersion = "v2" }},
		{"missing request id", func(r *ExecutionRequest) { r.RequestID = "" }},
		{"invalid action", func(r *ExecutionRequest) { r.Action = "EXEC" }},
		{"unsupported language", func(r *ExecutionRequest) { r.Language = "javascript" }},
		{"invalid artifact identifier", func(r *ExecutionRequest) { r.SourceArtifactID = "../secret" }},
		{"invalid source digest", func(r *ExecutionRequest) { r.SourceSHA256 = "not-a-digest" }},
		{"uppercase source digest", func(r *ExecutionRequest) { r.SourceSHA256 = strings.Repeat("A", 64) }},
		{"missing source length", func(r *ExecutionRequest) { r.SourceByteLength = 0 }},
		{"oversized source length", func(r *ExecutionRequest) { r.SourceByteLength = maximumRequestSourceBytes + 1 }},
		{"missing memory limit", func(r *ExecutionRequest) { r.Limits.MemoryBytes = 0 }},
		{"negative wall time", func(r *ExecutionRequest) { r.Limits.WallTimeMillis = -1 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequest()
			test.mutate(&request)
			if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestExecutionRequestValidateRejectsWhitespaceAndMissingIDs(t *testing.T) {
	t.Parallel()
	request := validRequest()
	request.ExecutionID = " exec_123 "
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for whitespace ID, got %v", err)
	}
	request = validRequest()
	request.AttemptID = ""
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid request for empty attempt ID, got %v", err)
	}
}

func TestExecutionRequestValidateAtRejectsExpiredAndFutureRequests(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*ExecutionRequest)
	}{
		{"expired", func(r *ExecutionRequest) { r.ExpiresAt = now }},
		{"issued too far in future", func(r *ExecutionRequest) { r.IssuedAt = now.Add(maximumFutureClockSkew + time.Second); r.ExpiresAt = now.Add(time.Hour) }},
		{"expiry before issue", func(r *ExecutionRequest) { r.IssuedAt = now.Add(time.Minute); r.ExpiresAt = now.Add(time.Second) }},
		{"missing expiry", func(r *ExecutionRequest) { r.ExpiresAt = time.Time{} }},
		{"non UTC issue time", func(r *ExecutionRequest) { r.IssuedAt = r.IssuedAt.In(time.FixedZone("UTC+1", 3600)) }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequest()
			request.IssuedAt = now.Add(-time.Second)
			request.ExpiresAt = now.Add(time.Minute)
			test.mutate(&request)
			if err := request.ValidateAt(now); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}
