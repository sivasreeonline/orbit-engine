package protocol

import (
	"errors"
	"strings"
	"testing"
)

func validRequest() ExecutionRequest {
	return ExecutionRequest{
		ProtocolVersion:  "v1",
		ExecutionID:      "exec_123",
		AttemptID:        "attempt_123",
		ProblemVersionID: "problem_v1",
		Action:           ActionRun,
		Language:         LanguageJava,
		RuntimeVersion:   "25",
		SourceArtifactID: "artifact_123",
		SourceSHA256:     strings.Repeat("a", 64),
		TestBundleID:     "bundle_123",
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
		{
			name: "unsupported protocol",
			mutate: func(request *ExecutionRequest) {
				request.ProtocolVersion = "v2"
			},
		},
		{
			name: "invalid action",
			mutate: func(request *ExecutionRequest) {
				request.Action = "EXEC"
			},
		},
		{
			name: "unsupported language",
			mutate: func(request *ExecutionRequest) {
				request.Language = "javascript"
			},
		},
		{
			name: "invalid artifact identifier",
			mutate: func(request *ExecutionRequest) {
				request.SourceArtifactID = "../secret"
			},
		},
		{
			name: "invalid source digest",
			mutate: func(request *ExecutionRequest) {
				request.SourceSHA256 = "not-a-digest"
			},
		},
		{
			name: "missing memory limit",
			mutate: func(request *ExecutionRequest) {
				request.Limits.MemoryBytes = 0
			},
		},
		{
			name: "negative wall time",
			mutate: func(request *ExecutionRequest) {
				request.Limits.WallTimeMillis = -1
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := validRequest()
			test.mutate(&request)

			err := request.Validate()
			if !errors.Is(err, ErrInvalidRequest) {
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
