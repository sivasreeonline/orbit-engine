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

func TestExecutionRequestValidateRejectsNonPositiveResourceLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ResourceLimits)
	}{
		{name: "zero CPU quota", mutate: func(l *ResourceLimits) { l.CPUQuotaMillis = 0 }},
		{name: "negative CPU quota", mutate: func(l *ResourceLimits) { l.CPUQuotaMillis = -1 }},
		{name: "zero memory", mutate: func(l *ResourceLimits) { l.MemoryBytes = 0 }},
		{name: "negative memory", mutate: func(l *ResourceLimits) { l.MemoryBytes = -1 }},
		{name: "zero wall time", mutate: func(l *ResourceLimits) { l.WallTimeMillis = 0 }},
		{name: "negative wall time", mutate: func(l *ResourceLimits) { l.WallTimeMillis = -1 }},
		{name: "zero process limit", mutate: func(l *ResourceLimits) { l.ProcessLimit = 0 }},
		{name: "negative process limit", mutate: func(l *ResourceLimits) { l.ProcessLimit = -1 }},
		{name: "zero output limit", mutate: func(l *ResourceLimits) { l.OutputBytes = 0 }},
		{name: "negative output limit", mutate: func(l *ResourceLimits) { l.OutputBytes = -1 }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validRequest()
			test.mutate(&request.Limits)
			if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestExecutionRequestValidateRejectsInvalidIdentifiersAndRuntimeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ExecutionRequest)
	}{
		{name: "oversized execution ID", mutate: func(r *ExecutionRequest) { r.ExecutionID = strings.Repeat("x", 129) }},
		{name: "whitespace attempt ID", mutate: func(r *ExecutionRequest) { r.AttemptID = "attempt 123" }},
		{name: "path-like problem version ID", mutate: func(r *ExecutionRequest) { r.ProblemVersionID = "../problem" }},
		{name: "empty test bundle ID", mutate: func(r *ExecutionRequest) { r.TestBundleID = "" }},
		{name: "empty runtime version", mutate: func(r *ExecutionRequest) { r.RuntimeVersion = "" }},
		{name: "oversized runtime version", mutate: func(r *ExecutionRequest) { r.RuntimeVersion = strings.Repeat("v", 33) }},
		{name: "whitespace runtime version", mutate: func(r *ExecutionRequest) { r.RuntimeVersion = "25 " }},
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

func TestExecutionRequestValidateAcceptsSubmitAndPython(t *testing.T) {
	t.Parallel()

	request := validRequest()
	request.Action = ActionSubmit
	request.Language = LanguagePython
	request.RuntimeVersion = "3.14"

	if err := request.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
