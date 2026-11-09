package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExecutionRequestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	request := validRequest()
	request.Action = ActionSubmit
	request.Language = LanguagePython
	request.RuntimeVersion = "3.14"

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var decoded ExecutionRequest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if !reflect.DeepEqual(decoded, request) {
		t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v", decoded, request)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("round-tripped request is invalid: %v", err)
	}
}

func TestExecutionRequestJSONUsesStableWireFieldNames(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode request fields: %v", err)
	}

	required := []string{
		"protocolVersion",
		"executionId",
		"attemptId",
		"problemVersionId",
		"action",
		"language",
		"runtimeVersion",
		"sourceArtifactId",
		"sourceSha256",
		"testBundleId",
		"limits",
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			t.Errorf("wire field %q is missing", field)
		}
	}

	for _, forbidden := range []string{"sourceCode", "hiddenTests", "expectedOutput"} {
		if _, ok := fields[forbidden]; ok {
			t.Errorf("request unexpectedly exposes forbidden field %q", forbidden)
		}
	}
}
