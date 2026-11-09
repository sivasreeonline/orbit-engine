package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validRequestJSON(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatalf("marshal valid request: %v", err)
	}
	return body
}

func TestDecodeExecutionRequestAcceptsValidRequest(t *testing.T) {
	t.Parallel()

	request, err := DecodeExecutionRequest(bytes.NewReader(validRequestJSON(t)))
	if err != nil {
		t.Fatalf("DecodeExecutionRequest() error = %v", err)
	}
	if request.ExecutionID != "exec_123" || request.Action != ActionRun {
		t.Fatalf("decoded request = %+v", request)
	}
}

func TestDecodeExecutionRequestRejectsUnknownAndSensitiveFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		field string
	}{
		{name: "source code", field: `"sourceCode":"public class Main {}"`},
		{name: "hidden tests", field: `"hiddenTests":[{"input":"secret"}]`},
		{name: "expected output", field: `"expectedOutput":"secret"`},
		{name: "credentials", field: `"databaseUrl":"postgres://secret"`},
		{name: "unreviewed field", field: `"futureFlag":true`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := validRequestJSON(t)
			body = append(body[:len(body)-1], []byte(","+test.field+"}")...)
			_, err := DecodeExecutionRequest(bytes.NewReader(body))
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestRejectsDuplicateObjectKeys(t *testing.T) {
	t.Parallel()

	body := validRequestJSON(t)
	duplicateTopLevel := bytes.Replace(
		body,
		[]byte(`"protocolVersion":"v1"`),
		[]byte(`"protocolVersion":"v1","protocolVersion":"v1"`),
		1,
	)
	_, err := DecodeExecutionRequest(bytes.NewReader(duplicateTopLevel))
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("top-level duplicate error = %v, want ErrInvalidJSON", err)
	}

	duplicateNested := bytes.Replace(
		body,
		[]byte(`"cpuQuotaMillis":1000`),
		[]byte(`"cpuQuotaMillis":1000,"cpuQuotaMillis":2000`),
		1,
	)
	_, err = DecodeExecutionRequest(bytes.NewReader(duplicateNested))
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("nested duplicate error = %v, want ErrInvalidJSON", err)
	}
}

func TestDecodeExecutionRequestRejectsNonCanonicalFieldCasing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		canonical  string
		nonCanonical string
	}{
		{name: "top-level execution id", canonical: `"executionId"`, nonCanonical: `"ExecutionID"`},
		{name: "top-level protocol version", canonical: `"protocolVersion"`, nonCanonical: `"ProtocolVersion"`},
		{name: "nested memory limit", canonical: `"memoryBytes"`, nonCanonical: `"MemoryBytes"`},
		{name: "nested cpu limit", canonical: `"cpuQuotaMillis"`, nonCanonical: `"CpuQuotaMillis"`},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := bytes.Replace(
				validRequestJSON(t),
				[]byte(test.canonical),
				[]byte(test.nonCanonical),
				1,
			)
			_, err := DecodeExecutionRequest(bytes.NewReader(body))
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestRejectsMalformedOrMultipleValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"protocolVersion":`},
		{name: "array instead of object", body: `[]`},
		{name: "null instead of object", body: `null`},
		{name: "multiple JSON values", body: string(validRequestJSON(t)) + ` {}`},
		{name: "trailing garbage", body: string(validRequestJSON(t)) + ` garbage`},
		{name: "empty body", body: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeExecutionRequest(strings.NewReader(test.body))
			if !errors.Is(err, ErrInvalidJSON) {
				t.Fatalf("error = %v, want ErrInvalidJSON", err)
			}
		})
	}
}

func TestDecodeExecutionRequestEnforcesBodyLimit(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte(" "), MaxExecutionRequestBytes+1)
	_, err := DecodeExecutionRequest(bytes.NewReader(body))
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("error = %v, want ErrInvalidJSON", err)
	}
}

func TestDecodeExecutionRequestValidatesDecodedFields(t *testing.T) {
	t.Parallel()

	body := validRequestJSON(t)
	body = bytes.Replace(body, []byte(`"memoryBytes":134217728`), []byte(`"memoryBytes":0`), 1)
	_, err := DecodeExecutionRequest(bytes.NewReader(body))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
}
