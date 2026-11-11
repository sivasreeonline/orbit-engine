package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const MaxExecutionRequestBytes = 64 * 1024

var ErrInvalidJSON = errors.New("invalid execution request JSON")

var executionRequestJSONKeys = stringSet(
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
)

var resourceLimitsJSONKeys = stringSet(
	"cpuQuotaMillis",
	"memoryBytes",
	"wallTimeMillis",
	"processLimit",
	"outputBytes",
)

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// DecodeExecutionRequest performs bounded, strict decoding before field validation.
// It accepts only canonical JSON field names so encoding/json's case-insensitive
// struct-field matching cannot make differently cased keys target the same field.
func DecodeExecutionRequest(reader io.Reader) (ExecutionRequest, error) {
	var request ExecutionRequest

	if reader == nil {
		return request, fmt.Errorf("%w: empty body", ErrInvalidJSON)
	}

	body, err := io.ReadAll(io.LimitReader(reader, MaxExecutionRequestBytes+1))
	if err != nil {
		return request, fmt.Errorf("%w: unreadable body", ErrInvalidJSON)
	}
	if len(body) == 0 {
		return request, fmt.Errorf("%w: empty body", ErrInvalidJSON)
	}
	if len(body) > MaxExecutionRequestBytes {
		return request, fmt.Errorf("%w: body exceeds limit", ErrInvalidJSON)
	}
	if !utf8.Valid(body) {
		return request, fmt.Errorf("%w: body is not valid UTF-8", ErrInvalidJSON)
	}

	if err := validateCanonicalJSONKeys(body); err != nil {
		return request, fmt.Errorf("%w: malformed, duplicate, unknown or non-canonical field", ErrInvalidJSON)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		return request, fmt.Errorf("%w: malformed or unsupported fields", ErrInvalidJSON)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return request, fmt.Errorf("%w: multiple JSON values", ErrInvalidJSON)
	}

	if err := request.Validate(); err != nil {
		return ExecutionRequest{}, err
	}

	return request, nil
}

// validateCanonicalJSONKeys rejects duplicate keys and any key that is not an
// exact member of the protocol's documented JSON schema. This is deliberately
// stricter than encoding/json, which also matches struct fields case-insensitively.
func validateCanonicalJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("execution request must be a JSON object")
	}
	if err := consumeJSONObject(decoder, executionRequestJSONKeys, true); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func consumeJSONValue(
	decoder *json.Decoder,
	allowedObjectKeys map[string]struct{},
	allowLimitsObject bool,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		if allowedObjectKeys == nil {
			return errors.New("object is not allowed at this protocol location")
		}
		return consumeJSONObject(decoder, allowedObjectKeys, allowLimitsObject)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, nil, false); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}

	return nil
}

func consumeJSONObject(
	decoder *json.Decoder,
	allowedKeys map[string]struct{},
	allowLimitsObject bool,
) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid JSON object key")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate JSON object key")
		}
		seen[key] = struct{}{}
		if _, allowed := allowedKeys[key]; !allowed {
			return errors.New("unknown or non-canonical JSON object key")
		}

		var childKeys map[string]struct{}
		if allowLimitsObject && key == "limits" {
			childKeys = resourceLimitsJSONKeys
		}
		if err := consumeJSONValue(decoder, childKeys, false); err != nil {
			return err
		}
	}

	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("unterminated JSON object")
	}
	return nil
}
