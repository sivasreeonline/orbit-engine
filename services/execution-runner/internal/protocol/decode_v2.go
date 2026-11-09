package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const MaxExecutionRequestV2Bytes = 64 * 1024

var executionRequestV2JSONKeys = stringSet(
	"protocolVersion",
	"correlationId",
	"executionId",
	"attemptId",
	"problemVersionId",
	"action",
	"language",
	"runtimeVersion",
	"runtimeImageDigest",
	"sourceArtifactId",
	"sourceSha256",
	"testBundleId",
	"comparisonPolicy",
	"deadlineAt",
	"cancellationRef",
	"limits",
)

var resourceLimitsV2JSONKeys = stringSet(
	"cpuQuotaMillis",
	"memoryBytes",
	"wallTimeMillis",
	"processLimit",
	"outputBytes",
	"scratchBytes",
	"scratchInodes",
)

func DecodeExecutionRequestV2(reader io.Reader) (ExecutionRequestV2, error) {
	return DecodeExecutionRequestV2At(reader, time.Now().UTC())
}

func DecodeExecutionRequestV2At(reader io.Reader, now time.Time) (ExecutionRequestV2, error) {
	var request ExecutionRequestV2
	if reader == nil {
		return request, fmt.Errorf("%w: empty body", ErrInvalidJSON)
	}
	body, err := io.ReadAll(io.LimitReader(reader, MaxExecutionRequestV2Bytes+1))
	if err != nil {
		return request, fmt.Errorf("%w: unreadable body", ErrInvalidJSON)
	}
	if len(body) == 0 {
		return request, fmt.Errorf("%w: empty body", ErrInvalidJSON)
	}
	if len(body) > MaxExecutionRequestV2Bytes {
		return request, fmt.Errorf("%w: body exceeds limit", ErrInvalidJSON)
	}
	if err := validateCanonicalV2JSONKeys(body); err != nil {
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
	if err := request.ValidateAt(now); err != nil {
		return ExecutionRequestV2{}, err
	}
	return request, nil
}

func validateCanonicalV2JSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("execution request must be a JSON object")
	}
	if err := consumeV2JSONObject(decoder, executionRequestV2JSONKeys, true); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func consumeV2JSONValue(decoder *json.Decoder, allowedObjectKeys map[string]struct{}) error {
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
		return consumeV2JSONObject(decoder, allowedObjectKeys, false)
	case '[':
		for decoder.More() {
			if err := consumeV2JSONValue(decoder, nil); err != nil {
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

func consumeV2JSONObject(
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
			childKeys = resourceLimitsV2JSONKeys
		}
		if err := consumeV2JSONValue(decoder, childKeys); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("unterminated JSON object")
	}
	return nil
}
