package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxExecutionRequestBytes = 64 * 1024

var ErrInvalidJSON = errors.New("invalid execution request JSON")

// DecodeExecutionRequest performs bounded, strict decoding before field validation.
// Unknown fields are rejected so source code, hidden tests, credentials, or future
// unreviewed fields cannot silently cross the runner protocol boundary.
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

	if err := rejectDuplicateJSONKeys(body); err != nil {
		return request, fmt.Errorf("%w: duplicate object key", ErrInvalidJSON)
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

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
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
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
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
