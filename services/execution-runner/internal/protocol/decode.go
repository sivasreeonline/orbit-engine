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
