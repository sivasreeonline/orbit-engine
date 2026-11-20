package runner

import (
	"context"

	"github.com/sivasreeonline/orbit-engine/services/execution-runner/internal/protocol"
)

type TestVisibility string

const (
	TestVisibilityPublic TestVisibility = "PUBLIC"
	TestVisibilityHidden TestVisibility = "HIDDEN"
)

type OutputComparison string

const (
	CompareExactBytes             OutputComparison = "EXACT_BYTES"
	CompareTrimTrailingWhitespace OutputComparison = "TRIM_TRAILING_WHITESPACE"
)

type TestCase struct {
	ID             string
	Visibility     TestVisibility
	Input          []byte
	ExpectedOutput []byte
	Comparison     OutputComparison
}

type TestBundle struct {
	ProblemVersionID string
	Cases            []TestCase
}

// ArtifactResolver is implemented by the authenticated runner control-plane
// adapter. It must authorize every artifact against the execution request.
// Source bytes and test payloads never travel inside the dispatch message.
type ArtifactResolver interface {
	ResolveSource(context.Context, protocol.ExecutionRequest) ([]byte, error)
	ResolveTestBundle(context.Context, protocol.ExecutionRequest) (TestBundle, error)
}
