package runner

import "context"

// DisabledQualificationGate is the production bootstrap default. It cannot be
// opened by configuration or environment variables; a separately reviewed
// Linux sandbox attestation integration must replace it before any claims.
type DisabledQualificationGate struct{}

func (DisabledQualificationGate) Qualified(context.Context) (bool, error) {
	return false, nil
}
