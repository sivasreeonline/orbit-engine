package runner

import (
	"context"
	"testing"
)

func TestDisabledQualificationGateNeverQualifies(t *testing.T) {
	gate := DisabledQualificationGate{}
	qualified, err := gate.Qualified(context.Background())
	if err != nil {
		t.Fatalf("Qualified() error = %v", err)
	}
	if qualified {
		t.Fatal("disabled qualification gate must never authorize execution")
	}
}
