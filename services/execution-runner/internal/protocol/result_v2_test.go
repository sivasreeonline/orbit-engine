package protocol

import (
	"testing"
	"time"
)

func TestCanonicalResultV2DigestMatchesCrossLanguageVector(t *testing.T) {
	peakMemory := int64(4_194_304)
	digest, err := CanonicalResultV2Digest(CanonicalResultV2{
		Format: "SKYHIGH-RUNNER-RESULT-V2",
		ExecutionID: "60000000-0000-4000-8000-000000000001",
		AttemptID: "70000000-0000-4000-8000-000000000001",
		DispatchID: "50000000-0000-4000-8000-000000000001",
		RunnerID: "90000000-0000-4000-8000-000000000001",
		KeyID: "runner-test-key",
		RequestSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyRevision: "policy-2026-11",
		RuntimeImageDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		InfrastructureStatus: "SUCCEEDED",
		CompilationStatus: "SUCCEEDED",
		Verdict: "ACCEPTED",
		CleanupStatus: "SUCCEEDED",
		TestsTotal: 4,
		TestsPassed: 4,
		ElapsedMs: 75,
		PeakMemoryBytes: &peakMemory,
		RunnerVersion: "runner-test-1",
		StartedAt: "2026-11-26T05:00:00Z",
		CompletedAt: "2026-11-26T05:00:00.075Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "3f4aabf0daca5b20170d13b65305049ad6a56a8bd30eb35b9daab00c68e82277"
	if digest != expected {
		t.Fatalf("canonical digest mismatch: got %s, want %s", digest, expected)
	}
}

func TestCanonicalResultV2DigestRejectsIncompleteBindings(t *testing.T) {
	_, err := CanonicalResultV2Digest(CanonicalResultV2{
		Format: "SKYHIGH-RUNNER-RESULT-V2",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err == nil {
		t.Fatal("incomplete v2 result binding was accepted")
	}
}
