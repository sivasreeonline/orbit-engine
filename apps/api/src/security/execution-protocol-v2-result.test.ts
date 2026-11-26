import { describe, expect, it } from "vitest";
import { computeV2CanonicalResultSha256 } from "./execution-protocol-v2-result";

describe("v2 canonical runner result digest", () => {
  it("matches the shared Go/API canonical envelope vector", async () => {
    await expect(computeV2CanonicalResultSha256({
      executionId: "60000000-0000-4000-8000-000000000001",
      attemptId: "70000000-0000-4000-8000-000000000001",
      dispatchId: "50000000-0000-4000-8000-000000000001",
      runnerId: "90000000-0000-4000-8000-000000000001",
      keyId: "runner-test-key",
      requestSha256: "a".repeat(64),
      policyRevision: "policy-2026-11",
      runtimeImageDigest: "b".repeat(64),
      infrastructureStatus: "SUCCEEDED",
      compilationStatus: "SUCCEEDED",
      verdict: "ACCEPTED",
      cleanupStatus: "SUCCEEDED",
      testsTotal: 4,
      testsPassed: 4,
      elapsedMs: 75,
      peakMemoryBytes: 4_194_304,
      runnerVersion: "runner-test-1",
      startedAt: "2026-11-26T05:00:00Z",
      completedAt: "2026-11-26T05:00:00.075Z",
    })).resolves.toBe("3f4aabf0daca5b20170d13b65305049ad6a56a8bd30eb35b9daab00c68e82277");
  });
});
