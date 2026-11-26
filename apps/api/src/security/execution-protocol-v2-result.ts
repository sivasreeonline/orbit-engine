export interface V2CanonicalResultDigestInput {
  readonly executionId: string;
  readonly attemptId: string;
  readonly dispatchId: string;
  readonly runnerId: string;
  readonly keyId: string;
  readonly requestSha256: string;
  readonly policyRevision: string;
  readonly runtimeImageDigest: string;
  readonly infrastructureStatus: "SUCCEEDED" | "FAILED";
  readonly infrastructureErrorCode?: string | undefined;
  readonly compilationStatus: "NOT_STARTED" | "SUCCEEDED" | "FAILED";
  readonly verdict: string;
  readonly cleanupStatus: "SUCCEEDED" | "FAILED" | "UNKNOWN";
  readonly testsTotal: number;
  readonly testsPassed: number;
  readonly elapsedMs: number;
  readonly peakMemoryBytes?: number | undefined;
  readonly runnerVersion: string;
  readonly startedAt: string;
  readonly completedAt: string;
}

/**
 * V2 canonical result envelope. Property order and explicit nulls are part of
 * the wire contract; keep this byte representation mirrored by the Go runner.
 * Timestamps are normalized to UTC millisecond precision before encoding.
 */
export async function computeV2CanonicalResultSha256(
  input: V2CanonicalResultDigestInput,
): Promise<string> {
  const startedAt = new Date(input.startedAt);
  const completedAt = new Date(input.completedAt);
  if (!Number.isFinite(startedAt.getTime()) || !Number.isFinite(completedAt.getTime())) {
    throw new Error("v2_result_timestamp_invalid");
  }
  const envelope = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: input.executionId,
    attemptId: input.attemptId,
    dispatchId: input.dispatchId,
    runnerId: input.runnerId,
    keyId: input.keyId,
    requestSha256: input.requestSha256,
    policyRevision: input.policyRevision,
    runtimeImageDigest: input.runtimeImageDigest,
    infrastructureStatus: input.infrastructureStatus,
    infrastructureErrorCode: input.infrastructureErrorCode ?? null,
    compilationStatus: input.compilationStatus,
    verdict: input.verdict,
    cleanupStatus: input.cleanupStatus,
    testsTotal: input.testsTotal,
    testsPassed: input.testsPassed,
    elapsedMs: input.elapsedMs,
    peakMemoryBytes: input.peakMemoryBytes ?? null,
    runnerVersion: input.runnerVersion,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
  };
  const bytes = new TextEncoder().encode(JSON.stringify(envelope));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
