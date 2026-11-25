import { describe, expect, it } from "vitest";
import type { ExecutionProtocolV2Policy } from "./execution-protocol-v2-policy";
import {
  buildExecutionProtocolV2Request,
  type ExecutionProtocolV2Entropy,
} from "./execution-protocol-v2-request";

const policy: ExecutionProtocolV2Policy = {
  policyRevision: "skyhigh-v2-policy-1",
  runtimeImageDigests: {
    java: `sha256:${"a".repeat(64)}`,
    python: `sha256:${"b".repeat(64)}`,
  },
  limits: {
    cpuQuotaMillis: 2000,
    memoryBytes: 536870912,
    wallTimeMillis: 10000,
    processLimit: 32,
    outputBytes: 1048576,
    scratchBytes: 268435456,
    scratchInodes: 4096,
  },
};

const input = {
  executionId: "11111111-1111-4111-8111-111111111111",
  attemptId: "22222222-2222-4222-8222-222222222222",
  problemVersionId: "33333333-3333-4333-8333-333333333333",
  action: "RUN" as const,
  language: "java" as const,
  runtimeVersion: "25",
  sourceArtifactId: "44444444-4444-4444-8444-444444444444",
  sourceSha256: "c".repeat(64),
  testBundleId: "33333333-3333-4333-8333-333333333333-run-0123456789abcdef",
  intakeAt: new Date("2026-11-26T10:00:00.000Z"),
};

const entropy: ExecutionProtocolV2Entropy = {
  randomUUID: () => "55555555-5555-4555-a555-555555555555",
  randomBytes: (length) => new Uint8Array(length).fill(0x11),
};

describe("buildExecutionProtocolV2Request", () => {
  it("builds the exact 16-field v2 request using trusted policy and immutable identities", async () => {
    const built = await buildExecutionProtocolV2Request(input, policy, entropy);

    expect(Object.keys(built.request)).toEqual([
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
    ]);
    expect(built.request).toMatchObject({
      protocolVersion: "v2",
      correlationId: "55555555-5555-4555-a555-555555555555",
      runtimeImageDigest: `sha256:${"a".repeat(64)}`,
      comparisonPolicy: "EXACT_BYTES",
      deadlineAt: "2026-11-26T10:00:10.000Z",
      cancellationRef: `cxl_${"11".repeat(16)}`,
      limits: policy.limits,
    });
    expect(new TextDecoder().decode(built.requestBytes)).toBe(JSON.stringify(built.request));
    expect(built.requestSha256).toMatch(/^[0-9a-f]{64}$/);
    const digestBuffer = new ArrayBuffer(built.requestBytes.byteLength);
    new Uint8Array(digestBuffer).set(built.requestBytes);
    const expectedDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", digestBuffer));
    const expectedHash = Array.from(expectedDigest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    expect(built.requestSha256).toBe(expectedHash);

    const repeated = await buildExecutionProtocolV2Request(input, policy, entropy);
    expect(repeated.requestBytes).toEqual(built.requestBytes);
    expect(repeated.requestSha256).toBe(built.requestSha256);
    expect(built.intakeAt.toISOString()).toBe("2026-11-26T10:00:00.000Z");
  });

  it("selects the language-specific immutable runtime image", async () => {
    const built = await buildExecutionProtocolV2Request(
      { ...input, language: "python" },
      policy,
      entropy,
    );
    expect(built.request.runtimeImageDigest).toBe(`sha256:${"b".repeat(64)}`);
  });

  it("rejects invalid identity and source hash fields", async () => {
    await expect(buildExecutionProtocolV2Request(
      { ...input, executionId: "not-a-uuid" },
      policy,
      entropy,
    )).rejects.toThrow("protocol_v2_request_execution_id_invalid");
    await expect(buildExecutionProtocolV2Request(
      { ...input, sourceSha256: "ABC" },
      policy,
      entropy,
    )).rejects.toThrow("protocol_v2_request_source_sha256_invalid");
  });

  it("rejects malformed runtime digests and resource limits", async () => {
    await expect(buildExecutionProtocolV2Request(input, {
      ...policy,
      runtimeImageDigests: { ...policy.runtimeImageDigests, java: "java:latest" },
    }, entropy)).rejects.toThrow("protocol_v2_request_runtime_image_digest_invalid");

    await expect(buildExecutionProtocolV2Request(input, {
      ...policy,
      limits: { ...policy.limits, outputBytes: 0 },
    }, entropy)).rejects.toThrow("protocol_v2_request_resource_limits_invalid");
  });

  it("rejects deadlines that exceed the database's ten-minute ceiling", async () => {
    const unsafePolicy = {
      ...policy,
      limits: { ...policy.limits, wallTimeMillis: 600001 },
    };
    await expect(buildExecutionProtocolV2Request(input, unsafePolicy, entropy))
      .rejects.toThrow("protocol_v2_request_wall_time_out_of_range");
  });

  it("rejects non-v4 protocol correlation IDs and invalid cancellation entropy", async () => {
    const invalidCorrelation: ExecutionProtocolV2Entropy = {
      ...entropy,
      randomUUID: () => "55555555-5555-1555-a555-555555555555",
    };
    await expect(buildExecutionProtocolV2Request(input, policy, invalidCorrelation))
      .rejects.toThrow("protocol_v2_request_correlation_id_invalid");

    const invalidCancellation: ExecutionProtocolV2Entropy = {
      ...entropy,
      randomBytes: () => new Uint8Array(8),
    };
    await expect(buildExecutionProtocolV2Request(input, policy, invalidCancellation))
      .rejects.toThrow("protocol_v2_request_cancellation_entropy_invalid");
  });
});
