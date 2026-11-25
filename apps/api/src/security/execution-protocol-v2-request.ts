import type { ExecutionAction, ExecutionLanguage } from "../db/execution-intake-repository";
import type { ExecutionProtocolV2Policy } from "./execution-protocol-v2-policy";

export interface ExecutionProtocolV2Request {
  readonly protocolVersion: "v2";
  readonly correlationId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly problemVersionId: string;
  readonly action: ExecutionAction;
  readonly language: ExecutionLanguage;
  readonly runtimeVersion: string;
  readonly runtimeImageDigest: string;
  readonly sourceArtifactId: string;
  readonly sourceSha256: string;
  readonly testBundleId: string;
  readonly comparisonPolicy: "EXACT_BYTES";
  readonly deadlineAt: string;
  readonly cancellationRef: string;
  readonly limits: ExecutionProtocolV2Policy["limits"];
}

export interface BuiltExecutionProtocolV2Request {
  readonly request: ExecutionProtocolV2Request;
  readonly requestBytes: Uint8Array;
  readonly requestSha256: string;
  readonly intakeAt: Date;
}

export interface ExecutionProtocolV2Entropy {
  randomUUID(): string;
  randomBytes(length: number): Uint8Array;
}

const webCryptoEntropy: ExecutionProtocolV2Entropy = {
  randomUUID: () => crypto.randomUUID(),
  randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
};

function isUuidV4(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requireUuid(value: string, field: string): void {
  if (!isUuidV4(value)) throw new Error(`protocol_v2_request_${field}_invalid`);
}

function requireOpaqueId(value: string, field: string): void {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(value)) {
    throw new Error(`protocol_v2_request_${field}_invalid`);
  }
}

/**
 * Builds the exact v2 wire bytes from trusted intake identity and server policy.
 * The caller must persist these bytes and digest atomically; retries must reuse
 * the persisted bytes rather than invoke this builder again.
 */
export async function buildExecutionProtocolV2Request(
  input: {
    readonly executionId: string;
    readonly attemptId: string;
    readonly problemVersionId: string;
    readonly action: ExecutionAction;
    readonly language: ExecutionLanguage;
    readonly runtimeVersion: string;
    readonly sourceArtifactId: string;
    readonly sourceSha256: string;
    readonly testBundleId: string;
    readonly intakeAt: Date;
  },
  policy: ExecutionProtocolV2Policy,
  entropy: ExecutionProtocolV2Entropy = webCryptoEntropy,
): Promise<BuiltExecutionProtocolV2Request> {
  requireUuid(input.executionId, "execution_id");
  requireUuid(input.attemptId, "attempt_id");
  requireUuid(input.problemVersionId, "problem_version_id");
  requireUuid(input.sourceArtifactId, "source_artifact_id");
  requireOpaqueId(input.testBundleId, "test_bundle_id");
  if (!/^[0-9a-f]{64}$/.test(input.sourceSha256)) {
    throw new Error("protocol_v2_request_source_sha256_invalid");
  }
  if (!/^[A-Za-z0-9._+-]{1,32}$/.test(input.runtimeVersion)) {
    throw new Error("protocol_v2_request_runtime_version_invalid");
  }
  const intakeTime = input.intakeAt.getTime();
  if (!Number.isFinite(intakeTime)) throw new Error("protocol_v2_request_intake_time_invalid");
  const wallTimeMillis = policy.limits.wallTimeMillis;
  if (!Number.isSafeInteger(wallTimeMillis) || wallTimeMillis <= 0 || wallTimeMillis > 600000) {
    throw new Error("protocol_v2_request_wall_time_out_of_range");
  }
  const limitValues = [
    policy.limits.cpuQuotaMillis,
    policy.limits.memoryBytes,
    policy.limits.wallTimeMillis,
    policy.limits.processLimit,
    policy.limits.outputBytes,
    policy.limits.scratchBytes,
    policy.limits.scratchInodes,
  ];
  if (limitValues.some((value) => !Number.isSafeInteger(value) || value <= 0) ||
      policy.limits.scratchBytes > 536870912 || policy.limits.scratchInodes > 8192) {
    throw new Error("protocol_v2_request_resource_limits_invalid");
  }
  const runtimeImageDigest = policy.runtimeImageDigests[input.language];
  if (!/^sha256:[0-9a-f]{64}$/.test(runtimeImageDigest)) {
    throw new Error("protocol_v2_request_runtime_image_digest_invalid");
  }

  const correlationId = entropy.randomUUID();
  requireUuid(correlationId, "correlation_id");
  const cancellationBytes = entropy.randomBytes(16);
  if (cancellationBytes.byteLength !== 16) {
    throw new Error("protocol_v2_request_cancellation_entropy_invalid");
  }
  const cancellationRef = `cxl_${toHex(cancellationBytes)}`;
  const deadlineTime = intakeTime + wallTimeMillis;
  if (!Number.isFinite(deadlineTime)) throw new Error("protocol_v2_request_deadline_invalid");
  const deadlineAt = new Date(deadlineTime).toISOString();
  const request: ExecutionProtocolV2Request = {
    protocolVersion: "v2",
    correlationId,
    executionId: input.executionId,
    attemptId: input.attemptId,
    problemVersionId: input.problemVersionId,
    action: input.action,
    language: input.language,
    runtimeVersion: input.runtimeVersion,
    runtimeImageDigest,
    sourceArtifactId: input.sourceArtifactId,
    sourceSha256: input.sourceSha256,
    testBundleId: input.testBundleId,
    comparisonPolicy: "EXACT_BYTES",
    deadlineAt,
    cancellationRef,
    limits: { ...policy.limits },
  };
  const requestBytes = new TextEncoder().encode(JSON.stringify(request));
  if (requestBytes.byteLength < 1 || requestBytes.byteLength > 16384) {
    throw new Error("protocol_v2_request_size_invalid");
  }
  const digestBuffer = new ArrayBuffer(requestBytes.byteLength);
  new Uint8Array(digestBuffer).set(requestBytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", digestBuffer));

  return {
    request,
    requestBytes,
    requestSha256: toHex(digest),
    intakeAt: new Date(intakeTime),
  };
}
