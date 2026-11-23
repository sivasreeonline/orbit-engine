import canonicalize from "canonicalize";
import { deriveReplayCheckpointOperationId } from "../../../api/src/gossip/gossip-replay-checkpoint-intent";
import {
  WitnessAmbiguousCommit,
  WitnessAppendConflict,
  WitnessIdempotencyConflict,
  type StoredWitnessCheckpoint,
  type WitnessCheckpoint,
  type WitnessCheckpointReceipt,
  type WitnessCheckpointScope,
  type WitnessProviderAdapter,
} from "./witness-provider-adapter";

const ZERO_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_SNAPSHOT_BYTES = 512 * 1024;

export type MonitorReplayCheckpointResult =
  | {
      readonly status: "CHECKPOINTED" | "ALREADY_CHECKPOINTED";
      readonly generation: number;
      readonly digest: string;
      readonly operationId: string;
      readonly receipt: WitnessCheckpointReceipt;
    };

export class MonitorReplayCheckpointError extends Error {
  constructor(
    readonly reason:
      | "invalid_scope"
      | "invalid_snapshot"
      | "operation_conflict"
      | "receipt_mismatch"
      | "operation_not_recoverable"
      | "latest_readback_mismatch"
      | "stale_operation",
    message: string,
  ) {
    super(message);
    this.name = "MonitorReplayCheckpointError";
  }
}

function validScope(scope: WitnessCheckpointScope): boolean {
  return Boolean(
    scope &&
    typeof scope.trustDomainId === "string" && scope.trustDomainId.length > 0 &&
    scope.trustDomainId.length <= 256 &&
    typeof scope.witnessId === "string" && scope.witnessId.length > 0 &&
    scope.witnessId.length <= 256 &&
    typeof scope.authorityId === "string" && scope.authorityId.length > 0 &&
    scope.authorityId.length <= 256 &&
    typeof scope.hostId === "string" && scope.hostId.length > 0 &&
    scope.hostId.length <= 256
  );
}

function sameScope(a: WitnessCheckpointScope, b: WitnessCheckpointScope): boolean {
  return a.trustDomainId === b.trustDomainId &&
    a.witnessId === b.witnessId &&
    a.authorityId === b.authorityId &&
    a.hostId === b.hostId;
}

function canonicalSnapshotBytes(snapshot: unknown): Uint8Array {
  if (
    snapshot === null ||
    typeof snapshot !== "object" ||
    Array.isArray(snapshot) ||
    Object.getPrototypeOf(snapshot) !== Object.prototype
  ) {
    throw new MonitorReplayCheckpointError(
      "invalid_snapshot",
      "replay snapshot must be a plain JSON object",
    );
  }
  let serialized: string | undefined;
  try {
    serialized = canonicalize(snapshot);
  } catch {
    serialized = undefined;
  }
  if (typeof serialized !== "string") {
    throw new MonitorReplayCheckpointError(
      "invalid_snapshot",
      "replay snapshot is not canonicalizable JSON",
    );
  }
  const bytes = new TextEncoder().encode(serialized);
  if (bytes.length === 0 || bytes.length > MAX_SNAPSHOT_BYTES) {
    throw new MonitorReplayCheckpointError(
      "invalid_snapshot",
      "canonical replay snapshot is empty or exceeds the size limit",
    );
  }
  return bytes;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function exactCheckpoint(a: WitnessCheckpoint, b: WitnessCheckpoint): boolean {
  return sameScope(a.scope, b.scope) &&
    a.generation === b.generation &&
    a.operationId === b.operationId &&
    a.phase === b.phase &&
    a.checkpointDigest === b.checkpointDigest &&
    a.previousDigest === b.previousDigest &&
    bytesEqual(a.canonicalSnapshotBytes, b.canonicalSnapshotBytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a[index]! ^ b[index]!;
  }
  return difference === 0;
}

function assertRecord(
  record: StoredWitnessCheckpoint | null,
  expected: WitnessCheckpoint,
): asserts record is StoredWitnessCheckpoint {
  if (!record || !exactCheckpoint(record.checkpoint, expected)) {
    throw new MonitorReplayCheckpointError(
      "operation_conflict",
      "witness operation is missing or bound to different canonical replay snapshot bytes",
    );
  }
  const receipt = record.receipt;
  if (
    !sameScope(receipt.scope, expected.scope) ||
    receipt.generation !== expected.generation ||
    receipt.operationId !== expected.operationId ||
    receipt.checkpointDigest !== expected.checkpointDigest ||
    receipt.previousDigest !== expected.previousDigest ||
    typeof receipt.consistencyToken !== "string" ||
    receipt.consistencyToken.trim().length === 0
  ) {
    throw new MonitorReplayCheckpointError(
      "receipt_mismatch",
      "witness receipt does not bind the exact replay checkpoint",
    );
  }
}

function exactReceipt(
  a: WitnessCheckpointReceipt,
  b: WitnessCheckpointReceipt,
): boolean {
  return sameScope(a.scope, b.scope) &&
    a.generation === b.generation &&
    a.operationId === b.operationId &&
    a.checkpointDigest === b.checkpointDigest &&
    a.previousDigest === b.previousDigest &&
    a.consistencyToken === b.consistencyToken;
}

function result(
  status: "CHECKPOINTED" | "ALREADY_CHECKPOINTED",
  record: StoredWitnessCheckpoint,
): MonitorReplayCheckpointResult {
  return {
    status,
    generation: record.checkpoint.generation,
    digest: record.checkpoint.checkpointDigest,
    operationId: record.checkpoint.operationId,
    receipt: record.receipt,
  };
}

/**
 * Provider-neutral orchestration for exact immutable replay-snapshot commits.
 * It does not authenticate receipt signatures or prove provider durability:
 * the returned receipt must still pass the FENCE signed-evidence verifier.
 */
export async function checkpointMonitorReplaySnapshot(
  adapter: WitnessProviderAdapter,
  scope: WitnessCheckpointScope,
  snapshot: unknown,
  expectedPredecessor?: { readonly generation: number; readonly digest: string },
): Promise<MonitorReplayCheckpointResult> {
  if (!validScope(scope)) {
    throw new MonitorReplayCheckpointError("invalid_scope", "witness checkpoint scope is malformed");
  }

  const bytes = canonicalSnapshotBytes(snapshot);
  const digest = await sha256Hex(bytes);
  if (!DIGEST.test(digest)) throw new Error("SHA-256 returned an invalid digest");
  if (expectedPredecessor && (
    !Number.isSafeInteger(expectedPredecessor.generation) ||
    expectedPredecessor.generation < 0 ||
    !DIGEST.test(expectedPredecessor.digest)
  )) {
    throw new MonitorReplayCheckpointError("invalid_scope", "expected witness predecessor is malformed");
  }

  const operationId = expectedPredecessor
    ? await deriveReplayCheckpointOperationId({ scope, expectedPredecessor, snapshotDigest: digest })
    : `fence-monitor-replay-${digest}`;

  const existing = await adapter.readByOperation(scope, operationId);
  if (existing) {
    const expected = existing.checkpoint;
    if (
      !sameScope(expected.scope, scope) ||
      expected.phase !== "MONITOR_GOSSIP_REPLAY_V1" ||
      expected.checkpointDigest !== digest ||
      !bytesEqual(expected.canonicalSnapshotBytes, bytes)
    ) {
      throw new MonitorReplayCheckpointError(
        "operation_conflict",
        "deterministic operation ID is already bound to different replay content",
      );
    }
    assertRecord(existing, expected);
    const latest = await adapter.readLatest(scope);
    if (!latest || !exactCheckpoint(latest.checkpoint, expected) ||
        !exactReceipt(latest.receipt, existing.receipt)) {
      throw new MonitorReplayCheckpointError(
        "stale_operation",
        "exact replay operation exists but is no longer the current witness head",
      );
    }
    return result("ALREADY_CHECKPOINTED", existing);
  }

  const latest = await adapter.readLatest(scope);
  if (latest && !sameScope(latest.checkpoint.scope, scope)) {
    throw new MonitorReplayCheckpointError("invalid_scope", "latest witness record has another scope");
  }
  const expectedGeneration = expectedPredecessor?.generation ?? (latest?.checkpoint.generation ?? 0);
  const expectedDigest = expectedPredecessor?.digest ?? (latest?.checkpoint.checkpointDigest ?? ZERO_DIGEST);
  if (
    !Number.isSafeInteger(expectedGeneration) ||
    expectedGeneration < 0 ||
    !DIGEST.test(expectedDigest)
  ) {
    throw new MonitorReplayCheckpointError("latest_readback_mismatch", "latest witness predecessor is malformed");
  }

  if (
    (latest?.checkpoint.generation ?? 0) !== expectedGeneration ||
    (latest?.checkpoint.checkpointDigest ?? ZERO_DIGEST) !== expectedDigest
  ) {
    throw new MonitorReplayCheckpointError(
      "stale_operation",
      "witness latest head does not match the persisted expected predecessor",
    );
  }

  const checkpoint: WitnessCheckpoint = {
    scope,
    generation: expectedGeneration + 1,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    checkpointDigest: digest,
    previousDigest: expectedDigest,
    canonicalSnapshotBytes: bytes,
  };

  let appendReceipt: WitnessCheckpointReceipt | undefined;
  try {
    appendReceipt = await adapter.appendIfCurrent(
      checkpoint,
      { generation: expectedGeneration, digest: expectedDigest },
      operationId,
    );
  } catch (error) {
    if (error instanceof WitnessAppendConflict || error instanceof WitnessIdempotencyConflict) {
      throw error;
    }
    if (!(error instanceof WitnessAmbiguousCommit)) throw error;
    const recovered = await adapter.readByOperation(scope, operationId);
    if (!recovered) {
      throw new MonitorReplayCheckpointError(
        "operation_not_recoverable",
        "ambiguous append acknowledgement has no immutable operation record",
      );
    }
    assertRecord(recovered, checkpoint);
    appendReceipt = recovered.receipt;
  }

  const committed = await adapter.readByOperation(scope, operationId);
  assertRecord(committed, checkpoint);
  if (!appendReceipt ||
      !exactReceipt(committed.receipt, appendReceipt)) {
    throw new MonitorReplayCheckpointError(
      "receipt_mismatch",
      "operation readback differs from append acknowledgement",
    );
  }

  const current = await adapter.readLatest(scope);
  if (
    !current ||
    !exactCheckpoint(current.checkpoint, checkpoint) ||
    !exactReceipt(current.receipt, committed.receipt)
  ) {
    throw new MonitorReplayCheckpointError(
      "latest_readback_mismatch",
      "strong latest readback does not identify the exact committed operation",
    );
  }

  return result("CHECKPOINTED", committed);
}
