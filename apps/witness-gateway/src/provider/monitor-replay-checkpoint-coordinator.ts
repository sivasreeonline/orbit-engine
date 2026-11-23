import canonicalize from "canonicalize";
import { deriveReplayCheckpointOperationId } from "../../../api/src/gossip/gossip-replay-checkpoint-intent";
import {
  validateMonitorReplayCheckpointBody,
  type MonitorReplayCheckpointBody,
} from "../../../api/src/witness/witness-profile-verifier";
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
const encoder = new TextEncoder();

export type MonitorReplayCheckpointResult =
  | {
      readonly status: "CHECKPOINTED" | "ALREADY_CHECKPOINTED";
      readonly generation: number;
      readonly snapshotDigest: string;
      readonly checkpointDigest: string;
      readonly operationId: string;
      readonly receipt: WitnessCheckpointReceipt;
    };

export class MonitorReplayCheckpointError extends Error {
  constructor(
    readonly reason:
      | "invalid_scope"
      | "invalid_predecessor"
      | "invalid_snapshot"
      | "invalid_checkpoint_body"
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
    typeof scope.trustDomainId === "string" &&
    scope.trustDomainId.length > 0 &&
    scope.trustDomainId.length <= 256 &&
    typeof scope.witnessId === "string" &&
    scope.witnessId.length > 0 &&
    scope.witnessId.length <= 256 &&
    typeof scope.authorityId === "string" &&
    scope.authorityId.length > 0 &&
    scope.authorityId.length <= 256 &&
    typeof scope.hostId === "string" &&
    scope.hostId.length > 0 &&
    scope.hostId.length <= 256
  );
}

function sameScope(a: WitnessCheckpointScope, b: WitnessCheckpointScope): boolean {
  return a.trustDomainId === b.trustDomainId &&
    a.witnessId === b.witnessId &&
    a.authorityId === b.authorityId &&
    a.hostId === b.hostId;
}

function canonicalBytes(value: unknown, label: string): Uint8Array {
  let serialized: string | undefined;
  try {
    serialized = canonicalize(value);
  } catch {
    serialized = undefined;
  }
  if (typeof serialized !== "string") {
    throw new MonitorReplayCheckpointError("invalid_checkpoint_body", `${label} is not canonicalizable JSON`);
  }
  return encoder.encode(serialized);
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
  const bytes = encoder.encode(serialized);
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

function exactCheckpoint(a: WitnessCheckpoint, b: WitnessCheckpoint): boolean {
  return sameScope(a.scope, b.scope) &&
    a.generation === b.generation &&
    a.operationId === b.operationId &&
    a.phase === b.phase &&
    a.snapshotDigest === b.snapshotDigest &&
    a.checkpointDigest === b.checkpointDigest &&
    a.previousDigest === b.previousDigest &&
    bytesEqual(a.canonicalSnapshotBytes, b.canonicalSnapshotBytes) &&
    bytesEqual(a.canonicalCheckpointBodyBytes, b.canonicalCheckpointBodyBytes);
}

function assertRecord(
  record: StoredWitnessCheckpoint | null,
  expected: WitnessCheckpoint,
): asserts record is StoredWitnessCheckpoint {
  if (!record || !exactCheckpoint(record.checkpoint, expected)) {
    throw new MonitorReplayCheckpointError(
      "operation_conflict",
      "witness operation is missing or bound to different canonical snapshot/checkpoint bytes",
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
      "witness receipt does not bind the exact replay checkpoint digest",
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
    snapshotDigest: record.checkpoint.snapshotDigest,
    checkpointDigest: record.checkpoint.checkpointDigest,
    operationId: record.checkpoint.operationId,
    receipt: record.receipt,
  };
}

/**
 * Provider-neutral orchestration for an immutable monitor-replay checkpoint.
 * Snapshot bytes and signed checkpoint-body bytes are independently hashed,
 * stored, compared on idempotent recovery, and read back. This coordinator
 * does not verify a witness signature or qualify provider durability.
 */
export async function checkpointMonitorReplaySnapshot(
  adapter: WitnessProviderAdapter,
  scope: WitnessCheckpointScope,
  snapshot: unknown,
  checkpointBody: MonitorReplayCheckpointBody,
  expectedPredecessor: { readonly generation: number; readonly digest: string },
): Promise<MonitorReplayCheckpointResult> {
  if (!validScope(scope)) {
    throw new MonitorReplayCheckpointError("invalid_scope", "witness checkpoint scope is malformed");
  }
  if (
    !expectedPredecessor ||
    !Number.isSafeInteger(expectedPredecessor.generation) ||
    expectedPredecessor.generation < 0 ||
    !DIGEST.test(expectedPredecessor.digest)
  ) {
    throw new MonitorReplayCheckpointError("invalid_predecessor", "expected witness predecessor is malformed");
  }

  const snapshotBytes = canonicalSnapshotBytes(snapshot);
  const snapshotDigest = await sha256Hex(snapshotBytes);
  if (!DIGEST.test(snapshotDigest)) throw new Error("SHA-256 returned an invalid snapshot digest");

  try {
    validateMonitorReplayCheckpointBody(checkpointBody);
  } catch (error) {
    throw new MonitorReplayCheckpointError(
      "invalid_checkpoint_body",
      error instanceof Error ? error.message : "monitor replay checkpoint body is malformed",
    );
  }
  const checkpointBytes = canonicalBytes(checkpointBody, "monitor replay checkpoint body");
  const checkpointDigest = await sha256Hex(checkpointBytes);
  if (!DIGEST.test(checkpointDigest)) throw new Error("SHA-256 returned an invalid checkpoint digest");

  if (
    checkpointBody.trustDomainId !== scope.trustDomainId ||
    checkpointBody.witnessId !== scope.witnessId ||
    checkpointBody.authorityId !== scope.authorityId ||
    checkpointBody.hostId !== scope.hostId ||
    checkpointBody.generation !== expectedPredecessor.generation + 1 ||
    checkpointBody.previousCheckpointDigest !== expectedPredecessor.digest ||
    checkpointBody.snapshotDigest !== snapshotDigest ||
    checkpointBody.snapshotByteLength !== snapshotBytes.length ||
    (isRecord(snapshot) &&
      (snapshot.senderId !== checkpointBody.senderId ||
       snapshot.recipientId !== checkpointBody.recipientId))
  ) {
    throw new MonitorReplayCheckpointError(
      "invalid_checkpoint_body",
      "monitor replay checkpoint body does not bind the exact scope, predecessor and canonical snapshot",
    );
  }

  const operationId = await deriveReplayCheckpointOperationId({
    scope,
    expectedPredecessor,
    snapshotDigest,
  });
  if (checkpointBody.operationId !== operationId) {
    throw new MonitorReplayCheckpointError(
      "invalid_checkpoint_body",
      "monitor replay checkpoint operation ID does not match the persisted scope/predecessor/snapshot identity",
    );
  }

  const expectedCheckpoint: WitnessCheckpoint = {
    scope,
    generation: checkpointBody.generation,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    snapshotDigest,
    checkpointDigest,
    previousDigest: expectedPredecessor.digest,
    canonicalSnapshotBytes: snapshotBytes,
    canonicalCheckpointBodyBytes: checkpointBytes,
  };

  const existing = await adapter.readByOperation(scope, operationId);
  if (existing) {
    assertRecord(existing, expectedCheckpoint);
    const latest = await adapter.readLatest(scope);
    if (!latest || !exactCheckpoint(latest.checkpoint, expectedCheckpoint) ||
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
  if (
    (latest?.checkpoint.generation ?? 0) !== expectedPredecessor.generation ||
    (latest?.checkpoint.checkpointDigest ?? ZERO_DIGEST) !== expectedPredecessor.digest
  ) {
    throw new MonitorReplayCheckpointError(
      "stale_operation",
      "witness latest head does not match the persisted expected predecessor",
    );
  }

  let appendReceipt: WitnessCheckpointReceipt | undefined;
  try {
    appendReceipt = await adapter.appendIfCurrent(
      expectedCheckpoint,
      expectedPredecessor,
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
    assertRecord(recovered, expectedCheckpoint);
    appendReceipt = recovered.receipt;
  }

  const committed = await adapter.readByOperation(scope, operationId);
  assertRecord(committed, expectedCheckpoint);
  if (!appendReceipt || !exactReceipt(committed.receipt, appendReceipt)) {
    throw new MonitorReplayCheckpointError(
      "receipt_mismatch",
      "operation readback differs from append acknowledgement",
    );
  }

  const current = await adapter.readLatest(scope);
  if (
    !current ||
    !exactCheckpoint(current.checkpoint, expectedCheckpoint) ||
    !exactReceipt(current.receipt, committed.receipt)
  ) {
    throw new MonitorReplayCheckpointError(
      "latest_readback_mismatch",
      "strong latest readback does not identify the exact committed operation",
    );
  }

  return result("CHECKPOINTED", committed);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
