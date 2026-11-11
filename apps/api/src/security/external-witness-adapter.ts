/**
 * Provider-neutral contract for an independently administered epoch witness.
 *
 * This module defines the boundary only. It deliberately contains no provider
 * client, credentials, network transport, or production adapter.
 */

export const ZERO_CHECKPOINT_DIGEST = "0".repeat(64);

export type CheckpointPhase = "ISSUED" | "ACCEPTED" | "REVOKED";

export interface WitnessCheckpoint {
  readonly schemaVersion: 1;
  readonly authorityId: string;
  readonly hostId: string;
  readonly generation: number;
  readonly phase: CheckpointPhase;
  readonly operationId: string;
  readonly previousCheckpointDigest: string;
  readonly checkpointDigest: string;
  readonly authorityStateDigest: string;
  readonly responseDigest: string;
  readonly epoch: number;
  readonly recordVersion: number;
}

export interface WitnessReceipt {
  readonly schemaVersion: 1;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
  readonly generation: number;
  readonly operationId: string;
  readonly checkpointDigest: string;
  readonly previousCheckpointDigest: string;
  readonly keyId: string;
  readonly signature: string;
  readonly committedAt: string;
  readonly consistencyToken: string;
}

export interface WitnessRecord {
  readonly checkpoint: WitnessCheckpoint;
  readonly receipt: WitnessReceipt;
}

export interface WitnessScope {
  readonly authorityId: string;
  readonly hostId: string;
}

export interface AppendCheckpointInput {
  readonly expectedGeneration: number;
  readonly expectedCheckpointDigest: string;
  readonly checkpoint: WitnessCheckpoint;
}

export interface AppendCheckpointResult {
  readonly status: "APPENDED" | "EXISTING";
  readonly record: WitnessRecord;
}

export interface ExternalWitnessAdapter {
  /**
   * Atomically compare-and-append exactly one successor checkpoint.
   *
   * A retry with the same authority, host, operation ID and byte-identical
   * checkpoint must return EXISTING with the original receipt. Rebinding that
   * operation ID, using a stale predecessor, or presenting a fork must conflict.
   */
  appendCheckpoint(input: AppendCheckpointInput): Promise<AppendCheckpointResult>;

  /** Strongly consistent read of the current retained high-water checkpoint. */
  readLatest(scope: WitnessScope): Promise<WitnessRecord | null>;

  /** Resolve a commit whose acknowledgement may have been lost. */
  readByOperation(
    scope: WitnessScope,
    operationId: string,
    phase: CheckpointPhase,
  ): Promise<WitnessRecord | null>;
}

export interface WitnessReceiptVerifier {
  /** Verify signature, witness identity, scope, checkpoint binding and key status. */
  verify(record: WitnessRecord): Promise<boolean>;
}

/**
 * Check that a receipt is bound to the exact checkpoint and trusted witness
 * identity before invoking a cryptographic WitnessReceiptVerifier.
 * This function does not verify the signature itself.
 */
export function assertReceiptMatchesCheckpoint(
  record: WitnessRecord,
  expectedWitnessId: string,
): void {
  const { checkpoint, receipt } = record;
  const committedAtIsUtc =
    receipt.committedAt.includes("T")
    && receipt.committedAt.endsWith("Z")
    && Number.isFinite(Date.parse(receipt.committedAt));

  if (
    receipt.schemaVersion !== 1
    || !expectedWitnessId
    || receipt.witnessId !== expectedWitnessId
    || receipt.authorityId !== checkpoint.authorityId
    || receipt.hostId !== checkpoint.hostId
    || receipt.generation !== checkpoint.generation
    || receipt.operationId !== checkpoint.operationId
    || receipt.checkpointDigest !== checkpoint.checkpointDigest
    || receipt.previousCheckpointDigest !== checkpoint.previousCheckpointDigest
    || !receipt.keyId
    || !receipt.signature
    || !receipt.consistencyToken
    || !committedAtIsUtc
  ) {
    throw new WitnessConflictError("witness receipt does not bind the expected checkpoint and trust identity");
  }
}

export class WitnessUnavailableError extends Error {
  readonly code = "WITNESS_UNAVAILABLE";

  constructor(message = "external witness is unavailable or commit outcome is unknown") {
    super(message);
    this.name = "WitnessUnavailableError";
  }
}

export class WitnessConflictError extends Error {
  readonly code = "WITNESS_CONFLICT";

  constructor(message: string) {
    super(message);
    this.name = "WitnessConflictError";
  }
}

export class CheckpointTransitionError extends Error {
  readonly code = "INVALID_CHECKPOINT_TRANSITION";

  constructor(message: string) {
    super(message);
    this.name = "CheckpointTransitionError";
  }
}

function isDigest(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

/**
 * Enforce the lifecycle and predecessor rules before an adapter call.
 * The witness must independently enforce the same rules during its CAS.
 */
export function assertCheckpointFollows(
  previous: WitnessCheckpoint | null,
  next: WitnessCheckpoint,
): void {
  if (
    next.schemaVersion !== 1
    || !next.authorityId
    || !next.hostId
    || !next.operationId
    || !Number.isSafeInteger(next.generation)
    || next.generation < 1
    || !Number.isSafeInteger(next.epoch)
    || next.epoch < 0
    || !Number.isSafeInteger(next.recordVersion)
    || next.recordVersion < 1
    || !isDigest(next.previousCheckpointDigest)
    || !isDigest(next.checkpointDigest)
    || !isDigest(next.authorityStateDigest)
    || !isDigest(next.responseDigest)
  ) {
    throw new CheckpointTransitionError("checkpoint envelope is malformed");
  }

  if (previous === null) {
    if (
      next.generation !== 1
      || next.previousCheckpointDigest !== ZERO_CHECKPOINT_DIGEST
      || next.phase !== "ISSUED"
    ) {
      throw new CheckpointTransitionError("first checkpoint must be generation-one issuance");
    }
    return;
  }

  if (
    next.authorityId !== previous.authorityId
    || next.hostId !== previous.hostId
    || next.generation !== previous.generation + 1
    || next.previousCheckpointDigest !== previous.checkpointDigest
    || next.recordVersion <= previous.recordVersion
    || next.checkpointDigest === previous.checkpointDigest
  ) {
    throw new CheckpointTransitionError("checkpoint identity, generation or predecessor mismatch");
  }

  if (previous.phase === "REVOKED") {
    throw new CheckpointTransitionError("revoked authority is terminal");
  }

  if (next.phase === "ISSUED") {
    if (previous.phase !== "ACCEPTED" || next.operationId === previous.operationId || next.epoch <= previous.epoch) {
      throw new CheckpointTransitionError("issuance requires an accepted predecessor and a higher epoch");
    }
    return;
  }

  if (next.phase === "ACCEPTED") {
    if (
      previous.phase !== "ISSUED"
      || next.operationId !== previous.operationId
      || next.epoch !== previous.epoch
      || next.responseDigest !== previous.responseDigest
    ) {
      throw new CheckpointTransitionError("acceptance must bind the exact pending issuance");
    }
    return;
  }

  if (next.phase === "REVOKED" && next.epoch !== previous.epoch) {
    throw new CheckpointTransitionError("revocation cannot change the epoch");
  }
}
