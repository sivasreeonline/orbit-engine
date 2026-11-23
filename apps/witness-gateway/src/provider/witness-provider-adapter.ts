export interface WitnessCheckpointScope {
  readonly trustDomainId: string;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
}

export interface WitnessCheckpoint {
  readonly scope: WitnessCheckpointScope;
  readonly generation: number;
  readonly operationId: string;
  readonly phase: "MONITOR_GOSSIP_REPLAY_V1";
  /** SHA-256 of the exact canonical replay snapshot bytes. */
  readonly snapshotDigest: string;
  /** SHA-256 of the exact canonical monitor-replay checkpoint-body bytes. */
  readonly checkpointDigest: string;
  readonly previousDigest: string;
  readonly canonicalSnapshotBytes: Uint8Array;
  readonly canonicalCheckpointBodyBytes: Uint8Array;
}

export interface WitnessCheckpointReceipt {
  readonly scope: WitnessCheckpointScope;
  readonly generation: number;
  readonly operationId: string;
  readonly checkpointDigest: string;
  readonly previousDigest: string;
  /** Opaque provider token. It is not a cryptographic proof. */
  readonly consistencyToken: string;
}

export interface StoredWitnessCheckpoint {
  readonly checkpoint: WitnessCheckpoint;
  readonly receipt: WitnessCheckpointReceipt;
}

export class WitnessAppendConflict extends Error {
  constructor(message = "witness predecessor is no longer current") {
    super(message);
    this.name = "WitnessAppendConflict";
  }
}

export class WitnessIdempotencyConflict extends Error {
  constructor(message = "witness idempotency key is bound to different content") {
    super(message);
    this.name = "WitnessIdempotencyConflict";
  }
}

export class WitnessAmbiguousCommit extends Error {
  constructor(message = "witness append acknowledgement is ambiguous") {
    super(message);
    this.name = "WitnessAmbiguousCommit";
  }
}

export interface WitnessProviderAdapter {
  /**
   * Atomically compare the exact predecessor and append one immutable record.
   * Idempotency must bind the key to every checkpoint field and canonical byte.
   */
  appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expected: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt>;

  /** Must be a strongly consistent read, never a cached/replica-stale read. */
  readLatest(scope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null>;

  /** Must return the immutable record for the exact operation ID, if present. */
  readByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null>;
}
