import {
  WitnessAppendConflict,
  WitnessAmbiguousCommit,
  WitnessIdempotencyConflict,
  type StoredWitnessCheckpoint,
  type WitnessCheckpoint,
  type WitnessCheckpointReceipt,
  type WitnessCheckpointScope,
  type WitnessProviderAdapter,
} from "../src/provider/witness-provider-adapter";

const ZERO_DIGEST = "0".repeat(64);

/**
 * Test-only in-memory atomic provider. It models compare-and-append,
 * immutable operation lookup, idempotency binding and ambiguous acknowledgements.
 * It is not a production durability implementation.
 */
export class SyntheticWitnessProviderAdapter implements WitnessProviderAdapter {
  readonly records: StoredWitnessCheckpoint[] = [];
  readonly operations = new Map<string, StoredWitnessCheckpoint>();
  readonly idempotency = new Map<string, string>();
  loseNextAck = false;
  forceStaleLatest = false;
  corruptCheckpointReadback = false;
  private lastLatest: StoredWitnessCheckpoint | null = null;

  async appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expected: { generation: number; digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt> {
    const contentKey = [
      checkpoint.scope.trustDomainId,
      checkpoint.scope.witnessId,
      checkpoint.scope.authorityId,
      checkpoint.scope.hostId,
      checkpoint.generation,
      checkpoint.operationId,
      checkpoint.phase,
      checkpoint.snapshotDigest,
      checkpoint.checkpointDigest,
      checkpoint.previousDigest,
      Array.from(checkpoint.canonicalSnapshotBytes).join(","),
      Array.from(checkpoint.canonicalCheckpointBodyBytes).join(","),
    ].join("|");
    const priorKey = this.idempotency.get(idempotencyKey);
    if (priorKey) {
      if (priorKey !== contentKey) throw new WitnessIdempotencyConflict();
      const prior = this.operations.get(checkpoint.operationId);
      if (!prior) throw new Error("idempotency index has no immutable operation");
      return prior.receipt;
    }

    const latest = this.records.at(-1) ?? null;
    const actualGeneration = latest?.checkpoint.generation ?? 0;
    const actualDigest = latest?.checkpoint.checkpointDigest ?? ZERO_DIGEST;
    if (actualGeneration !== expected.generation || actualDigest !== expected.digest) {
      throw new WitnessAppendConflict();
    }
    if (
      checkpoint.generation !== expected.generation + 1 ||
      checkpoint.previousDigest !== expected.digest ||
      checkpoint.phase !== "MONITOR_GOSSIP_REPLAY_V1"
    ) throw new WitnessAppendConflict("invalid successor checkpoint");
    if (this.operations.has(checkpoint.operationId)) throw new WitnessIdempotencyConflict();

    const receipt: WitnessCheckpointReceipt = {
      scope: checkpoint.scope,
      generation: checkpoint.generation,
      operationId: checkpoint.operationId,
      checkpointDigest: checkpoint.checkpointDigest,
      previousDigest: checkpoint.previousDigest,
      consistencyToken: `fixture-token-${checkpoint.generation}`,
    };
    const stored = { checkpoint, receipt };
    this.records.push(stored);
    this.operations.set(checkpoint.operationId, stored);
    this.idempotency.set(idempotencyKey, contentKey);
    if (this.loseNextAck) {
      this.loseNextAck = false;
      throw new WitnessAmbiguousCommit("simulated lost acknowledgement after commit");
    }
    return receipt;
  }

  async readLatest(requestedScope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    const latest = this.records.at(-1) ?? null;
    if (this.forceStaleLatest) return this.lastLatest;
    if (latest && JSON.stringify(latest.checkpoint.scope) !== JSON.stringify(requestedScope)) return null;
    this.lastLatest = latest;
    return latest;
  }

  async readByOperation(
    requestedScope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    const record = this.operations.get(operationId) ?? null;
    if (
      record &&
      JSON.stringify(record.checkpoint.scope) !== JSON.stringify(requestedScope)
    ) return null;
    if (record && this.corruptCheckpointReadback) {
      return {
        ...record,
        checkpoint: {
          ...record.checkpoint,
          canonicalCheckpointBodyBytes: new TextEncoder().encode("{}"),
        },
      };
    }
    return record;
  }
}

