import canonicalize from "canonicalize";
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
 * Test-only in-memory atomic witness provider. State and idempotency are scoped
 * by the complete witness identity, matching the provider contract. It is not
 * a production durability implementation.
 */
export class SyntheticWitnessProviderAdapter implements WitnessProviderAdapter {
  readonly records: StoredWitnessCheckpoint[] = [];
  readonly operations = new Map<string, StoredWitnessCheckpoint>();
  readonly idempotency = new Map<string, string>();
  loseNextAck = false;
  forceStaleLatest = false;
  corruptCheckpointReadback = false;
  private readonly lastLatestByScope = new Map<string, StoredWitnessCheckpoint | null>();

  private scopeKey(scope: WitnessCheckpointScope): string {
    return canonicalize(scope) ?? "";
  }

  private operationKey(scope: WitnessCheckpointScope, operationId: string): string {
    return canonicalize({ scope, operationId }) ?? "";
  }

  private idempotencyIndexKey(scope: WitnessCheckpointScope, idempotencyKey: string): string {
    return canonicalize({ scope, idempotencyKey }) ?? "";
  }

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
    const operationKey = this.operationKey(checkpoint.scope, checkpoint.operationId);
    const idempotencyIndexKey = this.idempotencyIndexKey(checkpoint.scope, idempotencyKey);
    const priorKey = this.idempotency.get(idempotencyIndexKey);
    if (priorKey) {
      if (priorKey !== contentKey) throw new WitnessIdempotencyConflict();
      const prior = this.operations.get(operationKey);
      if (!prior) throw new Error("idempotency index has no immutable operation");
      return prior.receipt;
    }

    const latest = [...this.records].reverse().find((record) =>
      this.scopeKey(record.checkpoint.scope) === this.scopeKey(checkpoint.scope)
    ) ?? null;
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
    if (this.operations.has(operationKey)) throw new WitnessIdempotencyConflict();

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
    this.operations.set(operationKey, stored);
    this.idempotency.set(idempotencyIndexKey, contentKey);
    if (this.loseNextAck) {
      this.loseNextAck = false;
      throw new WitnessAmbiguousCommit("simulated lost acknowledgement after commit");
    }
    return receipt;
  }

  async readLatest(requestedScope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    const scopeKey = this.scopeKey(requestedScope);
    const latest = [...this.records].reverse().find((record) =>
      this.scopeKey(record.checkpoint.scope) === scopeKey
    ) ?? null;
    if (this.forceStaleLatest) return this.lastLatestByScope.get(scopeKey) ?? null;
    this.lastLatestByScope.set(scopeKey, latest);
    return latest;
  }

  async readByOperation(
    requestedScope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    const record = this.operations.get(this.operationKey(requestedScope, operationId)) ?? null;
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
