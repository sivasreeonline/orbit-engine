import { describe, expect, it } from "vitest";
import {
  checkpointMonitorReplaySnapshot,
  MonitorReplayCheckpointError,
} from "./monitor-replay-checkpoint-coordinator";
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
const scope: WitnessCheckpointScope = {
  trustDomainId: "monitor-trust-domain",
  witnessId: "monitor-witness",
  authorityId: "monitor-a",
  hostId: "monitor-b",
};

class InMemoryAdapter implements WitnessProviderAdapter {
  readonly records: StoredWitnessCheckpoint[] = [];
  readonly operations = new Map<string, StoredWitnessCheckpoint>();
  readonly idempotency = new Map<string, string>();
  loseNextAck = false;
  forceStaleLatest = false;
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
      checkpoint.checkpointDigest,
      checkpoint.previousDigest,
      Array.from(checkpoint.canonicalSnapshotBytes).join(","),
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
    return record;
  }
}

const sample = {
  version: 1,
  senderId: "monitor-a",
  recipientId: "monitor-b",
  scope: "monitor-domain|monitor-witness|monitor-a|monitor-b",
  highestSequence: 1,
  seenBySequence: {
    "1": { messageId: "message-1", digest: "1".repeat(64) },
  },
  seenByMessageId: {
    "message-1": { sequence: 1, digest: "1".repeat(64) },
  },
  outstandingRequests: {},
  consumedNonces: [],
  missingSequences: [],
};

describe("provider-neutral monitor replay checkpoint coordinator", () => {
  it("canonicalizes snapshot bytes and appends exactly one immutable generation", async () => {
    const adapter = new InMemoryAdapter();
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample);
    expect(first).toMatchObject({ status: "CHECKPOINTED", generation: 1 });
    const reordered = Object.fromEntries(Object.entries(sample).reverse());
    const retry = await checkpointMonitorReplaySnapshot(adapter, scope, reordered);
    expect(retry).toMatchObject({
      status: "ALREADY_CHECKPOINTED",
      generation: 1,
      digest: first.digest,
      operationId: first.operationId,
    });
    expect(adapter.records).toHaveLength(1);
  });

  it("recovers a lost acknowledgement by immutable operation lookup", async () => {
    const adapter = new InMemoryAdapter();
    adapter.loseNextAck = true;
    const result = await checkpointMonitorReplaySnapshot(adapter, scope, sample);
    expect(result).toMatchObject({ status: "CHECKPOINTED", generation: 1 });
    expect(adapter.records).toHaveLength(1);
  });

  it("rejects a previously committed operation after a successor becomes current", async () => {
    const adapter = new InMemoryAdapter();
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample);
    await checkpointMonitorReplaySnapshot(adapter, scope, { ...sample, highestSequence: 2 });
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, sample))
      .rejects.toMatchObject({
        name: "MonitorReplayCheckpointError",
        reason: "stale_operation",
      });
    expect(first.generation).toBe(1);
  });

  it("rejects a stale competing predecessor instead of rebasing", async () => {
    const adapter = new InMemoryAdapter();
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample);
    const candidate = { ...sample, highestSequence: 2 };
    const other = { ...sample, highestSequence: 3 };
    // Force both coordinator calls to observe the same predecessor. Without
    // this barrier the second call may legitimately start after the first has
    // committed and append a sequential successor, which is not a CAS race.
    const readLatest = adapter.readLatest.bind(adapter);
    let initialReads = 0;
    let releaseInitialReads!: () => void;
    const initialReadsReady = new Promise<void>((resolve) => {
      releaseInitialReads = resolve;
    });
    adapter.readLatest = async (requestedScope) => {
      if (initialReads < 2) {
        initialReads += 1;
        if (initialReads === 2) releaseInitialReads();
        await initialReadsReady;
      }
      return readLatest(requestedScope);
    };
    const outcomes = await Promise.allSettled([
      checkpointMonitorReplaySnapshot(adapter, scope, candidate),
      checkpointMonitorReplaySnapshot(adapter, scope, other),
    ]);
    expect(outcomes.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((item) => item.status === "rejected")).toHaveLength(1);
    expect(adapter.records).toHaveLength(2);
    expect(adapter.records[1]?.checkpoint.previousDigest).toBe(first.digest);
  });

  it("rejects invalid scopes and non-JSON snapshots", async () => {
    const adapter = new InMemoryAdapter();
    await expect(checkpointMonitorReplaySnapshot(adapter, { ...scope, hostId: "" }, sample))
      .rejects.toBeInstanceOf(MonitorReplayCheckpointError);
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, { value: Number.NaN }))
      .rejects.toMatchObject({ reason: "invalid_snapshot" });
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, []))
      .rejects.toMatchObject({ reason: "invalid_snapshot" });
  });

  it("rejects malformed or empty receipt bindings on readback", async () => {
    const adapter = new InMemoryAdapter();
    const original = adapter.appendIfCurrent.bind(adapter);
    adapter.appendIfCurrent = async (...args) => {
      const receipt = await original(...args);
      return { ...receipt, checkpointDigest: "f".repeat(64) };
    };
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, sample))
      .rejects.toMatchObject({ reason: "receipt_mismatch" });
  });

  it("rejects a stale strong-read simulation after append", async () => {
    const adapter = new InMemoryAdapter();
    adapter.forceStaleLatest = true;
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, sample))
      .rejects.toMatchObject({ reason: "latest_readback_mismatch" });
  });
});
