import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import { SyntheticWitnessProviderAdapter } from "../../test-support/synthetic-witness-provider-adapter";
import { deriveReplayCheckpointOperationId } from "../../../api/src/gossip/gossip-replay-checkpoint-intent";
import {
  checkpointMonitorReplaySnapshot,
  MonitorReplayCheckpointError,
} from "./monitor-replay-checkpoint-coordinator";
import type { WitnessCheckpointScope } from "./witness-provider-adapter";
import type { MonitorReplayCheckpointBody } from "../../../api/src/witness/witness-profile-verifier";

const ZERO_DIGEST = "0".repeat(64);

const scope: WitnessCheckpointScope = {
  trustDomainId: "monitor-trust-domain",
  witnessId: "monitor-witness",
  authorityId: "monitor-a",
  hostId: "monitor-b",
};


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

async function checkpointBodyFor(
  snapshot: typeof sample,
  predecessor: { readonly generation: number; readonly digest: string },
): Promise<MonitorReplayCheckpointBody> {
  const serialized = canonicalize(snapshot);
  if (typeof serialized !== "string") throw new Error("sample snapshot is not canonicalizable");
  const bytes = new TextEncoder().encode(serialized);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const snapshotDigest = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const operationId = await deriveReplayCheckpointOperationId({
    scope,
    expectedPredecessor: predecessor,
    snapshotDigest,
  });
  return {
    profile: "sky-high-fence-monitor-replay-v1",
    schemaVersion: 1,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    senderId: snapshot.senderId,
    recipientId: snapshot.recipientId,
    generation: predecessor.generation + 1,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    previousCheckpointDigest: predecessor.digest,
    snapshotDigest,
    snapshotByteLength: bytes.length,
    baseStateVersion: predecessor.generation,
    messageDigest: "1".repeat(64),
  };
}

describe("provider-neutral monitor replay checkpoint coordinator", () => {
  it("stores and reads back distinct canonical snapshot and checkpoint-body digests", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample, body, predecessor);
    expect(first).toMatchObject({
      status: "CHECKPOINTED",
      generation: 1,
      snapshotDigest: body.snapshotDigest,
    });
    expect(first.checkpointDigest).not.toBe(first.snapshotDigest);
    const stored = adapter.records[0]?.checkpoint;
    expect(stored?.snapshotDigest).toBe(first.snapshotDigest);
    expect(stored?.checkpointDigest).toBe(first.checkpointDigest);
    expect(new TextDecoder().decode(stored?.canonicalSnapshotBytes)).toBe(canonicalize(sample));
    expect(new TextDecoder().decode(stored?.canonicalCheckpointBodyBytes)).toBe(canonicalize(body));

    const reordered = Object.fromEntries(Object.entries(sample).reverse()) as typeof sample;
    const retryBody = await checkpointBodyFor(reordered, predecessor);
    const retry = await checkpointMonitorReplaySnapshot(adapter, scope, reordered, retryBody, predecessor);
    expect(retry).toMatchObject({
      status: "ALREADY_CHECKPOINTED",
      generation: 1,
      snapshotDigest: first.snapshotDigest,
      checkpointDigest: first.checkpointDigest,
      operationId: first.operationId,
    });
    expect(adapter.records).toHaveLength(1);
  });

  it("uses persisted predecessor identity for stable operation ID and retry", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample, body, predecessor);
    const retryBody = await checkpointBodyFor(sample, predecessor);
    const retry = await checkpointMonitorReplaySnapshot(adapter, scope, sample, retryBody, predecessor);
    expect(retry.operationId).toBe(first.operationId);
    expect(first.operationId).not.toBe(`fence-monitor-replay-${first.snapshotDigest}`);
    expect(adapter.records).toHaveLength(1);
  });

  it("does not rebase a persisted predecessor after the witness head advances", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const genesis = { generation: 0, digest: ZERO_DIGEST };
    const firstBody = await checkpointBodyFor(sample, genesis);
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample, firstBody, genesis);
    const candidate = { ...sample, highestSequence: 2 };
    const staleBody = await checkpointBodyFor(candidate, genesis);
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, candidate, staleBody, genesis))
      .rejects.toMatchObject({ name: "MonitorReplayCheckpointError", reason: "stale_operation" });
    expect(adapter.records).toHaveLength(1);
    expect(first.generation).toBe(1);
  });

  it("recovers a lost acknowledgement by immutable operation lookup", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    adapter.loseNextAck = true;
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    const result = await checkpointMonitorReplaySnapshot(adapter, scope, sample, body, predecessor);
    expect(result).toMatchObject({ status: "CHECKPOINTED", generation: 1 });
    expect(adapter.records).toHaveLength(1);
  });

  it("rejects a previously committed operation after a successor becomes current", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const genesis = { generation: 0, digest: ZERO_DIGEST };
    const firstBody = await checkpointBodyFor(sample, genesis);
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample, firstBody, genesis);
    const successor = { ...sample, highestSequence: 2 };
    const nextPredecessor = { generation: first.generation, digest: first.checkpointDigest };
    const secondBody = await checkpointBodyFor(successor, nextPredecessor);
    await checkpointMonitorReplaySnapshot(adapter, scope, successor, secondBody, nextPredecessor);
    const retryBody = await checkpointBodyFor(sample, genesis);
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, sample, retryBody, genesis))
      .rejects.toMatchObject({ name: "MonitorReplayCheckpointError", reason: "stale_operation" });
    expect(first.generation).toBe(1);
  });

  it("rejects a stale competing predecessor instead of rebasing", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const genesis = { generation: 0, digest: ZERO_DIGEST };
    const firstBody = await checkpointBodyFor(sample, genesis);
    const first = await checkpointMonitorReplaySnapshot(adapter, scope, sample, firstBody, genesis);
    const candidate = { ...sample, highestSequence: 2 };
    const other = { ...sample, highestSequence: 3 };
    const [candidateBody, otherBody] = await Promise.all([
      checkpointBodyFor(candidate, { generation: first.generation, digest: first.checkpointDigest }),
      checkpointBodyFor(other, { generation: first.generation, digest: first.checkpointDigest }),
    ]);
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
      checkpointMonitorReplaySnapshot(adapter, scope, candidate, candidateBody, {
        generation: first.generation,
        digest: first.checkpointDigest,
      }),
      checkpointMonitorReplaySnapshot(adapter, scope, other, otherBody, {
        generation: first.generation,
        digest: first.checkpointDigest,
      }),
    ]);
    expect(outcomes.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((item) => item.status === "rejected")).toHaveLength(1);
    expect(adapter.records).toHaveLength(2);
    expect(adapter.records[1]?.checkpoint.previousDigest).toBe(first.checkpointDigest);
  });

  it("rejects altered checkpoint-body readback even when the snapshot bytes are unchanged", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    await checkpointMonitorReplaySnapshot(adapter, scope, sample, body, predecessor);
    adapter.corruptCheckpointReadback = true;
    await expect(checkpointMonitorReplaySnapshot(adapter, scope, sample, body, predecessor))
      .rejects.toMatchObject({ name: "MonitorReplayCheckpointError", reason: "operation_conflict" });
  });

  it("rejects checkpoint bodies bound to another snapshot, scope, or sender relationship", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    await expect(checkpointMonitorReplaySnapshot(
      adapter, scope, sample, { ...body, snapshotDigest: "f".repeat(64) }, predecessor,
    )).rejects.toMatchObject({ reason: "invalid_checkpoint_body" });
    await expect(checkpointMonitorReplaySnapshot(
      adapter, scope, sample, { ...body, trustDomainId: "other-domain" }, predecessor,
    )).rejects.toMatchObject({ reason: "invalid_checkpoint_body" });
    await expect(checkpointMonitorReplaySnapshot(
      adapter, scope, sample, { ...body, senderId: "someone-else" }, predecessor,
    )).rejects.toMatchObject({ reason: "invalid_checkpoint_body" });
  });

  it("rejects invalid scopes, malformed predecessors, and non-JSON snapshots", async () => {
    const adapter = new SyntheticWitnessProviderAdapter();
    const predecessor = { generation: 0, digest: ZERO_DIGEST };
    const body = await checkpointBodyFor(sample, predecessor);
    await expect(checkpointMonitorReplaySnapshot(
      adapter, { ...scope, hostId: "" }, sample, body, predecessor,
    )).rejects.toMatchObject({ reason: "invalid_scope" });
    await expect(checkpointMonitorReplaySnapshot(
      adapter, scope, sample, body, { generation: -1, digest: ZERO_DIGEST },
    )).rejects.toMatchObject({ reason: "invalid_predecessor" });
    await expect(checkpointMonitorReplaySnapshot(
      adapter, scope, { invalid: undefined }, body, predecessor,
    )).rejects.toBeInstanceOf(MonitorReplayCheckpointError);
  });
});
