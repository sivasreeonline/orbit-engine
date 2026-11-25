import { describe, expect, it } from "vitest";
import { createReplayCheckpointIntent } from "./gossip-replay-checkpoint-intent";
import { createPendingReplayIntent } from "./gossip-replay-pending-intent";
import {
  finalizePendingReplayIntent,
  hasPendingReplayIntent,
  initializeVersionedReplayState,
  REPLAY_PENDING_INTENT_KEY,
  REPLAY_STATE_ENVELOPE_KEY,
  stagePendingReplayIntent,
  type ReplayCheckpointStorage,
  type ReplayCheckpointStorageTransaction,
  type VersionedReplayState,
} from "./gossip-replay-checkpoint-lifecycle";

function makeStorage(seed: Record<string, unknown> = {}) {
  const values = new Map(Object.entries(seed));
  const storage: ReplayCheckpointStorage = {
    async transaction<T>(
      callback: (txn: ReplayCheckpointStorageTransaction) => Promise<T>,
    ): Promise<T> {
      const draft = new Map(values);
      const txn: ReplayCheckpointStorageTransaction = {
        async get<K>(key: string): Promise<K | undefined> {
          return structuredClone(draft.get(key)) as K | undefined;
        },
        async put<K>(key: string, value: K): Promise<void> {
          draft.set(key, structuredClone(value));
        },
        async delete(key: string): Promise<boolean> {
          return draft.delete(key);
        },
      };
      const result = await callback(txn);
      values.clear();
      for (const [key, value] of draft) values.set(key, value);
      return result;
    },
  };
  return { storage, values };
}

async function fixture(baseStateVersion = 0) {
  const snapshot = { highestSequence: 1, seen: { "message-1": "a".repeat(64) } };
  const intent = await createReplayCheckpointIntent({
    baseStateVersion,
    senderId: "monitor-a",
    recipientId: "monitor-b",
    messageDigest: "a".repeat(64),
    scope: "domain-a|witness-a|authority-a|host-a",
    expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
    nextState: snapshot,
  });
  const pending = await createPendingReplayIntent(intent, {
    messageId: "message-1",
    senderId: "monitor-a",
    recipientId: "monitor-b",
    scope: "domain-a|witness-a|authority-a|host-a",
    sequence: 1,
    canonicalDigest: "a".repeat(64),
    messageType: "HEAD_ADVERTISEMENT",
    issuedAt: 9_990,
    expiresAt: 10_100,
  }, snapshot);
  return { snapshot, intent, pending };
}

const initialState: VersionedReplayState = {
  version: 2,
  stateVersion: 0,
  snapshot: { highestSequence: 0 },
  witnessHead: {
    generation: 0,
    digest: "0".repeat(64),
    treeSize: 0,
    treeHeadDigest: "0".repeat(64),
  },
};

describe("transactional replay checkpoint lifecycle", () => {
  it("initializes only an empty, non-legacy relationship", async () => {
    const empty = makeStorage();
    expect(await initializeVersionedReplayState(empty.storage, initialState)).toEqual({ initialized: true });
    expect(empty.values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initialState);

    const legacy = makeStorage({ "replay-state-v1": { highestSequence: 9 } });
    expect(await initializeVersionedReplayState(legacy.storage, initialState))
      .toEqual({ initialized: false, reason: "legacy_state_requires_quarantine" });
  });

  it("persists pending intent without advancing accepted state", async () => {
    const { storage, values } = makeStorage({ [REPLAY_STATE_ENVELOPE_KEY]: initialState });
    const { pending } = await fixture();
    const before = structuredClone(values.get(REPLAY_STATE_ENVELOPE_KEY));
    expect(await stagePendingReplayIntent(storage, pending)).toEqual({ staged: true, stateVersion: 0 });
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(before);
    expect(await hasPendingReplayIntent(storage)).toBe(true);
  });

  it("rejects competing and stale pending intents", async () => {
    const { storage } = makeStorage({ [REPLAY_STATE_ENVELOPE_KEY]: initialState });
    const first = await fixture();
    expect((await stagePendingReplayIntent(storage, first.pending)).staged).toBe(true);
    expect(await stagePendingReplayIntent(storage, first.pending))
      .toEqual({ staged: false, reason: "pending_intent_exists" });

    const stale = await fixture(3);
    const freshStorage = makeStorage({ [REPLAY_STATE_ENVELOPE_KEY]: initialState });
    expect(await stagePendingReplayIntent(freshStorage.storage, stale.pending))
      .toEqual({ staged: false, reason: "stale_state_version" });
  });

  it("keeps pending and accepted state unchanged when witness is unavailable", async () => {
    const { storage, values } = makeStorage({ [REPLAY_STATE_ENVELOPE_KEY]: initialState });
    const { pending } = await fixture();
    await stagePendingReplayIntent(storage, pending);
    const beforeState = structuredClone(values.get(REPLAY_STATE_ENVELOPE_KEY));
    const beforePending = structuredClone(values.get(REPLAY_PENDING_INTENT_KEY));
    // A provider_unavailable response is intentionally not a finalization input.
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(beforeState);
    expect(values.get(REPLAY_PENDING_INTENT_KEY)).toEqual(beforePending);
    expect(await hasPendingReplayIntent(storage)).toBe(true);
  });

  it("atomically finalizes only evidence bound to the exact operation and predecessor", async () => {
    const { storage, values } = makeStorage({ [REPLAY_STATE_ENVELOPE_KEY]: initialState });
    const { pending, snapshot } = await fixture();
    await stagePendingReplayIntent(storage, pending);
    const bad = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: "wrong-operation",
      checkpointDigest: "d".repeat(64),
      snapshotDigest: pending.intent.snapshotDigest,
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(bad).toEqual({ finalized: false, reason: "evidence_binding_mismatch" });
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initialState);

    const wrongSnapshotBinding = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: pending.intent.operationId,
      checkpointDigest: "d".repeat(64),
      snapshotDigest: "e".repeat(64),
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(wrongSnapshotBinding).toEqual({
      finalized: false,
      reason: "evidence_binding_mismatch",
    });

    // A gateway result must also match the exact predecessor and complete
    // witness scope. A verified flag alone cannot authorize another branch.
    const wrongPredecessor = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: pending.intent.operationId,
      checkpointDigest: "d".repeat(64),
      snapshotDigest: pending.intent.snapshotDigest,
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      predecessorGeneration: 0,
      predecessorDigest: "f".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(wrongPredecessor).toEqual({
      finalized: false,
      reason: "evidence_binding_mismatch",
    });
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initialState);
    expect(await hasPendingReplayIntent(storage)).toBe(true);

    const wrongScope = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: pending.intent.operationId,
      checkpointDigest: "d".repeat(64),
      snapshotDigest: pending.intent.snapshotDigest,
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "different-host",
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(wrongScope).toEqual({
      finalized: false,
      reason: "evidence_binding_mismatch",
    });
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initialState);
    expect(await hasPendingReplayIntent(storage)).toBe(true);

    // Even with an unchanged stateVersion, finalization must reject a
    // witness head that no longer matches the predecessor captured at staging.
    const alteredState: VersionedReplayState = {
      ...initialState,
      witnessHead: {
        ...initialState.witnessHead,
        generation: 4,
        digest: "f".repeat(64),
      },
    };
    values.set(REPLAY_STATE_ENVELOPE_KEY, alteredState);
    const changedPredecessor = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: pending.intent.operationId,
      checkpointDigest: "d".repeat(64),
      snapshotDigest: pending.intent.snapshotDigest,
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(changedPredecessor).toEqual({
      finalized: false,
      reason: "evidence_binding_mismatch",
    });
    expect(values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(alteredState);
    expect(await hasPendingReplayIntent(storage)).toBe(true);

    // Restore the original predecessor to prove the same evidence can then
    // finalize the still-pending transition.
    values.set(REPLAY_STATE_ENVELOPE_KEY, initialState);

    const good = await finalizePendingReplayIntent(storage, pending, {
      verified: true,
      operationId: pending.intent.operationId,
      checkpointDigest: "d".repeat(64),
      snapshotDigest: pending.intent.snapshotDigest,
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      treeSize: 1,
      treeHeadDigest: "b".repeat(64),
      receiptLeafHash: "c".repeat(64),
    });
    expect(good).toEqual({ finalized: true, stateVersion: 1 });
    expect((values.get(REPLAY_STATE_ENVELOPE_KEY) as VersionedReplayState).snapshot).toEqual(snapshot);
    expect((values.get(REPLAY_STATE_ENVELOPE_KEY) as VersionedReplayState).witnessHead.digest)
      .toBe("d".repeat(64));
    expect((values.get(REPLAY_STATE_ENVELOPE_KEY) as VersionedReplayState).witnessHead.treeHeadDigest)
      .toBe("b".repeat(64));
    expect(values.has(REPLAY_PENDING_INTENT_KEY)).toBe(false);
  });

  it("rejects legacy local-only state instead of silently upgrading it", async () => {
    const { storage } = makeStorage({
      "replay-state-v1": { highestSequence: 12 },
      [REPLAY_STATE_ENVELOPE_KEY]: initialState,
    });
    const { pending } = await fixture();
    expect(await stagePendingReplayIntent(storage, pending))
      .toEqual({ staged: false, reason: "legacy_state_requires_quarantine" });
  });
});
