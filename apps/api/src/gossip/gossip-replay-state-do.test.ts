import { beforeEach, describe, expect, it, vi } from "vitest";
import { GossipReplayStateDO, rearmPendingCheckpointAlarm, REPLAY_CHECKPOINT_QUARANTINE_KEY, type VerifiedGossipMessage } from "./gossip-replay-state-do";
import type { Env } from "../env";
vi.mock("../witness/witness-gateway-client", () => ({
  checkpointReplayViaWitnessGateway: vi.fn(),
  verifyEvidenceViaWitnessGateway: vi.fn(),
}));
import {
  checkpointReplayViaWitnessGateway,
  verifyEvidenceViaWitnessGateway,
} from "../witness/witness-gateway-client";
import { createReplayCheckpointIntent } from "./gossip-replay-checkpoint-intent";
import { createPendingReplayIntent, type PendingReplayIntent } from "./gossip-replay-pending-intent";
import { REPLAY_STATE_ENVELOPE_KEY, type VersionedReplayState } from "./gossip-replay-checkpoint-lifecycle";

beforeEach(() => {
  vi.resetAllMocks();
});

interface FakeStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  put<T>(entries: Record<string, T>): Promise<void>;
  delete(key: string): Promise<boolean>;
  getAlarm(): Promise<number | null>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
  transaction<T>(callback: (txn: FakeStorage) => Promise<T>): Promise<T>;
}

function makeHarness(existing?: Map<string, unknown>, env: Partial<Env> = {}) {
  const values = existing ?? new Map<string, unknown>();
  let alarmTime: number | null = (values.get("__durable_alarm__") as number | undefined) ?? null;
  const storage: FakeStorage = {
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(keyOrEntries: string | Record<string, T>, value?: T): Promise<void> {
      if (typeof keyOrEntries === "string") {
        values.set(keyOrEntries, structuredClone(value));
        return;
      }
      for (const [key, entry] of Object.entries(keyOrEntries)) {
        values.set(key, structuredClone(entry));
      }
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
    },
    async getAlarm(): Promise<number | null> {
      return alarmTime;
    },
    async setAlarm(scheduledTime: number | Date): Promise<void> {
      alarmTime = scheduledTime instanceof Date ? scheduledTime.getTime() : scheduledTime;
      values.set("__durable_alarm__", alarmTime);
    },
    async deleteAlarm(): Promise<void> {
      alarmTime = null;
      values.delete("__durable_alarm__");
    },
    async transaction<T>(callback: (txn: FakeStorage) => Promise<T>): Promise<T> {
      const snapshot = structuredClone([...values.entries()]);
      try {
        return await callback(storage);
      } catch (error) {
        values.clear();
        for (const [key, value] of snapshot) values.set(key, value);
        throw error;
      }
    },
  };
  let initialization: Promise<unknown> = Promise.resolve();
  const state = {
    storage,
    blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
      initialization = callback();
      return initialization as Promise<T>;
    },
  } as unknown as DurableObjectState;
  return {
    object: new GossipReplayStateDO(state, env as Env),
    storage,
    values,
    getAlarm: () => alarmTime,
    clearAlarm: () => {
      alarmTime = null;
      values.delete("__durable_alarm__");
    },
    ready: () => initialization,
  };
}

function message(
  sequence: number,
  overrides: Partial<VerifiedGossipMessage> = {},
): VerifiedGossipMessage {
  return {
    messageId: `message-${sequence}`,
    senderId: "monitor-a",
    recipientId: "monitor-b",
    scope: "domain-a|witness-a|authority-a|host-a",
    sequence,
    canonicalDigest: String(sequence).padStart(64, "0"),
    messageType: "HEAD_ADVERTISEMENT",
    issuedAt: 9_990,
    expiresAt: 10_100,
    ...overrides,
  };
}

describe("GossipReplayStateDO", () => {
  it("commits accepted replay state and survives object reconstruction", async () => {
    const first = makeHarness();
    const accepted = await first.object.acceptVerifiedMessage(message(1), 10_000);
    expect(accepted.outcome).toBe("ACCEPTED");

    const restarted = makeHarness(first.values);
    const duplicate = await restarted.object.acceptVerifiedMessage(message(1), 10_000);
    expect(duplicate.outcome).toBe("DUPLICATE");
    expect(duplicate.highestSequence).toBe(1);
  });

  it("quarantines same-sequence equivocation without changing durable state", async () => {
    const harness = makeHarness();
    await harness.object.acceptVerifiedMessage(message(1), 10_000);
    const before = structuredClone(harness.values.get("replay-state-v1"));
    const result = await harness.object.acceptVerifiedMessage(
      message(1, { messageId: "different-message", canonicalDigest: "f".repeat(64) }),
      10_000,
    );
    expect(result.outcome).toBe("QUARANTINE");
    expect(harness.values.get("replay-state-v1")).toEqual(before);
  });

  it("records sequence gaps and clears them only when missing messages arrive", async () => {
    const harness = makeHarness();
    const gap = await harness.object.acceptVerifiedMessage(message(3), 10_000);
    expect(gap.outcome).toBe("ACCEPTED_WITH_GAP");
    expect(gap.missingSequences).toEqual([1, 2]);

    const one = await harness.object.acceptVerifiedMessage(message(1), 10_000);
    expect(one.outcome).toBe("ACCEPTED_WITH_GAP");
    expect(one.missingSequences).toEqual([2]);

    const two = await harness.object.acceptVerifiedMessage(message(2), 10_000);
    expect(two.outcome).toBe("ACCEPTED");
    expect(two.missingSequences).toEqual([]);
  });

  it("rejects a relationship identity or scope change", async () => {
    const harness = makeHarness();
    await harness.object.acceptVerifiedMessage(message(1), 10_000);
    const result = await harness.object.acceptVerifiedMessage(
      message(2, { scope: "other-scope" }),
      10_000,
    );
    expect(result.outcome).toBe("QUARANTINE");
    expect(result.highestSequence).toBe(1);
  });

  it("binds proof responses to one outstanding request and consumes the nonce", async () => {
    const harness = makeHarness();
    const request = message(1, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "fresh-nonce-1",
    });
    expect((await harness.object.acceptVerifiedMessage(request, 10_000)).outcome)
      .toBe("ACCEPTED");

    const response = message(2, {
      messageType: "CONSISTENCY_PROOF_RESPONSE",
      responseRequestId: request.messageId,
      responseNonce: "fresh-nonce-1",
    });
    expect((await harness.object.acceptVerifiedMessage(response, 10_000)).outcome)
      .toBe("ACCEPTED");

    const reused = message(3, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "fresh-nonce-1",
    });
    expect((await harness.object.acceptVerifiedMessage(reused, 10_000)).outcome)
      .toBe("QUARANTINE");
  });

  it("blocks expired, oversized-gap and out-of-window messages", async () => {
    const harness = makeHarness();
    expect((await harness.object.acceptVerifiedMessage(
      message(1, { expiresAt: 9_999 }), 10_000,
    )).outcome).toBe("BLOCKED");
    expect((await harness.object.acceptVerifiedMessage(message(65), 10_000)).outcome)
      .toBe("BLOCKED");
  });


  it("blocks competing messages while a durable checkpoint intent is pending", async () => {
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    expect(await harness.object.initializeCheckpointedState(initial))
      .toEqual({ initialized: true });

    const proposedState = { highestSequence: 1, messageId: "message-1" };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    expect((await harness.object.stageCheckpointIntent(pending)).staged).toBe(true);
    expect(await harness.object.hasPendingCheckpointIntent()).toBe(true);

    const before = structuredClone(harness.values.get(REPLAY_STATE_ENVELOPE_KEY));
    const competing = await harness.object.acceptVerifiedMessage(message(2), 10_000);
    expect(competing.outcome).toBe("BLOCKED");
    expect(harness.values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(before);
  });

  it("does not let the legacy acceptance method bypass versioned checkpoint state", async () => {
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const result = await harness.object.acceptVerifiedMessage(message(1), 10_000);
    expect(result.outcome).toBe("BLOCKED");
    expect(harness.values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initial);
  });

  it("arms a durable alarm when a pending checkpoint intent is staged", async () => {
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);

    expect((await harness.object.stageCheckpointIntent(pending)).staged).toBe(true);
    expect(harness.getAlarm()).toEqual(expect.any(Number));
  });

  it("re-arms a missing alarm after reconstructing an object with a pending intent", async () => {
    const first = makeHarness();
    const initial: VersionedReplayState = {
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
    await first.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    await first.object.stageCheckpointIntent(
      await createPendingReplayIntent(intent, message(1), proposedState),
    );

    first.clearAlarm();
    await rearmPendingCheckpointAlarm(first.storage);

    expect(first.getAlarm()).toEqual(expect.any(Number));
  });

  it("retries pending recovery from the Durable Object alarm and backs off on failure", async () => {
    vi.mocked(checkpointReplayViaWitnessGateway).mockResolvedValue({
      checkpointed: false,
      reason: "provider_unavailable",
    });
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    await harness.object.stageCheckpointIntent(
      await createPendingReplayIntent(intent, message(1), proposedState),
    );

    harness.clearAlarm();
    await harness.object.alarm();

    expect(checkpointReplayViaWitnessGateway).toHaveBeenCalledTimes(1);
    expect(harness.getAlarm()).toEqual(expect.any(Number));
    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(true);
    vi.mocked(checkpointReplayViaWitnessGateway).mockReset();
  });

  it("does not endlessly retry a corrupted pending intent from the alarm", async () => {
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    await harness.object.stageCheckpointIntent(
      await createPendingReplayIntent(intent, message(1), proposedState),
    );
    const corrupted = harness.values.get("replay-checkpoint-pending-v1") as {
      intent: { snapshotDigest: string };
    };
    corrupted.intent.snapshotDigest = "f".repeat(64);
    harness.values.set("replay-checkpoint-pending-v1", corrupted);
    harness.clearAlarm();

    await harness.object.alarm();

    expect(checkpointReplayViaWitnessGateway).not.toHaveBeenCalled();
    expect(harness.getAlarm()).toBeNull();
    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(true);
  });

  it("preserves pending intent when the provider is unavailable during recovery", async () => {
    vi.mocked(checkpointReplayViaWitnessGateway).mockResolvedValue({
      checkpointed: false,
      reason: "provider_unavailable",
    });
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1, messageId: "message-1" };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    await harness.object.stageCheckpointIntent(pending);
    const before = structuredClone(harness.values.get(REPLAY_STATE_ENVELOPE_KEY));

    const result = await harness.object.recoverPendingCheckpointIntent();

    expect(result).toEqual({ recovered: false, reason: "checkpoint_not_committed" });
    expect(harness.values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(before);
    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(true);
    expect(verifyEvidenceViaWitnessGateway).not.toHaveBeenCalled();
    vi.mocked(checkpointReplayViaWitnessGateway).mockReset();
  });

  it("retries exact persisted bytes and finalizes only verified evidence", async () => {
    const evidenceBytes = new TextEncoder().encode("{\"fixture\":\"signed-evidence\"}");
    vi.mocked(checkpointReplayViaWitnessGateway).mockResolvedValue({
      checkpointed: true,
      canonicalEvidenceBody: evidenceBytes,
    });
    vi.mocked(verifyEvidenceViaWitnessGateway).mockResolvedValue({
      verified: true,
      trustBundleGeneration: 1,
      trustBundleDigest: "1".repeat(64),
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      operationId: "fence-monitor-replay-test",
      checkpointDigest: "d".repeat(64),
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      snapshotDigest: "",
      treeHeadDigest: "b".repeat(64),
      treeSize: 1,
      receiptLeafHash: "c".repeat(64),
    });
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1, messageId: "message-1" };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    await harness.object.stageCheckpointIntent(pending);
    // A stale marker from a prior attempt must not survive successful commit.
    await harness.storage.put(REPLAY_CHECKPOINT_QUARANTINE_KEY, {
      version: 1,
      reason: "evidence_not_verified",
      quarantinedAt: 10_000,
    });
    vi.mocked(verifyEvidenceViaWitnessGateway).mockResolvedValue({
      verified: true,
      trustBundleGeneration: 1,
      trustBundleDigest: "1".repeat(64),
      trustDomainId: "domain-a",
      witnessId: "witness-a",
      authorityId: "authority-a",
      hostId: "host-a",
      operationId: intent.operationId,
      checkpointDigest: "d".repeat(64),
      predecessorGeneration: 0,
      predecessorDigest: "0".repeat(64),
      generation: 1,
      snapshotDigest: intent.snapshotDigest,
      treeHeadDigest: "b".repeat(64),
      treeSize: 1,
      receiptLeafHash: "c".repeat(64),
    });

    const result = await harness.object.recoverPendingCheckpointIntent();

    expect(result).toEqual({ recovered: true, stateVersion: 1 });
    expect(checkpointReplayViaWitnessGateway).toHaveBeenCalledWith(
      expect.anything(),
      new TextEncoder().encode(intent.canonicalCheckpointBody),
    );
    expect(verifyEvidenceViaWitnessGateway).toHaveBeenCalledWith(expect.anything(), evidenceBytes);
    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(false);
    expect(harness.values.has(REPLAY_CHECKPOINT_QUARANTINE_KEY)).toBe(false);
    expect((harness.values.get(REPLAY_STATE_ENVELOPE_KEY) as VersionedReplayState).snapshot)
      .toEqual(proposedState);
    vi.mocked(checkpointReplayViaWitnessGateway).mockReset();
    vi.mocked(verifyEvidenceViaWitnessGateway).mockReset();
  });

  it("does not automatically retry cryptographically invalid evidence from the alarm", async () => {
    vi.mocked(checkpointReplayViaWitnessGateway).mockResolvedValue({
      checkpointed: true,
      canonicalEvidenceBody: new TextEncoder().encode("{}"),
    });
    vi.mocked(verifyEvidenceViaWitnessGateway).mockResolvedValue({
      verified: false,
      reason: "receipt_invalid",
    });
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    await harness.object.stageCheckpointIntent(pending);
    harness.clearAlarm();

    await harness.object.alarm();

    expect(checkpointReplayViaWitnessGateway).toHaveBeenCalledTimes(1);
    expect(verifyEvidenceViaWitnessGateway).toHaveBeenCalledTimes(1);
    expect(harness.getAlarm()).toBeNull();
    expect(harness.values.get("replay-checkpoint-pending-v1")).toEqual(pending);
    expect(harness.values.get(REPLAY_STATE_ENVELOPE_KEY)).toEqual(initial);
    expect(harness.values.get(REPLAY_CHECKPOINT_QUARANTINE_KEY)).toMatchObject({
      version: 1,
      reason: "evidence_not_verified",
    });

    // Simulate a crash after quarantine persistence but before alarm deletion:
    // constructor recovery must remove this stale trigger, not just avoid adding one.
    await harness.storage.setAlarm(Date.now() + 1_000);
    await rearmPendingCheckpointAlarm(harness.storage);
    expect(harness.getAlarm()).toBeNull();
    expect(harness.values.get("replay-checkpoint-pending-v1")).toEqual(pending);
    vi.mocked(checkpointReplayViaWitnessGateway).mockReset();
    vi.mocked(verifyEvidenceViaWitnessGateway).mockReset();
  });

  it("keeps pending intent when returned evidence fails independent verification", async () => {
    vi.mocked(checkpointReplayViaWitnessGateway).mockResolvedValue({
      checkpointed: true,
      canonicalEvidenceBody: new TextEncoder().encode("{}"),
    });
    vi.mocked(verifyEvidenceViaWitnessGateway).mockResolvedValue({
      verified: false,
      reason: "receipt_invalid",
    });
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    await harness.object.stageCheckpointIntent(pending);

    const result = await harness.object.recoverPendingCheckpointIntent();

    expect(result).toEqual({ recovered: false, reason: "evidence_not_verified" });
    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(true);
    expect((harness.values.get(REPLAY_STATE_ENVELOPE_KEY) as VersionedReplayState).stateVersion)
      .toBe(0);
    vi.mocked(checkpointReplayViaWitnessGateway).mockReset();
    vi.mocked(verifyEvidenceViaWitnessGateway).mockReset();
  });

  it("does not quarantine a replacement intent after an older alarm attempt", async () => {
    const harness = makeHarness();
    const initial: VersionedReplayState = {
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
    await harness.object.initializeCheckpointedState(initial);
    const proposedState = { highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      messageDigest: message(1).canonicalDigest,
      scope: "domain-a|witness-a|authority-a|host-a",
      expectedPredecessor: { generation: 0, digest: "0".repeat(64) },
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message(1), proposedState);
    await harness.object.stageCheckpointIntent(pending);
    harness.clearAlarm();

    vi.spyOn(harness.object, "recoverPendingCheckpointIntent").mockImplementation(async () => {
      // Model the original intent being finalized and a newer transition
      // being staged before the alarm's quarantine transaction runs.
      await harness.storage.transaction(async (txn) => {
        const current = await txn.get<PendingReplayIntent>("replay-checkpoint-pending-v1");
        if (current) {
          await txn.put("replay-checkpoint-pending-v1", {
            ...current,
            transitionDigest: "f".repeat(64),
          });
        }
      });
      return { recovered: false, reason: "evidence_not_verified" };
    });

    await harness.object.alarm();

    expect(harness.values.has("replay-checkpoint-pending-v1")).toBe(true);
    expect(harness.values.has(REPLAY_CHECKPOINT_QUARANTINE_KEY)).toBe(false);
  });

  it("keeps the HTTP surface closed", async () => {
    const harness = makeHarness();
    const response = await harness.object.fetch();
    expect(response.status).toBe(404);
  });
});
