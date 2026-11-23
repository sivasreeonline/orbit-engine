import { describe, expect, it } from "vitest";
import {
  GossipReplayStateDO,
  type GossipReplayResult,
  type GossipReplayPendingIntent,
  type VerifiedGossipMessage,
} from "./gossip-replay-state-do";
import { buildMonitorReplayCheckpointArtifact } from "../witness/monitor-replay-checkpoint";
import type { Env } from "../env";

interface FakeStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(callback: (txn: FakeStorage) => Promise<T>): Promise<T>;
}

function makeHarness(existing?: Map<string, unknown>) {
  const values = existing ?? new Map<string, unknown>();
  const storage: FakeStorage = {
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async delete(key: string): Promise<boolean> {
      return values.delete(key);
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
  const state = { storage } as unknown as DurableObjectState;
  return {
    object: new GossipReplayStateDO(state, {} as Env),
    values,
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

async function finalizePending(
  object: GossipReplayStateDO,
  pending: GossipReplayPendingIntent,
): Promise<GossipReplayResult> {
  const scope = {
    trustDomainId: "test-trust-domain",
    witnessId: "test-witness",
    authorityId: "test-authority",
    hostId: "test-host",
    senderId: pending.snapshot.senderId,
    recipientId: pending.snapshot.recipientId,
    replayScope: pending.snapshot.scope,
  };
  const artifact = await buildMonitorReplayCheckpointArtifact(
    pending.snapshot,
    scope,
    pending.expectedGeneration + 1,
    pending.expectedPreviousDigest,
  );
  const finalized = await object.finalizeCheckpointIntent({
    operationId: pending.operationId,
    snapshotDigest: pending.snapshotDigest,
    generation: pending.expectedGeneration + 1,
    checkpointDigest: artifact.checkpointDigest,
    receiptDigest: "b".repeat(64),
    verification: {
      verified: true,
      trustBundleDigest: "c".repeat(64),
      treeHeadDigest: "d".repeat(64),
      treeSize: pending.expectedGeneration + 1,
      receiptLeafHash: "e".repeat(64),
    },
  });
  if (!finalized.replay) {
    throw new Error(`synthetic checkpoint finalization failed: ${finalized.status}: ${finalized.reason}`);
  }
  return finalized.replay;
}

async function acceptAndFinalize(
  object: GossipReplayStateDO,
  value: VerifiedGossipMessage,
  trustedNow: number,
): Promise<GossipReplayResult> {
  const prepared = await object.prepareCheckpointIntent(value, trustedNow);
  if (prepared.outcome !== "CHECKPOINT_PENDING" || !prepared.pendingIntent) {
    return prepared;
  }
  return finalizePending(object, prepared.pendingIntent);
}

describe("GossipReplayStateDO", () => {
  it("commits accepted replay state and survives object reconstruction", async () => {
    const first = makeHarness();
    const accepted = await acceptAndFinalize(first.object, message(1), 10_000);
    expect(accepted.outcome).toBe("ACCEPTED");

    const restarted = makeHarness(first.values);
    const duplicate = await acceptAndFinalize(restarted.object, message(1), 10_000);
    expect(duplicate.outcome).toBe("DUPLICATE");
    expect(duplicate.highestSequence).toBe(1);
  });

  it("quarantines same-sequence equivocation without changing durable state", async () => {
    const harness = makeHarness();
    await acceptAndFinalize(harness.object, message(1), 10_000);
    const before = structuredClone(harness.values.get("replay-state-v1"));
    const result = await acceptAndFinalize(harness.object, 
      message(1, { messageId: "different-message", canonicalDigest: "f".repeat(64) }),
      10_000,
    );
    expect(result.outcome).toBe("QUARANTINE");
    expect(harness.values.get("replay-state-v1")).toEqual(before);
  });

  it("records sequence gaps and clears them only when missing messages arrive", async () => {
    const harness = makeHarness();
    const gap = await acceptAndFinalize(harness.object, message(3), 10_000);
    expect(gap.outcome).toBe("ACCEPTED_WITH_GAP");
    expect(gap.missingSequences).toEqual([1, 2]);

    const one = await acceptAndFinalize(harness.object, message(1), 10_000);
    expect(one.outcome).toBe("ACCEPTED_WITH_GAP");
    expect(one.missingSequences).toEqual([2]);

    const two = await acceptAndFinalize(harness.object, message(2), 10_000);
    expect(two.outcome).toBe("ACCEPTED");
    expect(two.missingSequences).toEqual([]);
  });

  it("rejects a relationship identity or scope change", async () => {
    const harness = makeHarness();
    await acceptAndFinalize(harness.object, message(1), 10_000);
    const result = await acceptAndFinalize(harness.object, 
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
    expect((await acceptAndFinalize(harness.object, request, 10_000)).outcome)
      .toBe("ACCEPTED");

    const response = message(2, {
      messageType: "CONSISTENCY_PROOF_RESPONSE",
      responseRequestId: request.messageId,
      responseNonce: "fresh-nonce-1",
    });
    expect((await acceptAndFinalize(harness.object, response, 10_000)).outcome)
      .toBe("ACCEPTED");

    const reused = message(3, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "fresh-nonce-1",
    });
    expect((await acceptAndFinalize(harness.object, reused, 10_000)).outcome)
      .toBe("QUARANTINE");
  });

  it("blocks expired, oversized-gap and out-of-window messages", async () => {
    const harness = makeHarness();
    expect((await acceptAndFinalize(harness.object, 
      message(1, { expiresAt: 9_999 }), 10_000,
    )).outcome).toBe("BLOCKED");
    expect((await acceptAndFinalize(harness.object, message(65), 10_000)).outcome)
      .toBe("BLOCKED");
  });

  it("keeps the HTTP surface closed", async () => {
    const harness = makeHarness();
    const response = await harness.object.fetch();
    expect(response.status).toBe(404);
  });
});
