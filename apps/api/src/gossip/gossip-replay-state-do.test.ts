import { describe, expect, it } from "vitest";
import { GossipReplayStateDO, type VerifiedGossipMessage } from "./gossip-replay-state-do";
import type { Env } from "../env";

function makeHarness(existing?: Map<string, unknown>) {
  const values = existing ?? new Map<string, unknown>();
  const storage = {
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T): Promise<void> {
      values.set(key, structuredClone(value));
    },
    async transaction<T>(callback: (txn: typeof storage) => Promise<T>): Promise<T> {
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

  it("keeps the HTTP surface closed", async () => {
    const harness = makeHarness();
    const response = await harness.object.fetch();
    expect(response.status).toBe(404);
  });
});
