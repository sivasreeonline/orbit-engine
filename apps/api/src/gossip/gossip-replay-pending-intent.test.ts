import { describe, expect, it } from "vitest";
import { createReplayCheckpointIntent } from "./gossip-replay-checkpoint-intent";
import {
  createPendingReplayIntent,
  validatePendingReplayIntent,
} from "./gossip-replay-pending-intent";

const scope = "domain-a|witness-a|authority-a|host-a";
const predecessor = { generation: 0, digest: "0".repeat(64) };
const message = {
  messageId: "message-1",
  senderId: "monitor-a",
  recipientId: "monitor-b",
  scope,
  sequence: 1,
  canonicalDigest: "a".repeat(64),
  messageType: "HEAD_ADVERTISEMENT",
  issuedAt: 9_990,
  expiresAt: 10_100,
};

describe("durable pending replay intent", () => {
  it("binds the exact triggering message and proposed state to the persisted request", async () => {
    const proposedState = {
      version: 1,
      highestSequence: 1,
      seenByMessageId: { "message-1": { sequence: 1, digest: "a".repeat(64) } },
    };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope,
      expectedPredecessor: predecessor,
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message, proposedState);

    expect(await validatePendingReplayIntent(pending)).toBe(true);
    expect(pending.intent.canonicalCheckpointBody).toBe(intent.canonicalCheckpointBody);
    expect(pending.transitionDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a proposed state that differs from the checkpoint snapshot", async () => {
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope,
      expectedPredecessor: predecessor,
      nextState: { version: 1, highestSequence: 1 },
    });
    await expect(createPendingReplayIntent(
      intent,
      message,
      { version: 1, highestSequence: 2 },
    )).rejects.toThrow(/differs from checkpoint snapshot/);
  });

  it("detects persisted transition and message tampering after restart", async () => {
    const proposedState = { version: 1, highestSequence: 1 };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 7,
      scope,
      expectedPredecessor: predecessor,
      nextState: proposedState,
    });
    const pending = await createPendingReplayIntent(intent, message, proposedState);

    expect(await validatePendingReplayIntent({
      ...pending,
      message: { ...pending.message, sequence: 2 },
    })).toBe(false);
    expect(await validatePendingReplayIntent({
      ...pending,
      proposedState: { ...pending.proposedState, highestSequence: 9 },
    })).toBe(false);
    expect(await validatePendingReplayIntent({
      ...pending,
      transitionDigest: "f".repeat(64),
    })).toBe(false);
  });

  it("binds the base version and deterministic operation to the transition digest", async () => {
    const state = { version: 1, highestSequence: 1 };
    const firstIntent = await createReplayCheckpointIntent({
      baseStateVersion: 1, scope, expectedPredecessor: predecessor, nextState: state,
    });
    const secondIntent = await createReplayCheckpointIntent({
      baseStateVersion: 2, scope, expectedPredecessor: predecessor, nextState: state,
    });
    const first = await createPendingReplayIntent(firstIntent, message, state);
    const second = await createPendingReplayIntent(secondIntent, message, state);

    expect(first.intent.operationId).toBe(second.intent.operationId);
    expect(first.transitionDigest).not.toBe(second.transitionDigest);
  });
});
