import { describe, expect, it } from "vitest";
import {
  createReplayCheckpointIntent,
  validateReplayCheckpointIntent,
} from "./gossip-replay-checkpoint-intent";

const predecessor = { generation: 0, digest: "0".repeat(64) };
const scope = "domain-a|witness-a|authority-a|host-a";

describe("durable replay checkpoint intent", () => {
  it("creates deterministic operation IDs and canonical request bytes", async () => {
    const input = {
      baseStateVersion: 4,
      scope,
      expectedPredecessor: predecessor,
      nextState: { version: 1, highestSequence: 7, seen: { "7": "a".repeat(64) } },
    };
    const first = await createReplayCheckpointIntent(input);
    const second = await createReplayCheckpointIntent(input);

    expect(first.operationId).toBe(second.operationId);
    expect(first.canonicalCheckpointBody).toBe(second.canonicalCheckpointBody);
    expect(await validateReplayCheckpointIntent(first)).toBe(true);
  });

  it("separates idempotency keys across scope and predecessor while preserving retries", async () => {
    const base = {
      baseStateVersion: 4,
      scope,
      expectedPredecessor: predecessor,
      nextState: { version: 1, highestSequence: 7 },
    };
    const sameSnapshotDifferentScope = await createReplayCheckpointIntent({
      ...base,
      scope: "domain-b|witness-a|authority-a|host-a",
    });
    const sameSnapshotDifferentPredecessor = await createReplayCheckpointIntent({
      ...base,
      expectedPredecessor: { generation: 1, digest: "b".repeat(64) },
    });
    const original = await createReplayCheckpointIntent(base);
    expect(sameSnapshotDifferentScope.snapshotDigest).toBe(original.snapshotDigest);
    expect(sameSnapshotDifferentPredecessor.snapshotDigest).toBe(original.snapshotDigest);
    expect(sameSnapshotDifferentScope.operationId).not.toBe(original.operationId);
    expect(sameSnapshotDifferentPredecessor.operationId).not.toBe(original.operationId);
  });

  it("binds the request to its base state version and exact witness predecessor", async () => {
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 8,
      scope,
      expectedPredecessor: { generation: 3, digest: "b".repeat(64) },
      nextState: { version: 1, highestSequence: 9 },
    });

    expect(intent.baseStateVersion).toBe(8);
    expect(intent.expectedPredecessor).toEqual({
      generation: 3,
      digest: "b".repeat(64),
    });
    expect(await validateReplayCheckpointIntent(intent)).toBe(true);
  });

  it("rejects malformed relationship scopes and predecessor digests", async () => {
    await expect(createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope: "domain|witness|authority",
      expectedPredecessor: predecessor,
      nextState: { version: 1 },
    })).rejects.toThrow(/four non-empty/);

    await expect(createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope,
      expectedPredecessor: { generation: 0, digest: "not-a-digest" },
      nextState: { version: 1 },
    })).rejects.toThrow(/predecessor/);
  });

  it("detects tampering with persisted request bytes", async () => {
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 1,
      scope,
      expectedPredecessor: predecessor,
      nextState: { version: 1, highestSequence: 1 },
    });

    const tampered = {
      ...intent,
      canonicalSnapshotBase64Url: intent.canonicalSnapshotBase64Url.slice(0, -1) +
        (intent.canonicalSnapshotBase64Url.endsWith("A") ? "B" : "A"),
    };
    expect(await validateReplayCheckpointIntent(tampered)).toBe(false);
  });

  it("rejects extra fields in persisted intent and scope objects", async () => {
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope,
      expectedPredecessor: predecessor,
      nextState: { version: 1 },
    });

    expect(await validateReplayCheckpointIntent({
      ...intent,
      unexpected: true,
    } as typeof intent)).toBe(false);
    expect(await validateReplayCheckpointIntent({
      ...intent,
      scope: { ...intent.scope, unexpected: true } as typeof intent.scope,
    })).toBe(false);
  });

  it("rejects non-plain snapshots", async () => {
    await expect(createReplayCheckpointIntent({
      baseStateVersion: 0,
      scope,
      expectedPredecessor: predecessor,
      nextState: Object.create({ inherited: true }) as Record<string, unknown>,
    })).rejects.toThrow(/plain JSON object/);
  });
});
