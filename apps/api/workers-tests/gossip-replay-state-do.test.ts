import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type {
  GossipReplayPendingIntent,
  GossipReplayResult,
  VerifiedGossipMessage,
} from "../src/gossip/gossip-replay-state-do";
import { buildMonitorReplayCheckpointArtifact } from "../src/witness/monitor-replay-checkpoint";

function message(
  sequence: number,
  overrides: Partial<VerifiedGossipMessage> = {},
): VerifiedGossipMessage {
  return {
    messageId: `workers-runtime-message-${sequence}`,
    senderId: "runtime-monitor-a",
    recipientId: "runtime-monitor-b",
    scope: "runtime-domain|runtime-witness|runtime-authority|runtime-host",
    sequence,
    canonicalDigest: sequence.toString(16).padStart(64, "0"),
    messageType: "HEAD_ADVERTISEMENT",
    issuedAt: 9_990,
    expiresAt: 10_100,
    ...overrides,
  };
}

function replayObject(testName: string) {
  const id = env.GOSSIP_REPLAY.idFromName(
    `workers-runtime:${testName}:${crypto.randomUUID()}`,
  );
  return env.GOSSIP_REPLAY.get(id);
}

type ReplayStub = ReturnType<typeof env.GOSSIP_REPLAY.get>;

async function finalizePending(
  stub: ReplayStub,
  pending: GossipReplayPendingIntent,
): Promise<GossipReplayResult> {
  const scope = {
    trustDomainId: "runtime-test-trust-domain",
    witnessId: "runtime-test-witness",
    authorityId: "runtime-test-authority",
    hostId: "runtime-test-host",
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
  const finalized = await stub.finalizeCheckpointIntent({
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
    throw new Error(`synthetic witness finalization failed: ${finalized.status}: ${finalized.reason}`);
  }
  return finalized.replay;
}

async function acceptAndFinalize(
  stub: ReplayStub,
  value: VerifiedGossipMessage,
  trustedNow: number,
): Promise<GossipReplayResult> {
  const prepared = await stub.prepareCheckpointIntent(value, trustedNow);
  if (prepared.outcome !== "CHECKPOINT_PENDING" || !prepared.pendingIntent) {
    return prepared;
  }
  return finalizePending(stub, prepared.pendingIntent);
}

describe("GossipReplayStateDO in the local Cloudflare Workers runtime", () => {
  it("persists accepted replay state across separate RPC stub acquisitions", async () => {
    const id = env.GOSSIP_REPLAY.idFromName(
      `workers-runtime:persistence:${crypto.randomUUID()}`,
    );
    const firstStub = env.GOSSIP_REPLAY.get(id);
    const accepted = await acceptAndFinalize(firstStub, message(1), 10_000);

    const secondStub = env.GOSSIP_REPLAY.get(id);
    const duplicate = await acceptAndFinalize(secondStub, message(1), 10_000);

    expect(accepted.outcome).toBe("ACCEPTED");
    expect(duplicate.outcome).toBe("DUPLICATE");
    expect(duplicate.highestSequence).toBe(1);
  });

  it("serializes concurrent conflicting sequence claims without accepting both", async () => {
    const stub = replayObject("concurrent-equivocation");
    const original = message(1);
    const conflicting = message(1, {
      messageId: "workers-runtime-conflicting-message",
      canonicalDigest: "f".repeat(64),
    });
    const [left, right] = await Promise.all([
      stub.prepareCheckpointIntent(original, 10_000),
      stub.prepareCheckpointIntent(conflicting, 10_000),
    ]);
    expect([left.outcome, right.outcome].sort()).toEqual([
      "BLOCKED",
      "CHECKPOINT_PENDING",
    ]);
    const pending = left.pendingIntent ? left : right;
    const blocked = left.pendingIntent ? right : left;
    expect(blocked.outcome).toBe("BLOCKED");
    await finalizePending(stub, pending.pendingIntent!);

    const otherMessage = left.pendingIntent ? conflicting : original;
    const conflict = await stub.prepareCheckpointIntent(otherMessage, 10_000);
    expect(conflict.outcome).toBe("QUARANTINE");
    expect(conflict.highestSequence).toBe(1);
  });

  it("persists request correlation and nonce consumption across RPC calls", async () => {
    const stub = replayObject("proof-request-nonce");
    const request = message(1, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "workers-runtime-nonce",
    });
    const acceptedRequest = await acceptAndFinalize(stub, request, 10_000);
    const response = message(2, {
      messageType: "CONSISTENCY_PROOF_RESPONSE",
      responseRequestId: request.messageId,
      responseNonce: "workers-runtime-nonce",
    });
    const acceptedResponse = await acceptAndFinalize(stub, response, 10_000);
    const reusedNonce = await acceptAndFinalize(stub, 
      message(3, {
        messageType: "CONSISTENCY_PROOF_REQUEST",
        requestNonce: "workers-runtime-nonce",
      }),
      10_000,
    );

    expect(acceptedRequest.outcome).toBe("ACCEPTED");
    expect(acceptedResponse.outcome).toBe("ACCEPTED");
    expect(reusedNonce.outcome).toBe("QUARANTINE");
  });

  it("keeps the Durable Object HTTP surface closed in workerd", async () => {
    const stub = replayObject("closed-http-surface");
    const response = await stub.fetch("https://gossip-replay.invalid/");
    expect(response.status).toBe(404);
  });
  it("returns the complete normalized replay snapshot for independent checkpointing", async () => {
    const stub = replayObject("snapshot-export");
    const empty = await stub.readSnapshot();
    expect(empty).toMatchObject({
      version: 1,
      senderId: "",
      recipientId: "",
      scope: "",
      highestSequence: 0,
      seenBySequence: {},
      seenByMessageId: {},
      outstandingRequests: {},
      consumedNonces: [],
      missingSequences: [],
    });

    const request = message(2, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "snapshot-export-nonce",
    });
    await acceptAndFinalize(stub, request, 10_000);
    const snapshot = await stub.readSnapshot();
    expect(snapshot).toMatchObject({
      senderId: "runtime-monitor-a",
      recipientId: "runtime-monitor-b",
      scope: request.scope,
      highestSequence: 2,
      seenBySequence: {
        "2": {
          messageId: request.messageId,
          digest: request.canonicalDigest,
        },
      },
      outstandingRequests: {
        [request.messageId]: {
          nonce: "snapshot-export-nonce",
          expiresAt: request.expiresAt,
        },
      },
      consumedNonces: [],
      missingSequences: [1],
    });
  });

  it("keeps replay state pending until verified finalization and supports idempotent recovery", async () => {
    const stub = replayObject("pending-intent-finalize");
    const prepared = await stub.prepareCheckpointIntent(message(1), 10_000);
    expect(prepared.outcome).toBe("CHECKPOINT_PENDING");
    expect(prepared.pendingIntent?.operationId).toMatch(/^fence-monitor-replay-[0-9a-f]{64}$/);
    expect((await stub.readSnapshot()).highestSequence).toBe(0);
    expect((await stub.readPendingCheckpointIntent())?.snapshot.highestSequence).toBe(1);

    const blocked = await stub.prepareCheckpointIntent(message(2), 10_000);
    expect(blocked.outcome).toBe("BLOCKED");

    const pending = prepared.pendingIntent!;
    const scope = {
      trustDomainId: "runtime-test-trust-domain",
      witnessId: "runtime-test-witness",
      authorityId: "runtime-test-authority",
      hostId: "runtime-test-host",
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
    const input = {
      operationId: pending.operationId,
      snapshotDigest: pending.snapshotDigest,
      generation: pending.expectedGeneration + 1,
      checkpointDigest: artifact.checkpointDigest,
      receiptDigest: "b".repeat(64),
      verification: {
        verified: true as const,
        trustBundleDigest: "c".repeat(64),
        treeHeadDigest: "d".repeat(64),
        treeSize: 1,
        receiptLeafHash: "e".repeat(64),
      },
    };
    const finalized = await stub.finalizeCheckpointIntent(input);
    const recovered = await stub.finalizeCheckpointIntent(input);
    expect(finalized.status).toBe("FINALIZED");
    expect(recovered.status).toBe("ALREADY_FINALIZED");
    expect((await stub.readSnapshot()).highestSequence).toBe(1);
    expect((await stub.readPendingCheckpointIntent())).toBeNull();
    expect((await stub.readCheckpointState())?.checkpointDigest).toBe(artifact.checkpointDigest);
  });

});
