import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { VerifiedGossipMessage } from "../src/gossip/gossip-replay-state-do";

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

describe("GossipReplayStateDO in the local Cloudflare Workers runtime", () => {
  it("persists accepted replay state across separate RPC stub acquisitions", async () => {
    const id = env.GOSSIP_REPLAY.idFromName(
      `workers-runtime:persistence:${crypto.randomUUID()}`,
    );
    const firstStub = env.GOSSIP_REPLAY.get(id);
    const accepted = await firstStub.acceptVerifiedMessage(message(1), 10_000);

    const secondStub = env.GOSSIP_REPLAY.get(id);
    const duplicate = await secondStub.acceptVerifiedMessage(message(1), 10_000);

    expect(accepted.outcome).toBe("ACCEPTED");
    expect(duplicate.outcome).toBe("DUPLICATE");
    expect(duplicate.highestSequence).toBe(1);
  });

  it("serializes concurrent conflicting sequence claims without accepting both", async () => {
    const stub = replayObject("concurrent-equivocation");
    const [left, right] = await Promise.all([
      stub.acceptVerifiedMessage(message(1), 10_000),
      stub.acceptVerifiedMessage(
        message(1, {
          messageId: "workers-runtime-conflicting-message",
          canonicalDigest: "f".repeat(64),
        }),
        10_000,
      ),
    ]);

    expect([left.outcome, right.outcome].sort()).toEqual([
      "ACCEPTED",
      "QUARANTINE",
    ]);
    expect(left.highestSequence).toBe(1);
    expect(right.highestSequence).toBe(1);
  });

  it("persists request correlation and nonce consumption across RPC calls", async () => {
    const stub = replayObject("proof-request-nonce");
    const request = message(1, {
      messageType: "CONSISTENCY_PROOF_REQUEST",
      requestNonce: "workers-runtime-nonce",
    });
    const acceptedRequest = await stub.acceptVerifiedMessage(request, 10_000);
    const response = message(2, {
      messageType: "CONSISTENCY_PROOF_RESPONSE",
      responseRequestId: request.messageId,
      responseNonce: "workers-runtime-nonce",
    });
    const acceptedResponse = await stub.acceptVerifiedMessage(response, 10_000);
    const reusedNonce = await stub.acceptVerifiedMessage(
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
});
