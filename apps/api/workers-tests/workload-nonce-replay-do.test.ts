import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

function nonce(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

function replayStub(callerId: string) {
  return env.WORKLOAD_NONCE_REPLAY.get(
    env.WORKLOAD_NONCE_REPLAY.idFromName(callerId),
  );
}

describe("WorkloadNonceReplayDO in the local Cloudflare Workers runtime", () => {
  it("atomically rejects concurrent duplicate nonce claims", async () => {
    const callerId = `runtime-worker-${crypto.randomUUID()}`;
    const value = nonce();
    const now = Math.floor(Date.now() / 1_000);
    const stub = replayStub(callerId);
    const results = await Promise.all([
      stub.consumeNonce(callerId, value, now + 60, now),
      stub.consumeNonce(callerId, value, now + 60, now),
    ]);
    expect(results.sort()).toEqual([false, true]);
  });

  it("persists nonce consumption across separate stub acquisitions", async () => {
    const callerId = `runtime-worker-${crypto.randomUUID()}`;
    const value = nonce();
    const now = Math.floor(Date.now() / 1_000);
    const first = await replayStub(callerId).consumeNonce(callerId, value, now + 60, now);
    const second = await replayStub(callerId).consumeNonce(callerId, value, now + 60, now);
    expect(first).toBe(true);
    expect(second).toBe(false);
  });

  it("isolates equal nonces from different workload identities", async () => {
    const nonceValue = nonce();
    const now = Math.floor(Date.now() / 1_000);
    const callerA = `runtime-worker-a-${crypto.randomUUID()}`;
    const callerB = `runtime-worker-b-${crypto.randomUUID()}`;
    const [a, b] = await Promise.all([
      replayStub(callerA).consumeNonce(callerA, nonceValue, now + 60, now),
      replayStub(callerB).consumeNonce(callerB, nonceValue, now + 60, now),
    ]);
    expect(a).toBe(true);
    expect(b).toBe(true);
  });

  it("keeps the Durable Object HTTP surface closed in workerd", async () => {
    const callerId = `runtime-worker-http-${crypto.randomUUID()}`;
    const stub = replayStub(callerId);
    expect((await stub.fetch("https://workload-nonce.invalid/")).status).toBe(404);
  });
});
