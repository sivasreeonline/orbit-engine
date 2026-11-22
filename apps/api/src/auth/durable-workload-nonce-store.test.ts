import { describe, expect, it } from "vitest";
import { DurableWorkloadNonceStore } from "./durable-workload-nonce-store";

describe("DurableWorkloadNonceStore", () => {
  it("routes nonce consumption to the caller-scoped Durable Object", async () => {
    const calls: unknown[][] = [];
    const namespace = {
      idFromName(name: string) { return { name }; },
      get(id: { name: string }) {
        return {
          async consumeNonce(callerId: string, nonce: string, expiresAt: number, trustedNow: number) {
            calls.push([id.name, callerId, nonce, expiresAt, trustedNow]);
            return true;
          },
        };
      },
    };
    const store = new DurableWorkloadNonceStore(namespace as never);
    const result = await store.consumeNonce("api-worker-a", "nonce-value", 10_060, 10_000);
    expect(result).toBe(true);
    expect(calls).toEqual([[
      "api-worker-a", "api-worker-a", "nonce-value", 10_060, 10_000,
    ]]);
  });
});
