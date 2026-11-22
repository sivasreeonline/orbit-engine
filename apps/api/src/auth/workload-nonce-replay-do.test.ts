import { describe, expect, it } from "vitest";
import { WorkloadNonceReplayDO } from "./workload-nonce-replay-do";
import type { Env } from "../env";

interface FakeStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(options?: { prefix?: string; limit?: number }): Promise<Map<string, T>>;
  transaction<T>(callback: (txn: FakeStorage) => Promise<T>): Promise<T>;
  getAlarm(): Promise<number | null>;
  setAlarm(timestamp: number): Promise<void>;
  deleteAlarm(): Promise<void>;
}

function makeHarness(existing?: Map<string, unknown>, initialAlarm: number | null = null) {
  const values = existing ?? new Map<string, unknown>();
  let alarm = initialAlarm;
  let tail = Promise.resolve();
  const storage: FakeStorage = {
    async get<T>(key: string) {
      return values.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T) {
      values.set(key, structuredClone(value));
    },
    async delete(key: string) {
      return values.delete(key);
    },
    async list<T>(options = {}) {
      const entries = [...values.entries()]
        .filter(([key]) => !options.prefix || key.startsWith(options.prefix))
        .slice(0, options.limit ?? Number.POSITIVE_INFINITY);
      return new Map(entries) as Map<string, T>;
    },
    transaction<T>(callback: (txn: FakeStorage) => Promise<T>): Promise<T> {
      const run = tail.then(async () => {
        const snapshot = structuredClone([...values.entries()]);
        try {
          return await callback(storage);
        } catch (error) {
          values.clear();
          for (const [key, value] of snapshot) values.set(key, value);
          throw error;
        }
      });
      tail = run.then(() => undefined, () => undefined);
      return run;
    },
    async getAlarm() {
      return alarm;
    },
    async setAlarm(timestamp: number) {
      alarm = timestamp;
    },
    async deleteAlarm() {
      alarm = null;
    },
  };
  const state = { storage } as unknown as DurableObjectState;
  return {
    object: new WorkloadNonceReplayDO(state, {} as Env),
    values,
    get alarm() { return alarm; },
  };
}

const CALLER = "api-worker-test";
const NONCE = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg";

describe("WorkloadNonceReplayDO", () => {
  it("atomically consumes a nonce and preserves it across reconstruction", async () => {
    const first = makeHarness();
    expect(await first.object.consumeNonce(CALLER, NONCE, 10_060, 10_000)).toBe(true);

    const restarted = makeHarness(first.values, first.alarm);
    expect(await restarted.object.consumeNonce(CALLER, NONCE, 10_060, 10_000)).toBe(false);
    expect(restarted.values.size).toBe(1);
  });

  it("serializes concurrent attempts so exactly one invocation consumes a nonce", async () => {
    const harness = makeHarness();
    const results = await Promise.all([
      harness.object.consumeNonce(CALLER, NONCE, 10_060, 10_000),
      harness.object.consumeNonce(CALLER, NONCE, 10_060, 10_000),
    ]);
    expect(results.sort()).toEqual([false, true]);
  });

  it("keeps caller nonce spaces isolated", async () => {
    const harness = makeHarness();
    expect(await harness.object.consumeNonce("api-worker-a", NONCE, 10_060, 10_000)).toBe(true);
    expect(await harness.object.consumeNonce("api-worker-b", NONCE, 10_060, 10_000)).toBe(true);
  });

  it("retains replay entries through expiry plus clock-skew allowance", async () => {
    const harness = makeHarness();
    expect(await harness.object.consumeNonce(CALLER, NONCE, 10_060, 10_000)).toBe(true);
    expect(await harness.object.consumeNonce(CALLER, NONCE, 10_200, 10_089)).toBe(false);
    expect(await harness.object.consumeNonce(CALLER, NONCE, 10_150, 10_091)).toBe(true);
  });

  it("rejects malformed identities, nonces and time horizons", async () => {
    const harness = makeHarness();
    expect(await harness.object.consumeNonce("../caller", NONCE, 10_060, 10_000)).toBe(false);
    expect(await harness.object.consumeNonce(CALLER, "short", 10_060, 10_000)).toBe(false);
    expect(await harness.object.consumeNonce(CALLER, NONCE, 10_000, 10_000)).toBe(false);
    expect(await harness.object.consumeNonce(CALLER, NONCE, 10_200, 10_000)).toBe(false);
  });

  it("cleans expired nonce entries on the Durable Object alarm", async () => {
    const expiredKey = `workload-nonce-v1:${CALLER}:${NONCE}`;
    const harness = makeHarness(new Map([[expiredKey, Math.floor(Date.now() / 1_000) - 60]]));
    await harness.object.alarm();
    expect(harness.values.has(expiredKey)).toBe(false);
    expect(harness.alarm).toBeNull();
  });

  it("keeps the HTTP surface closed", async () => {
    const harness = makeHarness();
    expect((await harness.object.fetch()).status).toBe(404);
  });
});
