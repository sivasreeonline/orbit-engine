import { describe, expect, it, vi } from "vitest";
import type { OutboxLease } from "../db/outbox-lease-repository";
import {
  LocalExecutionOutboxDispatcher,
  type LocalExecutionDispatchEnvelope,
  type LocalOutboxLeaseRepository,
} from "./local-execution-outbox-dispatcher";

const executionId = "10000000-0000-4000-8000-000000000001";
const attemptId = "20000000-0000-4000-8000-000000000001";

function lease(overrides: Partial<OutboxLease> = {}): OutboxLease {
  return {
    id: "30000000-0000-4000-8000-000000000001",
    executionId,
    eventType: "EXECUTION_REQUESTED",
    protocolVersion: "v1",
    correlationId: "local-dispatch-test",
    payload: { executionId, attemptId, protocolVersion: "v1" },
    deliveryAttempts: 1,
    leaseToken: "40000000-0000-4000-8000-000000000001",
    leaseExpiresAt: "2026-11-13T00:00:00.000Z",
    ...overrides,
  };
}

function repository(batch: OutboxLease[], marked = true) {
  const outbox: LocalOutboxLeaseRepository = {
    claimBatch: vi.fn().mockResolvedValue(batch),
    markPublished: vi.fn().mockResolvedValue(marked),
    markDeadLetter: vi.fn().mockResolvedValue(true),
  };
  return outbox;
}

const configuration = {
  workerId: "local-dispatcher-1",
  batchSize: 10,
  leaseDurationSeconds: 30,
};

describe("LocalExecutionOutboxDispatcher", () => {
  it("acknowledges only after the durable sink accepts the exact opaque envelope", async () => {
    const item = lease();
    const outbox = repository([item]);
    const order: string[] = [];
    vi.mocked(outbox.markPublished).mockImplementation(async () => {
      order.push("ack");
      return true;
    });
    const sink = {
      accept: vi.fn(async (value: LocalExecutionDispatchEnvelope) => {
        order.push("sink");
        expect(value).toEqual({ executionId, attemptId, protocolVersion: "v1" });
      }),
    };

    const dispatcher = new LocalExecutionOutboxDispatcher(outbox, sink, configuration);
    await expect(dispatcher.dispatchOnce()).resolves.toEqual({
      claimed: 1, acknowledged: 1, rejected: 0, fenced: 0,
    });

    expect(order).toEqual(["sink", "ack"]);
    expect(outbox.markPublished).toHaveBeenCalledWith(
      item.id, configuration.workerId, item.leaseToken,
    );
  });

  it("does not acknowledge when durable sink acceptance fails", async () => {
    const outbox = repository([lease()]);
    const sink = { accept: vi.fn().mockRejectedValue(new Error("durable sink unavailable")) };
    const dispatcher = new LocalExecutionOutboxDispatcher(outbox, sink, configuration);

    await expect(dispatcher.dispatchOnce()).resolves.toEqual({
      claimed: 1, acknowledged: 0, rejected: 1, fenced: 0,
    });
    expect(outbox.markPublished).not.toHaveBeenCalled();
  });

  it("rejects payloads containing source or other unexpected fields", async () => {
    const item = lease({
      payload: {
        executionId,
        attemptId,
        protocolVersion: "v1",
        sourceCode: "must never enter the queue envelope",
      },
    });
    const outbox = repository([item]);
    const sink = { accept: vi.fn() };
    const dispatcher = new LocalExecutionOutboxDispatcher(outbox, sink, configuration);

    await expect(dispatcher.dispatchOnce()).resolves.toEqual({
      claimed: 1, acknowledged: 0, rejected: 1, fenced: 0,
    });
    expect(sink.accept).not.toHaveBeenCalled();
    expect(outbox.markPublished).not.toHaveBeenCalled();
    expect(outbox.markDeadLetter).toHaveBeenCalledWith(
      item.id, configuration.workerId, item.leaseToken,
    );
    expect(outbox.markDeadLetter).not.toHaveBeenCalled();
  });

  it("reports a stale lease as fenced when acknowledgement loses the race", async () => {
    const outbox = repository([lease()], false);
    const sink = { accept: vi.fn().mockResolvedValue(undefined) };
    const dispatcher = new LocalExecutionOutboxDispatcher(outbox, sink, configuration);

    await expect(dispatcher.dispatchOnce()).resolves.toEqual({
      claimed: 1, acknowledged: 0, rejected: 0, fenced: 1,
    });
  });

  it("validates bounded local worker configuration", () => {
    const outbox = repository([]);
    const sink = { accept: vi.fn().mockResolvedValue(undefined) };

    expect(() => new LocalExecutionOutboxDispatcher(outbox, sink, {
      ...configuration, batchSize: 101,
    })).toThrow("invalid_local_dispatch_batch_size");
    expect(() => new LocalExecutionOutboxDispatcher(outbox, sink, {
      ...configuration, leaseDurationSeconds: 0,
    })).toThrow("invalid_local_dispatch_lease_duration");
  });
});
