import { describe, expect, it, vi } from "vitest";
import type { OutboxLease } from "./outbox-lease-repository";
import {
  publishOutboxBatch,
  type ExecutionQueue,
  type OutboxLeaseStore,
} from "./outbox-publisher";

const lease: OutboxLease = {
  id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1",
  executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
  eventType: "EXECUTION_REQUESTED",
  protocolVersion: "v1",
  correlationId: "corr-1",
  payload: {
    executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
    attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
    protocolVersion: "v1",
  },
  deliveryAttempts: 2,
  leaseToken: "ffffffff-ffff-4fff-8fff-fffffffffff1",
  leaseExpiresAt: "2026-11-09T12:00:00.000Z",
};

function setup(options: {
  readonly send?: () => Promise<void>;
  readonly acknowledged?: boolean;
  readonly released?: boolean;
} = {}) {
  const calls: string[] = [];
  const store: OutboxLeaseStore = {
    async claimBatch(workerId, batchSize, leaseDurationSeconds) {
      calls.push(`claim:${workerId}:${batchSize}:${leaseDurationSeconds}`);
      return [lease];
    },
    async markPublished(outboxId, workerId, token) {
      calls.push(`ack:${outboxId}:${workerId}:${token}`);
      return options.acknowledged ?? true;
    },
    async releaseForRetry(outboxId, workerId, token, availableAt) {
      calls.push(`release:${outboxId}:${workerId}:${token}:${availableAt.toISOString()}`);
      return options.released ?? true;
    },
  };
  const queue: ExecutionQueue = {
    send: options.send ?? vi.fn(async () => undefined),
  };
  return { store, queue, calls };
}

const publisherOptions = {
  workerId: "publisher-1",
  batchSize: 10,
  leaseDurationSeconds: 60,
  retryAt: (attempts: number, now: Date) => new Date(now.getTime() + attempts * 1_000),
};

describe("publishOutboxBatch", () => {
  it("sends the metadata payload before acknowledging the outbox lease", async () => {
    const { store, queue, calls } = setup();

    const outcomes = await publishOutboxBatch(store, queue, publisherOptions);

    expect(outcomes).toEqual([{ outboxId: lease.id, status: "PUBLISHED" }]);
    expect(calls[0]).toBe("claim:publisher-1:10:60");
    expect(calls[1]).toBe(`ack:${lease.id}:publisher-1:${lease.leaseToken}`);
    expect(queue.send).toHaveBeenCalledWith(lease.payload);
  });

  it("releases a failed queue send using the injected retry policy", async () => {
    const { store, queue, calls } = setup({
      send: vi.fn(async () => { throw new Error("queue unavailable"); }),
    });

    const outcomes = await publishOutboxBatch(store, queue, publisherOptions);

    expect(outcomes).toEqual([{ outboxId: lease.id, status: "SEND_FAILED_RELEASED" }]);
    expect(calls).toHaveLength(2);
    expect(calls[1]?.startsWith(`release:${lease.id}:publisher-1:${lease.leaseToken}:`)).toBe(true);
  });

  it("reports lease loss when a failed send cannot release its lease", async () => {
    const { store, queue } = setup({
      send: vi.fn(async () => { throw new Error("queue unavailable"); }),
      released: false,
    });

    await expect(publishOutboxBatch(store, queue, publisherOptions))
      .resolves.toEqual([{ outboxId: lease.id, status: "SEND_FAILED_LEASE_EXPIRED" }]);
  });

  it("reports acknowledgement loss without pretending the queue send was rolled back", async () => {
    const { store, queue } = setup({ acknowledged: false });

    await expect(publishOutboxBatch(store, queue, publisherOptions))
      .resolves.toEqual([{ outboxId: lease.id, status: "ACKNOWLEDGEMENT_LOST" }]);
  });
});
