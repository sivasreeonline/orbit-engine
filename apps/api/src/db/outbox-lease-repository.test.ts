import { describe, expect, it } from "vitest";
import { PostgresOutboxLeaseRepository } from "./outbox-lease-repository";

interface QueryCall {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

function fakeClient(rows: Record<string, unknown>[] = []) {
  const calls: QueryCall[] = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      return { rows: rows as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";
const outboxId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1";
const leaseToken = "ffffffff-ffff-4fff-8fff-fffffffffff1";

describe("PostgresOutboxLeaseRepository", () => {
  it("claims a bounded batch using SKIP LOCKED and increments delivery attempts", async () => {
    const fake = fakeClient([{
      id: outboxId,
      execution_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      event_type: "EXECUTION_REQUESTED",
      protocol_version: "v1",
      correlation_id: "corr-1",
      payload: { executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" },
      delivery_attempts: 1,
      lease_token: leaseToken,
      lease_expires_at: new Date("2026-11-09T12:00:00.000Z"),
    }]);
    const repository = new PostgresOutboxLeaseRepository(connection, () => fake.client);

    const claimed = await repository.claimBatch("publisher-1", 10, 60);

    expect(claimed).toEqual([{
      id: outboxId,
      executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
      eventType: "EXECUTION_REQUESTED",
      protocolVersion: "v1",
      correlationId: "corr-1",
      payload: { executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" },
      deliveryAttempts: 1,
      leaseToken,
      leaseExpiresAt: "2026-11-09T12:00:00.000Z",
    }]);
    const claimQuery = fake.calls[1];
    expect(claimQuery?.text).toContain("FOR UPDATE SKIP LOCKED");
    expect(claimQuery?.text).toContain("delivery_attempts = outbox.delivery_attempts + 1");
    expect(claimQuery?.text).toContain("lease_expires_at <= now()");
    expect(claimQuery?.values).toEqual([10, "publisher-1", 60]);
    expect(fake.ended()).toBe(true);
  });

  it("acknowledges only the matching active lease", async () => {
    const fake = fakeClient([{ id: outboxId }]);
    const repository = new PostgresOutboxLeaseRepository(connection, () => fake.client);

    await expect(repository.markPublished(outboxId, "publisher-1", leaseToken)).resolves.toBe(true);

    const ack = fake.calls[1];
    expect(ack?.text).toContain("delivery_state = 'PUBLISHED'");
    expect(ack?.text).toContain("lease_owner = $2 AND lease_token = $3::uuid");
    expect(ack?.text).toContain("lease_expires_at > now()");
    expect(ack?.text).toContain("published_at = now()");
  });

  it("rejects stale acknowledgements when the lease token no longer matches", async () => {
    const fake = fakeClient([]);
    const repository = new PostgresOutboxLeaseRepository(connection, () => fake.client);

    await expect(repository.markPublished(outboxId, "old-publisher", leaseToken))
      .resolves.toBe(false);
  });

  it("releases a failed delivery only for the active lease and caller-selected retry time", async () => {
    const fake = fakeClient([{ id: outboxId }]);
    const repository = new PostgresOutboxLeaseRepository(connection, () => fake.client);
    const availableAt = new Date("2026-11-09T12:05:00.000Z");

    await expect(repository.releaseForRetry(
      outboxId, "publisher-1", leaseToken, availableAt,
    )).resolves.toBe(true);

    const release = fake.calls[1];
    expect(release?.text).toContain("available_at = $4::timestamptz");
    expect(release?.text).toContain("lease_expires_at > now()");
    expect(release?.values).toEqual([
      outboxId, "publisher-1", leaseToken, availableAt.toISOString(),
    ]);
  });

  it("fails closed when database configuration is absent", async () => {
    const repository = new PostgresOutboxLeaseRepository(undefined);
    await expect(repository.claimBatch("publisher-1", 1, 30))
      .rejects.toThrow("database_unavailable");
  });

  it("validates batch, lease and worker inputs before opening a connection", async () => {
    const fake = fakeClient();
    const repository = new PostgresOutboxLeaseRepository(connection, () => fake.client);

    await expect(repository.claimBatch("", 1, 30)).rejects.toThrow("invalid_outbox_worker_id");
    await expect(repository.claimBatch("publisher-1", 0, 30)).rejects.toThrow("invalid_outbox_batch_size");
    await expect(repository.claimBatch("publisher-1", 101, 30)).rejects.toThrow("invalid_outbox_batch_size");
    await expect(repository.claimBatch("publisher-1", 1, 0)).rejects.toThrow("invalid_outbox_lease_duration");
    expect(fake.calls).toHaveLength(0);
    expect(fake.ended()).toBe(false);
  });
});
