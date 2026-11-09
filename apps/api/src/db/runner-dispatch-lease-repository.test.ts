import { describe, expect, it } from "vitest";
import {
  PostgresRunnerDispatchLeaseRepository,
  RunnerDispatchReceiptConflictError,
  StaleRunnerDispatchLeaseError,
} from "./runner-dispatch-lease-repository";

interface Call { readonly text: string; readonly values: unknown[] | undefined; }
function fakeClient(responses: Record<string, unknown>[][] = []) {
  const calls: Call[] = [];
  let ended = false;
  let index = 0;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      const rows = responses[index] ?? [];
      index += 1;
      return { rows: rows as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}
const connection = "postgres://test-user:test-password@localhost/test";
const dispatchId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const attemptId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const token = "dddddddd-dddd-4ddd-8ddd-ddddddddddd1";
const receiptHash = "a".repeat(64);

describe("PostgresRunnerDispatchLeaseRepository", () => {
  it("claims bounded pending work with SKIP LOCKED and a fresh fencing token", async () => {
    const fake = fakeClient([
      [],
      [{
        id: dispatchId, execution_id: executionId, attempt_id: attemptId,
        protocol_version: "v1", correlation_id: "corr-1", delivery_attempts: 1,
        lease_token: token, lease_expires_at: new Date("2026-11-09T12:00:00Z"),
      }],
    ]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.claimBatch("runner-dispatcher-1", 10, 60)).resolves.toEqual([{
      id: dispatchId, executionId, attemptId, protocolVersion: "v1",
      correlationId: "corr-1", deliveryAttempts: 1, leaseToken: token,
      leaseExpiresAt: "2026-11-09T12:00:00.000Z",
    }]);
    expect(fake.calls[1]?.text).toContain("FOR UPDATE SKIP LOCKED");
    expect(fake.calls[1]?.text).toContain("delivery_attempts = dispatch.delivery_attempts + 1");
    expect(fake.ended()).toBe(true);
  });

  it("persists receipt and marks delivered in one fenced transaction", async () => {
    const fake = fakeClient([[], [], [], [], [{ id: dispatchId }], [], [{ id: dispatchId }], []]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.recordReceipt(
      dispatchId, "runner-1", token, "receipt-001", receiptHash,
    )).resolves.toEqual({ status: "RECORDED" });
    expect(fake.calls[1]?.text).toBe("BEGIN");
    expect(fake.calls[5]?.text).toContain("INSERT INTO runner_dispatch_receipts");
    expect(fake.calls[6]?.text).toContain("delivery_state = 'DELIVERED'");
    expect(fake.calls[6]?.text).toContain("lease_expires_at > now()");
    expect(fake.calls[7]?.text).toBe("COMMIT");
    expect(fake.ended()).toBe(true);
  });

  it("returns the prior result for an exact receipt replay", async () => {
    const fake = fakeClient([
      [], [], [{
        dispatch_id: dispatchId, runner_id: "runner-1",
        receipt_id: "receipt-001", receipt_hash: receiptHash,
      }], [],
    ]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.recordReceipt(
      dispatchId, "runner-1", token, "receipt-001", receiptHash,
    )).resolves.toEqual({ status: "DUPLICATE" });
    expect(fake.calls[3]?.text).toBe("COMMIT");
  });

  it("rejects a conflicting receipt for an already receipted dispatch", async () => {
    const fake = fakeClient([
      [], [], [{
        dispatch_id: dispatchId, runner_id: "runner-1",
        receipt_id: "receipt-original", receipt_hash: receiptHash,
      }], [],
    ]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.recordReceipt(
      dispatchId, "runner-1", token, "receipt-other", receiptHash,
    )).rejects.toBeInstanceOf(RunnerDispatchReceiptConflictError);
    expect(fake.calls[3]?.text).toBe("ROLLBACK");
  });

  it("rejects stale workers before writing a receipt", async () => {
    const fake = fakeClient([[], [], [], [], []]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.recordReceipt(
      dispatchId, "runner-old", token, "receipt-old", receiptHash,
    )).rejects.toBeInstanceOf(StaleRunnerDispatchLeaseError);
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO runner_dispatch_receipts"))).toBe(false);
  });

  it("releases a failed dispatch for caller-selected retry time", async () => {
    const fake = fakeClient([[], [{ id: dispatchId }]]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    const at = new Date("2026-11-09T12:05:00Z");
    await expect(repository.releaseForRetry(dispatchId, "dispatcher-1", token, at)).resolves.toBe(true);
    expect(fake.calls[1]?.values).toEqual([dispatchId, "dispatcher-1", token, at.toISOString()]);
  });

  it("dead-letters only the active fenced lease", async () => {
    const fake = fakeClient([[], []]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.markDeadLetter(dispatchId, "dispatcher-1", token)).resolves.toBe(false);
    expect(fake.calls[1]?.text).toContain("delivery_state = 'DEAD_LETTER'");
  });

  it("validates inputs before connecting and fails closed without configuration", async () => {
    const fake = fakeClient();
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.claimBatch("", 1, 30)).rejects.toThrow("invalid_runner_dispatch_worker_id");
    await expect(repository.claimBatch("dispatcher-1", 0, 30)).rejects.toThrow("invalid_runner_dispatch_batch_size");
    await expect(repository.claimBatch("dispatcher-1", 1, 0)).rejects.toThrow("invalid_runner_dispatch_lease_duration");
    await expect(repository.recordReceipt("bad-id", "dispatcher-1", token, "receipt-1", receiptHash))
      .rejects.toThrow("invalid_runner_dispatch_id");
    await expect(repository.recordReceipt(dispatchId, "dispatcher-1", token, "bad receipt", receiptHash))
      .rejects.toThrow("invalid_runner_dispatch_receipt_id");
    await expect(repository.recordReceipt(dispatchId, "dispatcher-1", token, "receipt-1", "bad-hash"))
      .rejects.toThrow("invalid_runner_dispatch_receipt_hash");
    expect(fake.calls).toHaveLength(0);
    const unconfigured = new PostgresRunnerDispatchLeaseRepository(undefined);
    await expect(unconfigured.claimBatch("dispatcher-1", 1, 30)).rejects.toThrow("database_unavailable");
  });
});
