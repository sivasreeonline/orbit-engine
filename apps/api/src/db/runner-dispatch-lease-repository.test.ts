import { describe, expect, it } from "vitest";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";

interface Call { readonly text: string; readonly values: unknown[] | undefined; }
function fakeClient(rows: Record<string, unknown>[] = []) {
  const calls: Call[] = [];
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
const dispatchId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const attemptId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const token = "dddddddd-dddd-4ddd-8ddd-ddddddddddd1";

describe("PostgresRunnerDispatchLeaseRepository", () => {
  it("claims bounded pending work with SKIP LOCKED and a fresh fencing token", async () => {
    const fake = fakeClient([{
      id: dispatchId, execution_id: executionId, attempt_id: attemptId,
      protocol_version: "v1", correlation_id: "corr-1", delivery_attempts: 1,
      lease_token: token, lease_expires_at: new Date("2026-11-09T12:00:00Z"),
    }]);
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

  it("claims at most one job per student lane using durable least-served tickets", async () => {
    const fake = fakeClient([{
      id: dispatchId, execution_id: executionId, attempt_id: attemptId,
      protocol_version: "v1", correlation_id: "corr-1", delivery_attempts: 2,
      lease_token: token, lease_expires_at: new Date("2026-11-13T12:00:00Z"),
    }]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);

    await expect(repository.claimFairBatch("fair-dispatcher-1", 20, 45)).resolves.toEqual([{
      id: dispatchId, executionId, attemptId, protocolVersion: "v1",
      correlationId: "corr-1", deliveryAttempts: 2, leaseToken: token,
      leaseExpiresAt: "2026-11-13T12:00:00.000Z",
    }]);

    const claim = fake.calls[3];
    expect(claim?.text).toContain("FOR UPDATE OF lane SKIP LOCKED");
    expect(claim?.text).toContain("DISTINCT ON (owner_attempt.tenant_id, owner_attempt.actor_user_id)");
    expect(claim?.text).toContain("ORDER BY lane.last_served_ticket");
    expect(claim?.text).toContain("nextval('runner_dispatch_scheduler_ticket_seq')");
    expect(claim?.values).toEqual([20, "fair-dispatcher-1", 45]);
    expect(fake.ended()).toBe(true);
  });

  it("claims execution and dispatch leases atomically and appends JOB_CLAIMED evidence", async () => {
    const calls: Call[] = [];
    let ended = false;
    const runnerId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1";
    const client = {
      async connect() {},
      async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
        calls.push({ text, values });
        if (text.includes("SELECT count(*)::integer AS active_count")) {
          return { rows: [{ active_count: 0 }] as unknown as T[] };
        }
        if (text.includes("SELECT lane.tenant_id, lane.actor_user_id")) {
          return { rows: [{
            tenant_id: "30000000-0000-4000-8000-000000000001",
            actor_user_id: "20000000-0000-4000-8000-000000000001",
          }] as unknown as T[] };
        }
        if (text.includes("previous_job_state")) {
          return { rows: [{
            dispatch_id: dispatchId,
            execution_id: executionId,
            attempt_id: attemptId,
            protocol_version: "v1",
            correlation_id: "corr-runner",
            delivery_attempts: 0,
            previous_job_state: "QUEUED",
            previous_lease_token: null,
            previous_lease_owner: null,
            previous_lease_expires_at: null,
            previous_retry_count: 0,
            previous_key_id: null,
            previous_start_event_id: null,
          }] as unknown as T[] };
        }
        if (text.includes("UPDATE runner_dispatch_outbox") && text.includes("RETURNING id, execution_id")) {
          return { rows: [{
            id: dispatchId,
            execution_id: executionId,
            attempt_id: attemptId,
            protocol_version: "v1",
            correlation_id: "corr-runner",
            delivery_attempts: 1,
            lease_token: token,
            lease_expires_at: new Date("2026-11-13T12:02:00Z"),
          }] as unknown as T[] };
        }
        if (text.includes("UPDATE execution_jobs") && text.includes("RETURNING id, retry_count")) {
          return { rows: [{ id: executionId, retry_count: 0 }] as unknown as T[] };
        }
        if (text.includes("INSERT INTO execution_evidence_events")) {
          return { rows: [{ event_id: "f0000000-0000-4000-8000-000000000001" }] as unknown as T[] };
        }
        if (text.includes("UPDATE runner_dispatch_scheduler_lanes")) {
          return { rows: [{ id: "30000000-0000-4000-8000-000000000001" }] as unknown as T[] };
        }
        return { rows: [] as T[] };
      },
      async end() { ended = true; },
    };
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => client);

    await expect(repository.claimFairBatchForRunner(runnerId, 4, 2, 120)).resolves.toEqual([{
      id: dispatchId, executionId, attemptId, protocolVersion: "v1",
      correlationId: "corr-runner", deliveryAttempts: 1, leaseToken: token,
      leaseExpiresAt: "2026-11-13T12:02:00.000Z",
    }]);

    expect(calls[1]?.text).toBe("BEGIN");
    expect(calls[2]?.text).toContain("pg_advisory_xact_lock");
    expect(calls.some((call) => call.text.includes("active_count"))).toBe(true);
    expect(calls.some((call) => call.text.includes("FOR UPDATE OF lane SKIP LOCKED"))).toBe(true);
    expect(calls.some((call) => call.text.includes("FOR UPDATE OF dispatch, job SKIP LOCKED"))).toBe(true);
    expect(calls.some((call) => call.text.includes("retry_count = retry_count + CASE WHEN $3 = 'RUNNING' THEN 1 ELSE 0 END"))).toBe(true);
    expect(calls.some((call) => call.text.includes("'JOB_CLAIMED', 'RUNNER'"))).toBe(true);
    expect(calls.some((call) => call.text.includes("INSERT INTO execution_evidence_events"))).toBe(true);
    expect(calls.some((call) => call.text.includes("INSERT INTO runner_dispatch_lease_recoveries"))).toBe(false);
    expect(calls.some((call) => call.text === "COMMIT")).toBe(true);
    expect(ended).toBe(true);
  });

  it("marks delivered only with the active unexpired fencing token", async () => {
    const fake = fakeClient([{ id: dispatchId }]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    await expect(repository.markDelivered(dispatchId, "dispatcher-1", token)).resolves.toBe(true);
    expect(fake.calls[1]?.text).toContain("delivery_state = 'DELIVERED'");
    expect(fake.calls[1]?.text).toContain("lease_expires_at > now()");
    expect(fake.calls[1]?.text).toContain("lease_token = $3::uuid");
  });

  it("releases a failed dispatch for caller-selected retry time", async () => {
    const fake = fakeClient([{ id: dispatchId }]);
    const repository = new PostgresRunnerDispatchLeaseRepository(connection, () => fake.client);
    const at = new Date("2026-11-09T12:05:00Z");
    await expect(repository.releaseForRetry(dispatchId, "dispatcher-1", token, at)).resolves.toBe(true);
    expect(fake.calls[1]?.values).toEqual([dispatchId, "dispatcher-1", token, at.toISOString()]);
  });

  it("dead-letters only the active fenced lease", async () => {
    const fake = fakeClient([]);
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
    await expect(repository.markDelivered("bad-id", "dispatcher-1", token)).rejects.toThrow("invalid_runner_dispatch_id");
    expect(fake.calls).toHaveLength(0);
    const unconfigured = new PostgresRunnerDispatchLeaseRepository(undefined);
    await expect(unconfigured.claimBatch("dispatcher-1", 1, 30)).rejects.toThrow("database_unavailable");
  });
});
