import { describe, expect, it } from "vitest";
import { PostgresExecutionJobRepository } from "./execution-job-repository";

interface QueryCall {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

function fakeClient(options: {
  readonly claimed?: Record<string, unknown>[];
  readonly existing?: Record<string, unknown>[];
  readonly updated?: Record<string, unknown>[];
} = {}) {
  const calls: QueryCall[] = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (text.includes("UPDATE execution_jobs") && text.includes("RETURNING id, attempt_id")) {
        return { rows: (options.claimed ?? []) as unknown as T[] };
      }
      if (text.includes("SELECT state")) {
        return { rows: (options.existing ?? []) as unknown as T[] };
      }
      return { rows: (options.updated ?? []) as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";
const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const attemptId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const leaseToken = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";

describe("PostgresExecutionJobRepository", () => {
  it("claims a queued job and returns its fencing token", async () => {
    const fake = fakeClient({
      claimed: [{
        id: executionId,
        attempt_id: attemptId,
        state_version: 2,
        retry_count: 0,
        lease_owner: "consumer-1",
        lease_token: leaseToken,
        lease_expires_at: new Date("2026-11-09T12:00:00.000Z"),
      }],
    });
    const repository = new PostgresExecutionJobRepository(connection, () => fake.client);

    const result = await repository.claim(executionId, "consumer-1", 60);

    expect(result).toEqual({
      status: "CLAIMED",
      lease: {
        executionId,
        attemptId,
        stateVersion: "2",
        retryCount: 0,
        leaseOwner: "consumer-1",
        leaseToken,
        leaseExpiresAt: "2026-11-09T12:00:00.000Z",
      },
    });
    expect(fake.calls[1]?.text).toContain("state = 'QUEUED' AND available_at <= now()");
    expect(fake.calls[1]?.text).toContain("state = 'CLAIMED' AND lease_expires_at <= now()");
    expect(fake.ended()).toBe(true);
  });

  it("reports duplicate delivery when a valid claim is already active", async () => {
    const fake = fakeClient({ existing: [{
      state: "CLAIMED",
      active_lease: true,
      not_yet_available: false,
    }] });
    const repository = new PostgresExecutionJobRepository(connection, () => fake.client);

    await expect(repository.claim(executionId, "consumer-2", 60))
      .resolves.toEqual({ status: "ALREADY_CLAIMED" });
  });

  it("distinguishes missing, delayed and terminal jobs", async () => {
    const missing = fakeClient();
    const missingRepository = new PostgresExecutionJobRepository(connection, () => missing.client);
    await expect(missingRepository.claim(executionId, "consumer-1", 60))
      .resolves.toEqual({ status: "NOT_FOUND" });

    const delayed = fakeClient({ existing: [{
      state: "QUEUED",
      active_lease: false,
      not_yet_available: true,
    }] });
    const delayedRepository = new PostgresExecutionJobRepository(connection, () => delayed.client);
    await expect(delayedRepository.claim(executionId, "consumer-1", 60))
      .resolves.toEqual({ status: "NOT_READY" });

    const terminal = fakeClient({ existing: [{
      state: "COMPLETED",
      active_lease: false,
      not_yet_available: false,
    }] });
    const terminalRepository = new PostgresExecutionJobRepository(connection, () => terminal.client);
    await expect(terminalRepository.claim(executionId, "consumer-1", 60))
      .resolves.toEqual({ status: "NOT_CLAIMABLE", state: "COMPLETED" });
  });

  it("marks running only with the current unexpired lease", async () => {
    const fake = fakeClient({ updated: [{ id: executionId }] });
    const repository = new PostgresExecutionJobRepository(connection, () => fake.client);

    await expect(repository.markRunning(executionId, "consumer-1", leaseToken))
      .resolves.toBe(true);

    expect(fake.calls[1]?.text).toContain("state = 'RUNNING'");
    expect(fake.calls[1]?.text).toContain("lease_owner = $2 AND lease_token = $3::uuid");
    expect(fake.calls[1]?.text).toContain("lease_expires_at > now()");
  });

  it("rejects stale lease tokens", async () => {
    const fake = fakeClient({ updated: [] });
    const repository = new PostgresExecutionJobRepository(connection, () => fake.client);

    await expect(repository.markRunning(executionId, "old-consumer", leaseToken))
      .resolves.toBe(false);
  });

  it("validates claim inputs and fails closed without database configuration", async () => {
    const fake = fakeClient();
    const repository = new PostgresExecutionJobRepository(connection, () => fake.client);

    await expect(repository.claim("bad-id", "consumer-1", 60)).rejects.toThrow("invalid_execution_id");
    await expect(repository.claim(executionId, "", 60)).rejects.toThrow("invalid_execution_worker_id");
    await expect(repository.claim(executionId, "consumer-1", 0)).rejects.toThrow("invalid_execution_lease_duration");
    expect(fake.calls).toHaveLength(0);

    const unconfigured = new PostgresExecutionJobRepository(undefined);
    await expect(unconfigured.claim(executionId, "consumer-1", 60))
      .rejects.toThrow("database_unavailable");
  });
});
