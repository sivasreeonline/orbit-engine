import { describe, expect, it } from "vitest";
import {
  ExecutionIntakeDatabaseError,
  PostgresExecutionIntakeRepository,
} from "./execution-intake-repository";

const tenantId = "30000000-0000-4000-8000-000000000001";
const userId = "20000000-0000-4000-8000-000000000001";
const connectionString = "postgres://test-user:test-password@localhost/test";
const requestHash = "b".repeat(64);
const attemptId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1";
const executionId = "ffffffff-ffff-4fff-8fff-fffffffffff1";

function command(overrides: Record<string, unknown> = {}) {
  return {
    principal: { tenantId, userId },
    endpoint: "RUN" as const,
    idempotencyKey: "test-idempotency-key",
    requestHash,
    problemId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
    problemVersionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
    language: "java" as const,
    runtimeVersion: "25",
    sourceBytes: new TextEncoder().encode("public class Main {}"),
    correlationId: "test-correlation-id",
    ...overrides,
  };
}

function fakeClient(options: {
  conflict?: boolean;
  existingHash?: string;
  failOnOutbox?: boolean;
} = {}) {
  const calls: Array<{ sql: string; values?: unknown[] }> = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(sql: string, values?: unknown[]) {
      calls.push({ sql, values });
      if (options.failOnOutbox && sql.includes("INSERT INTO execution_outbox")) {
        throw new Error("private driver details");
      }
      if (sql.includes("INSERT INTO source_snapshots")) return { rows: [{ id: "dddddddd-dddd-4ddd-8ddd-ddddddddddd1" }] as T[] };
      if (sql.includes("INSERT INTO execution_attempts")) return { rows: [{ id: attemptId }] as T[] };
      if (sql.includes("INSERT INTO execution_jobs")) return { rows: [{ id: executionId }] as T[] };
      if (sql.includes("INSERT INTO execution_idempotency")) {
        return { rows: options.conflict ? [] : [{ id: "idempotency-row" }] as T[] };
      }
      if (sql.includes("SELECT i.request_sha256")) {
        return {
          rows: [{
            request_sha256: options.existingHash ?? requestHash,
            attempt_id: attemptId,
            execution_id: executionId,
          }] as T[],
        };
      }
      return { rows: [] as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, isEnded: () => ended };
}

describe("PostgresExecutionIntakeRepository prototype", () => {
  it("creates snapshot, attempt, job, idempotency reservation and outbox in one transaction", async () => {
    const fake = fakeClient();
    const repository = new PostgresExecutionIntakeRepository(
      { HYPERDRIVE: { connectionString } },
      () => fake.client,
    );

    const result = await repository.create(command());

    expect(result).toEqual({ kind: "CREATED", executionId, attemptId });
    expect(fake.calls[0]?.sql).toBe("SET statement_timeout = '5s'");
    expect(fake.calls[1]?.sql).toBe("BEGIN");
    expect(fake.calls.some((call) => call.sql === "COMMIT")).toBe(true);
    expect(fake.calls.some((call) => call.sql === "ROLLBACK")).toBe(false);
    expect(fake.calls.some((call) => call.sql.includes("INSERT INTO execution_outbox"))).toBe(true);
    expect(fake.isEnded()).toBe(true);
    const outbox = fake.calls.find((call) => call.sql.includes("INSERT INTO execution_outbox"));
    expect(String(outbox?.values?.[2])).not.toMatch(/source|hiddenTests|expectedOutput/i);
  });

  it("rolls back speculative rows and replays the original IDs for the same key and hash", async () => {
    const fake = fakeClient({ conflict: true, existingHash: requestHash });
    const repository = new PostgresExecutionIntakeRepository(
      { HYPERDRIVE: { connectionString } },
      () => fake.client,
    );

    const result = await repository.create(command());

    expect(result).toEqual({ kind: "REPLAYED", executionId, attemptId });
    expect(fake.calls.some((call) => call.sql === "ROLLBACK")).toBe(true);
    expect(fake.calls.some((call) => call.sql === "COMMIT")).toBe(false);
    expect(fake.calls.some((call) => call.sql.includes("INSERT INTO execution_outbox"))).toBe(false);
    expect(fake.isEnded()).toBe(true);
  });

  it("rejects reuse of a key with a different semantic request hash", async () => {
    const fake = fakeClient({ conflict: true, existingHash: "c".repeat(64) });
    const repository = new PostgresExecutionIntakeRepository(
      { HYPERDRIVE: { connectionString } },
      () => fake.client,
    );

    await expect(repository.create(command())).resolves.toEqual({ kind: "IDEMPOTENCY_CONFLICT" });
    expect(fake.calls.some((call) => call.sql === "ROLLBACK")).toBe(true);
  });

  it("rolls back all writes if outbox insertion fails and exposes no driver details", async () => {
    const fake = fakeClient({ failOnOutbox: true });
    const repository = new PostgresExecutionIntakeRepository(
      { HYPERDRIVE: { connectionString } },
      () => fake.client,
    );

    await expect(repository.create(command())).rejects.toBeInstanceOf(ExecutionIntakeDatabaseError);
    expect(fake.calls.some((call) => call.sql === "ROLLBACK")).toBe(true);
    expect(fake.isEnded()).toBe(true);
  });

  it("fails closed when the database binding is missing", async () => {
    const repository = new PostgresExecutionIntakeRepository({});
    await expect(repository.create(command())).rejects.toBeInstanceOf(ExecutionIntakeDatabaseError);
  });

  it("rejects invalid request hashes and oversized source snapshots before connecting", async () => {
    const fake = fakeClient();
    const repository = new PostgresExecutionIntakeRepository(
      { HYPERDRIVE: { connectionString } },
      () => fake.client,
    );

    await expect(repository.create(command({ requestHash: "not-a-hash" }))).rejects.toBeInstanceOf(TypeError);
    await expect(repository.create(command({ sourceBytes: new Uint8Array(1_048_577) }))).rejects.toBeInstanceOf(TypeError);
    expect(fake.calls).toHaveLength(0);
  });
});
