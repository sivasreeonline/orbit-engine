import { describe, expect, it } from "vitest";
import { DatabaseUnavailableError } from "./database-errors";
import {
  ExecutionSourceComparisonConflictError,
  ExecutionSourceComparisonLimitError,
  ExecutionSourceComparisonNotFoundError,
  PostgresExecutionSourceComparisonRepository,
} from "./execution-source-comparison-repository";
import {
  ExecutionSourceSnapshotIntegrityError,
  ExecutionSourceSnapshotUnavailableError,
} from "./execution-source-snapshot-repository";

const tenantId = "30000000-0000-4000-8000-000000000001";
const actorUserId = "20000000-0000-4000-8000-000000000001";
const baseAttemptId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1";
const targetAttemptId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2";
const baseBytes = new TextEncoder().encode("class Main {}\n");
const targetBytes = new TextEncoder().encode("class Main { int n; }\n");

async function digest(bytes: Uint8Array): Promise<string> {
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function comparisonRow(overrides: Record<string, unknown> = {}) {
  return {
    base_attempt_id: baseAttemptId,
    base_problem_id: "10000000-0000-4000-8000-000000000001",
    base_problem_version_id: "11000000-0000-4000-8000-000000000001",
    base_language: "java",
    base_runtime_version: "25",
    base_attempt_sha256: await digest(baseBytes),
    base_sha256: await digest(baseBytes),
    base_byte_length: baseBytes.byteLength,
    base_storage_kind: "DATABASE",
    base_source_bytes: baseBytes,
    target_attempt_id: targetAttemptId,
    target_problem_id: "10000000-0000-4000-8000-000000000001",
    target_problem_version_id: "11000000-0000-4000-8000-000000000001",
    target_language: "java",
    target_runtime_version: "25",
    target_attempt_sha256: await digest(targetBytes),
    target_sha256: await digest(targetBytes),
    target_byte_length: targetBytes.byteLength,
    target_storage_kind: "DATABASE",
    target_source_bytes: targetBytes,
    ...overrides,
  };
}

function fakeClient(rows: Record<string, unknown>[] = [], fail = false) {
  const calls: Array<{ text: string; values: unknown[] | undefined }> = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (fail && text.includes("FROM execution_attempts")) throw new Error("private database error");
      return { rows: rows as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";

const mismatches: Array<[string, Record<string, unknown>]> = [
  ["different problem", { target_problem_id: "10000000-0000-4000-8000-000000000002" }],
  ["different problem version", { target_problem_version_id: "11000000-0000-4000-8000-000000000002" }],
  ["different language", { target_language: "python" }],
  ["different runtime", { target_runtime_version: "3.14" }],
];

describe("PostgresExecutionSourceComparisonRepository", () => {
  it("returns both verified snapshots using one owner-scoped query", async () => {
    const row = await comparisonRow();
    const fake = fakeClient([row]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    const result = await repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    );

    expect(result.base.sourceCode).toBe("class Main {}\n");
    expect(result.target.sourceCode).toBe("class Main { int n; }\n");
    const query = fake.calls.find((call) => call.text.includes("FROM execution_attempts"));
    expect(query?.values).toEqual([baseAttemptId, targetAttemptId, tenantId, actorUserId, 128 * 1024]);
    expect(query?.text).toContain("b.tenant_id = $3::uuid");
    expect(query?.text).toContain("b.actor_user_id = $4::uuid");
    expect(query?.text).toContain("t.tenant_id = $3::uuid");
    expect(query?.text).toContain("t.actor_user_id = $4::uuid");
    expect(query?.text).toContain("bs.tenant_id = $3::uuid");
    expect(query?.text).toContain("ts.actor_user_id = $4::uuid");
    expect(query?.text).toContain("CASE WHEN bs.byte_length <= $5 THEN bs.source_bytes ELSE NULL END");
    expect(fake.ended()).toBe(true);
  });

  it("returns a non-disclosing not-found result if either attempt is missing or outside owner scope", async () => {
    const fake = fakeClient([]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceComparisonNotFoundError);
  });

  it.each([
    ["different problem", { target_problem_id: "10000000-0000-4000-8000-000000000002" }],
    ["different problem version", { target_problem_version_id: "11000000-0000-4000-8000-000000000002" }],
    ["different language", { target_language: "python" }],
    ["different runtime", { target_runtime_version: "3.14" }],
  ])("rejects comparison with %s", async (_label, override) => {
    const fake = fakeClient([await comparisonRow(override)]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceComparisonConflictError);
  });

  it("fails closed when either snapshot is stored in R2 without a private reader", async () => {
    const fake = fakeClient([await comparisonRow({
      target_storage_kind: "R2",
      target_source_bytes: null,
    })]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceSnapshotUnavailableError);
  });

  it("does not materialize source bytes above the database-side comparison cap", async () => {
    const fake = fakeClient([await comparisonRow({
      base_byte_length: 128 * 1024 + 1,
      base_source_bytes: null,
    })]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceComparisonLimitError);
  });

  it("rejects corrupted source bytes", async () => {
    const fake = fakeClient([await comparisonRow({ base_byte_length: baseBytes.byteLength + 1 })]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceSnapshotIntegrityError);
  });

  it("rejects disagreement between attempt metadata and snapshot digest", async () => {
    const fake = fakeClient([await comparisonRow({
      base_attempt_sha256: "c".repeat(64),
    })]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceSnapshotIntegrityError);
  });

  it("maps database failures to a generic retryable error", async () => {
    const fake = fakeClient([], true);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, targetAttemptId,
    )).rejects.toBeInstanceOf(DatabaseUnavailableError);
    expect(fake.ended()).toBe(true);
  });

  it("rejects identical attempt IDs before database access", async () => {
    const fake = fakeClient([]);
    const repository = new PostgresExecutionSourceComparisonRepository(connection, () => fake.client);

    await expect(repository.getComparableAttemptSources(
      tenantId, actorUserId, baseAttemptId, baseAttemptId,
    )).rejects.toThrow("invalid_execution_source_comparison_scope");
    expect(fake.calls).toEqual([]);
  });
});
