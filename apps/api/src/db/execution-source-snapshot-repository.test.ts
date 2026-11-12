import { describe, expect, it } from "vitest";
import { DatabaseUnavailableError } from "./database-errors";
import {
  ExecutionSourceSnapshotIntegrityError,
  ExecutionSourceSnapshotNotFoundError,
  ExecutionSourceSnapshotUnavailableError,
  PostgresExecutionSourceSnapshotRepository,
} from "./execution-source-snapshot-repository";

interface QueryCall {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

const tenantId = "30000000-0000-4000-8000-000000000001";
const actorUserId = "20000000-0000-4000-8000-000000000001";
const attemptId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1";
const sourceCode = "public class Main { }";
const sourceBytes = new TextEncoder().encode(sourceCode);

async function digest(value: Uint8Array): Promise<string> {
  const result = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(result), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fakeClient(row: Record<string, unknown>[] = [], fail = false) {
  const calls: QueryCall[] = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (fail && text.includes("FROM execution_attempts")) throw new Error("sensitive database detail");
      return { rows: row as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";

describe("PostgresExecutionSourceSnapshotRepository", () => {
  it("returns exact source only when tenant and actor own the attempt", async () => {
    const hash = await digest(sourceBytes);
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: hash,
      byte_length: sourceBytes.byteLength,
      storage_kind: "DATABASE",
      source_bytes: sourceBytes,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    const result = await repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId);

    expect(result).toEqual({
      attemptId,
      sourceSha256: hash,
      sourceByteLength: String(sourceBytes.byteLength),
      sourceCode,
    });
    const query = fake.calls.find((call) => call.text.includes("FROM execution_attempts"));
    expect(query?.values).toEqual([attemptId, tenantId, actorUserId]);
    expect(query?.text).toContain("ea.tenant_id = $2::uuid");
    expect(query?.text).toContain("ea.actor_user_id = $3::uuid");
    expect(fake.ended()).toBe(true);
  });

  it("returns the same source snapshot byte-for-byte, including line endings and Unicode", async () => {
    const exactSource = "class Main {\r\n  // café\n}\r\n";
    const bytes = new TextEncoder().encode(exactSource);
    const hash = await digest(bytes);
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: hash,
      byte_length: String(bytes.byteLength),
      storage_kind: "DATABASE",
      source_bytes: bytes,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    const result = await repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId);

    expect(result.sourceCode).toBe(exactSource);
    expect(result.sourceSha256).toBe(hash);
  });

  it("does not reveal whether an attempt exists outside the authenticated owner scope", async () => {
    const fake = fakeClient([]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(ExecutionSourceSnapshotNotFoundError);
  });

  it("fails closed when the snapshot is stored in R2 but private object retrieval is not configured", async () => {
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: "a".repeat(64),
      byte_length: 20,
      storage_kind: "R2",
      source_bytes: null,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(ExecutionSourceSnapshotUnavailableError);
  });

  it("rejects corrupted source bytes whose length does not match the immutable metadata", async () => {
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: "a".repeat(64),
      byte_length: sourceBytes.byteLength + 1,
      storage_kind: "DATABASE",
      source_bytes: sourceBytes,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(ExecutionSourceSnapshotIntegrityError);
  });

  it("rejects source bytes whose digest does not match the recorded hash", async () => {
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: "a".repeat(64),
      byte_length: sourceBytes.byteLength,
      storage_kind: "DATABASE",
      source_bytes: sourceBytes,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(ExecutionSourceSnapshotIntegrityError);
  });

  it("rejects invalid UTF-8 rather than silently replacing source characters", async () => {
    const invalidBytes = new Uint8Array([0xc3, 0x28]);
    const hash = await digest(invalidBytes);
    const fake = fakeClient([{
      attempt_id: attemptId,
      sha256: hash,
      byte_length: invalidBytes.byteLength,
      storage_kind: "DATABASE",
      source_bytes: invalidBytes,
    }]);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(ExecutionSourceSnapshotIntegrityError);
  });

  it("maps database failures to a generic retryable service error", async () => {
    const fake = fakeClient([], true);
    const repository = new PostgresExecutionSourceSnapshotRepository(connection, () => fake.client);

    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(DatabaseUnavailableError);
    expect(fake.ended()).toBe(true);
  });

  it("fails closed when no database connection is configured", async () => {
    const repository = new PostgresExecutionSourceSnapshotRepository(undefined);
    await expect(repository.getAttemptSourceSnapshot(tenantId, actorUserId, attemptId))
      .rejects.toBeInstanceOf(DatabaseUnavailableError);
  });
});
