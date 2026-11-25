import { describe, expect, it } from "vitest";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import {
  ExecutionProblemNotFoundError,
  ExecutionTestBundleIntegrityError,
  IdempotencyConflictError,
  PostgresExecutionIntakeRepository,
} from "./execution-intake-repository";

interface QueryCall {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

function fakeClient(options: {
  readonly existing?: Record<string, unknown>[];
  readonly problem?: Record<string, unknown>[];
  readonly failAt?: string;
  readonly emptyTestCases?: boolean;
} = {}) {
  const calls: QueryCall[] = [];
  let ended = false;
  let rolledBack = false;
  let committed = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (text === "ROLLBACK") rolledBack = true;
      if (text === "COMMIT") committed = true;
      if (options.failAt && text.includes(options.failAt)) {
        throw new Error("sensitive database failure");
      }
      if (text.includes("FROM execution_idempotency AS ei")) {
        return { rows: (options.existing ?? []) as unknown as T[] };
      }
      if (text.includes("FROM problem_test_cases")) {
        const action = values?.[1];
        const publicCase = {
          id: "case-public",
          sequence: 1,
          visibility: "PUBLIC",
          input_data: new TextEncoder().encode("1 2"),
          expected_output: new TextEncoder().encode("3\n"),
        };
        const hiddenCase = {
          id: "case-hidden",
          sequence: 2,
          visibility: "HIDDEN",
          input_data: new TextEncoder().encode("4 5"),
          expected_output: new TextEncoder().encode("9\n"),
        };
        return { rows: (options.emptyTestCases ? [] : action === "SUBMIT" ? [publicCase, hiddenCase] : [publicCase]) as unknown as T[] };
      }
      if (text.includes("FROM problems AS p")) {
        return { rows: (options.problem ?? [{
          problem_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
          problem_version_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
        }]) as unknown as T[] };
      }
      if (text.includes("INSERT INTO source_snapshots")) {
        return { rows: [{ id: "cccccccc-cccc-4ccc-8ccc-ccccccccccc1" }] as unknown as T[] };
      }
      if (text.includes("INSERT INTO execution_attempts")) {
        return { rows: [{ id: "dddddddd-dddd-4ddd-8ddd-ddddddddddd1" }] as unknown as T[] };
      }
      if (text.includes("INSERT INTO execution_jobs")) {
        return { rows: [{ id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1" }] as unknown as T[] };
      }
      return { rows: [] as unknown as T[] };
    },
    async end() { ended = true; },
  };
  return {
    client,
    calls,
    ended: () => ended,
    rolledBack: () => rolledBack,
    committed: () => committed,
  };
}

const input = {
  principal: {
    tenantId: "30000000-0000-4000-8000-000000000001",
    userId: "20000000-0000-4000-8000-000000000001",
    roles: ["STUDENT"],
  },
  action: "RUN" as const,
  problemSlug: "two-sum",
  language: "java" as const,
  runtimeVersion: "25",
  sourceCode: "public class Main {}",
  correlationId: "corr-test-001",
};
const key = "idempotency-key-001";
const v2Policy: ExecutionProtocolV2Policy = {
  policyRevision: "skyhigh-v2-policy-test",
  runtimeImageDigests: {
    java: `sha256:${"a".repeat(64)}`,
    python: `sha256:${"b".repeat(64)}`,
  },
  limits: {
    cpuQuotaMillis: 2000,
    memoryBytes: 536870912,
    wallTimeMillis: 10000,
    processLimit: 32,
    outputBytes: 1048576,
    scratchBytes: 268435456,
    scratchInodes: 4096,
  },
};
const connection = "postgres://test-user:test-password@localhost/test";

describe("PostgresExecutionIntakeRepository", () => {
  it("persists exact v2 request bytes atomically and records a v2-only outbox discriminator", async () => {
    const fake = fakeClient();
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client, v2Policy);
    const result = await repository.create(input, key);
    const requestInsert = fake.calls.find((call) => call.text.includes("INSERT INTO execution_protocol_requests"));
    expect(requestInsert).toBeDefined();
    const requestBytes = requestInsert?.values?.[7] as Uint8Array;
    const request = JSON.parse(new TextDecoder().decode(requestBytes)) as Record<string, unknown>;
    expect(request).toMatchObject({
      protocolVersion: "v2",
      executionId: result.executionId,
      attemptId: result.attemptId,
      problemVersionId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      sourceArtifactId: "cccccccc-cccc-4ccc-8ccc-ccccccccccc1",
      testBundleId: result.testBundleId,
      sourceSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(requestInsert?.values?.[6]).toMatch(/^[0-9a-f]{64}$/);
    const outbox = fake.calls.find((call) => call.text.includes("INSERT INTO execution_outbox"));
    expect(outbox?.values?.[1]).toBe("v2");
    expect(fake.calls.find((call) => call.text === "COMMIT")).toBeDefined();
    expect(fake.calls.findIndex((call) => call.text.includes("INSERT INTO execution_protocol_requests")))
      .toBeLessThan(fake.calls.findIndex((call) => call.text.includes("INSERT INTO execution_outbox")));
  });

  it("replays the original persisted v2 request without rebuilding from current policy", async () => {
    const first = fakeClient();
    const firstRepository = new PostgresExecutionIntakeRepository(connection, () => first.client, v2Policy);
    const created = await firstRepository.create(input, key);
    const requestInsert = first.calls.find((call) => call.text.includes("INSERT INTO execution_protocol_requests"));
    const requestBytes = requestInsert?.values?.[7] as Uint8Array;
    const requestSha = String(requestInsert?.values?.[6]);
    const requestDocument = JSON.parse(new TextDecoder().decode(requestBytes)) as Record<string, unknown>;
    const idempotencyInsert = first.calls.find((call) => call.text.includes("INSERT INTO execution_idempotency"));
    const replayFake = fakeClient({
      existing: [{
        attempt_id: created.attemptId,
        execution_id: created.executionId,
        request_sha256: String(idempotencyInsert?.values?.[4]),
        problem_version_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
        protocol_version: "v2",
        protocol_request_bytes: requestBytes,
        protocol_request_sha256: requestSha,
        protocol_request_correlation_id: requestDocument.correlationId,
        outbox_correlation_id: requestDocument.correlationId,
      }],
    });
    const replayRepository = new PostgresExecutionIntakeRepository(connection, () => replayFake.client, {
      ...v2Policy,
      policyRevision: "changed-policy-must-not-rebuild",
    });
    const replay = await replayRepository.create(input, key);
    expect(replay).toEqual({ ...created, replayed: true });
    expect(replayFake.calls.some((call) => call.text.includes("INSERT INTO execution_protocol_requests"))).toBe(false);
    expect(replayFake.calls.some((call) => call.text.includes("FROM problem_test_cases"))).toBe(false);
    expect(replayFake.committed()).toBe(true);
  });


  it("writes snapshot, attempt, job, outbox and idempotency in one transaction", async () => {
    const fake = fakeClient();
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client);
    const result = await repository.create(input, key);

    expect(result).toEqual({
      executionId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1",
      attemptId: "dddddddd-dddd-4ddd-8ddd-ddddddddddd1",
      testBundleId: expect.stringMatching(/^bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1-run-[0-9a-f]{16}$/),
      replayed: false,
    });
    expect(fake.calls[0]?.text).toBe("SET statement_timeout = '5s'");
    expect(fake.calls.some((call) => call.text === "BEGIN")).toBe(true);
    expect(fake.calls.some((call) => call.text === "COMMIT")).toBe(true);
    expect(fake.rolledBack()).toBe(false);
    expect(fake.ended()).toBe(true);

    const outbox = fake.calls.find((call) => call.text.includes("INSERT INTO execution_outbox"));
    const payload = JSON.parse(String(outbox?.values?.[3])) as Record<string, unknown>;
    expect(payload).toEqual({
      executionId: result.executionId,
      attemptId: result.attemptId,
      protocolVersion: "v1",
    });
    expect(JSON.stringify(payload)).not.toContain(input.sourceCode);
  });

  it("returns the original execution for a matching idempotent replay", async () => {
    // A replay must compare the same hash; derive it through a first deterministic call.
    const first = fakeClient();
    const firstRepository = new PostgresExecutionIntakeRepository(connection, () => first.client);
    const created = await firstRepository.create(input, key);
    const hashCall = first.calls.find((call) => call.text.includes("INSERT INTO execution_idempotency"));
    const expectedHash = String(hashCall?.values?.[4]);
    const replayFake = fakeClient({
      existing: [{
        attempt_id: created.attemptId,
        execution_id: created.executionId,
        request_sha256: expectedHash,
        problem_version_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      }],
    });
    const replayRepository = new PostgresExecutionIntakeRepository(connection, () => replayFake.client);
    const replay = await replayRepository.create(input, key);
    expect(replay).toEqual({ ...created, replayed: true });
    expect(replayFake.calls.some((call) => call.text.includes("INSERT INTO source_snapshots"))).toBe(false);
    expect(replayFake.committed()).toBe(true);
  });

  it("uses PUBLIC cases for RUN and includes HIDDEN cases for SUBMIT", async () => {
    const runFake = fakeClient();
    const runRepository = new PostgresExecutionIntakeRepository(connection, () => runFake.client);
    const run = await runRepository.create(input, key);

    const submitFake = fakeClient();
    const submitRepository = new PostgresExecutionIntakeRepository(connection, () => submitFake.client);
    const submit = await submitRepository.create({ ...input, action: "SUBMIT" }, key);

    const runQuery = runFake.calls.find((call) => call.text.includes("FROM problem_test_cases"));
    const submitQuery = submitFake.calls.find((call) => call.text.includes("FROM problem_test_cases"));
    expect(runQuery?.values?.[1]).toBe("RUN");
    expect(submitQuery?.values?.[1]).toBe("SUBMIT");
    expect(run.testBundleId).toMatch(/-run-[0-9a-f]{16}$/);
    expect(submit.testBundleId).toMatch(/-submit-[0-9a-f]{16}$/);
    expect(submit.testBundleId).not.toBe(run.testBundleId);
  });

  it("fails closed when a published problem has no valid test bundle", async () => {
    const fake = fakeClient({ emptyTestCases: true });
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client);
    await expect(repository.create(input, key)).rejects.toBeInstanceOf(ExecutionTestBundleIntegrityError);
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO source_snapshots"))).toBe(false);
    expect(fake.rolledBack()).toBe(true);
  });

  it("rejects reuse of an idempotency key for a different request and rolls back", async () => {
    const fake = fakeClient({
      existing: [{
        attempt_id: "dddddddd-dddd-4ddd-8ddd-ddddddddddd1",
        execution_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1",
        request_sha256: "0".repeat(64),
        problem_version_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
      }],
    });
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client);
    await expect(repository.create(input, key)).rejects.toBeInstanceOf(IdempotencyConflictError);
    expect(fake.rolledBack()).toBe(true);
    expect(fake.committed()).toBe(false);
    expect(fake.ended()).toBe(true);
  });

  it("rolls back every partial write when a later insert fails", async () => {
    const fake = fakeClient({ failAt: "INSERT INTO execution_outbox" });
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client);
    await expect(repository.create(input, key)).rejects.toThrow("database_unavailable");
    expect(fake.rolledBack()).toBe(true);
    expect(fake.committed()).toBe(false);
    expect(fake.ended()).toBe(true);
  });

  it("does not create source evidence for an unpublished or out-of-scope problem", async () => {
    const fake = fakeClient({ problem: [] });
    const repository = new PostgresExecutionIntakeRepository(connection, () => fake.client);
    await expect(repository.create(input, key)).rejects.toBeInstanceOf(ExecutionProblemNotFoundError);
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO source_snapshots"))).toBe(false);
    expect(fake.rolledBack()).toBe(true);
  });

  it("fails closed without a database connection", async () => {
    const repository = new PostgresExecutionIntakeRepository(undefined);
    await expect(repository.create(input, key)).rejects.toThrow("database_unavailable");
  });
});
