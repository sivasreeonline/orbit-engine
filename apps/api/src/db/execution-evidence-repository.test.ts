import { describe, expect, it } from "vitest";
import { DatabaseUnavailableError } from "./database-errors";
import {
  ExecutionEvidenceConflictError,
  PostgresExecutionEvidenceRepository,
  StaleExecutionLeaseError,
} from "./execution-evidence-repository";

const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const attemptId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const leaseToken = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
const connection = "postgres://test-user:test-password@localhost/test";

const resultInput = {
  executionId,
  attemptId,
  leaseOwner: "runner-local-1",
  leaseToken,
  infrastructureStatus: "SUCCEEDED" as const,
  compilationStatus: "SUCCEEDED" as const,
  verdict: "ACCEPTED" as const,
  cleanupStatus: "SUCCEEDED" as const,
  testsTotal: 2,
  testsPassed: 2,
  elapsedMs: 42,
  peakMemoryBytes: 1024,
  runnerVersion: "dev-local",
  runtimeImageDigest: "a".repeat(64),
  resultSha256: "b".repeat(64),
  startedAt: "2026-11-12T10:00:00.000Z",
  completedAt: "2026-11-12T10:00:00.042Z",
};

function makeClient(handler: (text: string, values: unknown[] | undefined) => Record<string, unknown>[]) {
  const calls: Array<{ text: string; values: unknown[] | undefined }> = [];
  let connected = false;
  let ended = false;
  const client = {
    async connect() { connected = true; },
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      return { rows: handler(text, values) as T[] };
    },
    async end() { ended = true; },
  };
  return {
    client,
    calls,
    connected: () => connected,
    ended: () => ended,
  };
}

describe("PostgresExecutionEvidenceRepository", () => {
  it("rejects invalid event and result data before opening a database connection", async () => {
    const fake = makeClient(() => []);
    const repository = new PostgresExecutionEvidenceRepository(
      connection,
      () => fake.client,
    );

    await expect(repository.appendEvent({
      eventId: "not-a-uuid",
      executionId,
      attemptId,
      eventType: "RUNNER_STARTED",
      actorKind: "RUNNER",
    })).rejects.toThrow("invalid_execution_evidence_identifier");

    await expect(repository.recordResult({
      ...resultInput,
      testsPassed: 1,
    })).rejects.toThrow("accepted_verdict_requires_all_tests_to_pass");

    await expect(repository.recordResult({
      ...resultInput,
      infrastructureStatus: "FAILED",
      infrastructureErrorCode: "runner unavailable",
      verdict: "NOT_EVALUATED",
    })).rejects.toThrow("invalid_infrastructure_failure_outcome");

    expect(fake.connected()).toBe(false);
    expect(fake.calls).toHaveLength(0);
  });

  it("records a terminal result in the same transaction as the fenced job completion and event", async () => {
    const fake = makeClient((text) => {
      if (text.includes("SELECT id FROM execution_jobs")) return [{ id: executionId }];
      if (text.includes("FROM execution_result_records")) return [];
      if (text.includes("UPDATE execution_jobs")) return [{ id: executionId }];
      if (text.includes("INSERT INTO execution_result_records")) {
        return [{ execution_id: executionId }];
      }
      return [];
    });
    const repository = new PostgresExecutionEvidenceRepository(
      connection,
      () => fake.client,
    );

    const result = await repository.recordResult(resultInput);

    expect(result).toEqual({
      executionId,
      attemptId,
      state: "COMPLETED",
      resultSha256: resultInput.resultSha256,
      replayed: false,
    });
    expect(fake.calls.map((call) => call.text.trim().split("\n")[0])).toEqual([
      "SET statement_timeout = '5s'",
      "BEGIN",
      "SELECT id FROM execution_jobs",
      "SELECT attempt_id, result_sha256",
      "UPDATE execution_jobs",
      "INSERT INTO execution_result_records (",
      "INSERT INTO execution_evidence_events (",
      "COMMIT",
    ]);
    const completion = fake.calls.find((call) => call.text.includes("UPDATE execution_jobs"));
    expect(completion?.text).toContain("lease_token = $5::uuid");
    expect(completion?.text).toContain("lease_expires_at > now()");
    expect(completion?.values).toEqual([
      executionId,
      attemptId,
      "runner-local-1",
      "COMPLETED",
      leaseToken,
    ]);
    expect(fake.ended()).toBe(true);
  });

  it("replays an identical result without requiring the old runner lease again", async () => {
    const fake = makeClient((text) => {
      if (text.includes("SELECT id FROM execution_jobs")) return [{ id: executionId }];
      if (text.includes("FROM execution_result_records")) {
        return [{ attempt_id: attemptId, result_sha256: resultInput.resultSha256 }];
      }
      return [];
    });
    const repository = new PostgresExecutionEvidenceRepository(
      connection,
      () => fake.client,
    );

    const replay = await repository.recordResult(resultInput);

    expect(replay.replayed).toBe(true);
    expect(replay.state).toBe("COMPLETED");
    expect(fake.calls.some((call) => call.text.includes("UPDATE execution_jobs"))).toBe(false);
    expect(fake.calls.at(-1)?.text).toBe("COMMIT");
  });

  it("rejects a conflicting result for an execution that is already finalized", async () => {
    const fake = makeClient((text) => {
      if (text.includes("SELECT id FROM execution_jobs")) return [{ id: executionId }];
      if (text.includes("FROM execution_result_records")) {
        return [{ attempt_id: attemptId, result_sha256: "c".repeat(64) }];
      }
      return [];
    });
    const repository = new PostgresExecutionEvidenceRepository(
      connection,
      () => fake.client,
    );

    await expect(repository.recordResult(resultInput))
      .rejects.toBeInstanceOf(ExecutionEvidenceConflictError);
    expect(fake.calls.at(-1)?.text).toBe("ROLLBACK");
  });

  it("rejects completion when the runner lease is stale or belongs to another worker", async () => {
    const fake = makeClient((text) => {
      if (text.includes("SELECT id FROM execution_jobs")) return [{ id: executionId }];
      if (text.includes("UPDATE execution_jobs")) return [];
      return [];
    });
    const repository = new PostgresExecutionEvidenceRepository(
      connection,
      () => fake.client,
    );

    await expect(repository.recordResult(resultInput))
      .rejects.toBeInstanceOf(StaleExecutionLeaseError);
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO execution_result_records"))).toBe(false);
    expect(fake.calls.at(-1)?.text).toBe("ROLLBACK");
  });

  it("returns attempts and their ordered safe events in one owner-scoped timeline query", async () => {
    const fake = makeClient((text) => {
      if (text.includes("json_agg(json_build_object")) {
        return [{
          attempt_id: attemptId,
          execution_id: executionId,
          action: "RUN",
          language: "java",
          runtime_version: "25",
          source_sha256: "a".repeat(64),
          source_byte_length: "12",
          created_at: "2026-11-12T10:00:00.000Z",
          execution_state: "COMPLETED",
          infrastructure_status: "SUCCEEDED",
          compilation_status: "SUCCEEDED",
          verdict: "WRONG_ANSWER",
          cleanup_status: "SUCCEEDED",
          tests_total: 2,
          tests_passed: 1,
          elapsed_ms: "42",
          peak_memory_bytes: "1024",
          result_sha256: "b".repeat(64),
          events: [{
            sequenceId: "1",
            eventId: "cccccccc-cccc-4ccc-8ccc-ccccccccccc1",
            eventType: "RUNNER_STARTED",
            actorKind: "RUNNER",
            phaseStatus: "STARTED",
            safeCode: null,
            durationMs: null,
            createdAt: "2026-11-12T10:00:00.010Z",
          }],
        }];
      }
      return [];
    });
    const repository = new PostgresExecutionEvidenceRepository(connection, () => fake.client);

    const timeline = await repository.listProblemAttemptTimeline(
      "30000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000001",
      "two-sum",
      25,
    );

    expect(timeline).toHaveLength(1);
    expect(timeline[0]?.action).toBe("RUN");
    expect(timeline[0]?.verdict).toBe("WRONG_ANSWER");
    expect(timeline[0]?.events).toEqual([{
      sequenceId: "1",
      eventId: "cccccccc-cccc-4ccc-8ccc-ccccccccccc1",
      eventType: "RUNNER_STARTED",
      actorKind: "RUNNER",
      phaseStatus: "STARTED",
      safeCode: null,
      durationMs: null,
      createdAt: "2026-11-12T10:00:00.010Z",
    }]);
    const query = fake.calls.find((call) => call.text.includes("json_agg(json_build_object"));
    expect(query?.values).toEqual([
      "30000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000001",
      "two-sum",
      25,
    ]);
    expect(query?.text).toContain("ea.tenant_id = $1::uuid AND ea.actor_user_id = $2::uuid");
    expect(query?.text).toContain("ee.execution_id = ej.id AND ee.attempt_id = ea.id");
    expect(query?.text).toContain("ee.tenant_id = ea.tenant_id AND ee.actor_user_id = ea.actor_user_id");
    expect(query?.text).toContain("ORDER BY ee.sequence_id");
    expect(fake.ended()).toBe(true);
  });

  it("fails closed when database configuration is absent", async () => {
    const repository = new PostgresExecutionEvidenceRepository(undefined);
    await expect(repository.listProblemAttemptHistory(
      "30000000-0000-4000-8000-000000000001",
      "20000000-0000-4000-8000-000000000001",
      "two-sum",
    )).rejects.toBeInstanceOf(DatabaseUnavailableError);
  });
});
