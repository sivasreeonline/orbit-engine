import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresExecutionEvidenceRepository } from "./execution-evidence-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";
import {
  RunnerCompletionConflictError,
  type RecordRunnerExecutionResultInput,
} from "./execution-evidence-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";

async function createStartedDispatch(runnerId: string, actorId: string, keyId: string) {
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action: "SUBMIT",
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode: `public class Main { // runner-completion-${randomUUID()} }\n`,
    correlationId: `runner-completion-${randomUUID()}`,
  }, `runner-completion-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });
  const claimed = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RUNNER_COMPLETION_DISPATCH_NOT_CLAIMED");

  const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
  const start = new PostgresRunnerStartRepository(databaseUrl);
  await acceptance.record({
    acceptanceId: randomUUID(),
    dispatchId: dispatch.id,
    executionId: created.executionId,
    attemptId: created.attemptId,
    runnerId,
    keyId,
    leaseToken: dispatch.leaseToken,
    receiptSha256: "a".repeat(64),
  });
  await start.start({
    dispatchId: dispatch.id,
    executionId: created.executionId,
    attemptId: created.attemptId,
    leaseToken: dispatch.leaseToken,
    runnerId,
    keyId,
  });
  return { created, dispatch };
}

function makeResult(input: {
  executionId: string;
  attemptId: string;
  dispatchId: string;
  runnerId: string;
  keyId: string;
  leaseToken: string;
}): RecordRunnerExecutionResultInput {
  const completedAt = new Date();
  const startedAt = new Date(completedAt.getTime() - 75);
  const digestMaterial = {
    executionId: input.executionId,
    attemptId: input.attemptId,
    infrastructureStatus: "SUCCEEDED",
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    testsTotal: 4,
    testsPassed: 4,
    elapsedMs: 75,
    runnerVersion: "runner-integration-test",
  };
  return {
    ...input,
    leaseOwner: input.runnerId,
    infrastructureStatus: "SUCCEEDED",
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "SUCCEEDED",
    testsTotal: 4,
    testsPassed: 4,
    elapsedMs: 75,
    peakMemoryBytes: 4_194_304,
    runnerVersion: "runner-integration-test",
    runtimeImageDigest: "b".repeat(64),
    resultSha256: createHash("sha256").update(JSON.stringify(digestMaterial)).digest("hex"),
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
  };
}

describe.skipIf(!databaseUrl)("authenticated runner completion PostgreSQL integration", () => {
  it("stores one terminal result and receipt, then replays only for the same runner lease", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-completion-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `completion-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const { created, dispatch } = await createStartedDispatch(runnerId, actorId, keyId);
      const input = makeResult({
        executionId: created.executionId,
        attemptId: created.attemptId,
        dispatchId: dispatch.id,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
      });

      const first = await evidence.recordRunnerResult(input);
      expect(first.replayed).toBe(false);
      expect(first.state).toBe("COMPLETED");

      const replay = await evidence.recordRunnerResult(input);
      expect(replay.replayed).toBe(true);
      expect(replay.resultSha256).toBe(first.resultSha256);

      await expect(evidence.recordRunnerResult({
        ...input,
        resultSha256: "c".repeat(64),
      })).rejects.toBeInstanceOf(RunnerCompletionConflictError);

      const persisted = await setup.query<{
        job_state: string;
        dispatch_state: string;
        dispatch_lease_owner: string | null;
        result_count: string;
        completion_count: string;
        completion_runner: string;
        completion_event_count: string;
        completion_event_type: string;
      }>(
        [
          "SELECT job.state AS job_state, dispatch.delivery_state AS dispatch_state,",
          "  dispatch.lease_owner AS dispatch_lease_owner,",
          "  (SELECT count(*)::text FROM execution_result_records WHERE execution_id = job.id) AS result_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_completions WHERE execution_id = job.id) AS completion_count,",
          "  (SELECT runner_id::text FROM runner_dispatch_completions WHERE execution_id = job.id) AS completion_runner,",
          "  (SELECT count(*)::text FROM execution_evidence_events",
          "   WHERE execution_id = job.id AND event_type = 'EXECUTION_FINISHED') AS completion_event_count,",
          "  (SELECT event_type FROM execution_evidence_events",
          "   WHERE event_id = (SELECT event_id FROM runner_dispatch_completions WHERE execution_id = job.id)) AS completion_event_type",
          "FROM execution_jobs AS job",
          "INNER JOIN runner_dispatch_outbox AS dispatch ON dispatch.execution_id = job.id",
          "WHERE job.id = $1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(persisted.rows[0]).toEqual({
        job_state: "COMPLETED",
        dispatch_state: "DELIVERED",
        dispatch_lease_owner: null,
        result_count: "1",
        completion_count: "1",
        completion_runner: runnerId,
        completion_event_count: "1",
        completion_event_type: "EXECUTION_FINISHED",
      });

      await expect(setup.query(
        "UPDATE runner_dispatch_completions SET key_id = 'other-key' WHERE execution_id = $1::uuid",
        [created.executionId],
      )).rejects.toMatchObject({ code: "55000" });
    } finally {
      await setup.end();
    }
  }, 25_000);

  it("rejects expired leases without persisting a terminal result or completion receipt", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-completion-expired-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `completion-expired-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const { created, dispatch } = await createStartedDispatch(runnerId, actorId, keyId);
      const input = makeResult({
        executionId: created.executionId,
        attemptId: created.attemptId,
        dispatchId: dispatch.id,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
      });
      await setup.query(
        "UPDATE runner_dispatch_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.id],
      );
      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [created.executionId],
      );

      await expect(evidence.recordRunnerResult(input)).rejects.toThrow(
        "execution_result_rejected_for_stale_or_invalid_lease",
      );
      const counts = await setup.query<{ job_state: string; result_count: string; completion_count: string }>(
        [
          "SELECT job.state AS job_state,",
          "  (SELECT count(*)::text FROM execution_result_records WHERE execution_id = job.id) AS result_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_completions WHERE execution_id = job.id) AS completion_count",
          "FROM execution_jobs AS job WHERE job.id = $1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(counts.rows[0]).toEqual({
        job_state: "RUNNING",
        result_count: "0",
        completion_count: "0",
      });
    } finally {
      await setup.end();
    }
  }, 20_000);
});
