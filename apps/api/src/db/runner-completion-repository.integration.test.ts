import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresExecutionEvidenceRepository } from "./execution-evidence-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import { computeV2CanonicalResultSha256 } from "../security/execution-protocol-v2-result";
import {
  RunnerCompletionConflictError,
  RunnerCompletionRuntimeImageMismatchError,
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

  it("completes a qualified v2 runner lifecycle from claim through immutable result replay", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-v2-lifecycle-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const policy = {
      policyRevision: "v2-positive-lifecycle-integration",
      runtimeImageDigests: {
        java: `sha256:${"b".repeat(64)}`,
        python: `sha256:${"c".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 1_000,
        memoryBytes: 268_435_456,
        wallTimeMillis: 60_000,
        processLimit: 32,
        outputBytes: 1_048_576,
        scratchBytes: 16_777_216,
        scratchInodes: 1_024,
      },
    } satisfies ExecutionProtocolV2Policy;
    const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, policy);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);
    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `v2-lifecycle-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      await setup.query(
        "INSERT INTO runner_machine_protocol_capabilities (runner_id, protocol_version, qualification_reference) VALUES ($1, 'v2', $2)",
        [runnerId, `v2-lifecycle-qualification-${randomUUID()}`],
      );

      const created = await intake.create({
        principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
        action: "SUBMIT",
        problemSlug: "two-sum",
        language: "java",
        runtimeVersion: "25",
        sourceCode: `public class Main { // v2-positive-lifecycle-${randomUUID()} }\\n`,
        correlationId: `v2-positive-lifecycle-${randomUUID()}`,
      }, `v2-positive-lifecycle-${randomUUID()}`);
      const handoffResult = await handoff.record({
        executionId: created.executionId,
        attemptId: created.attemptId,
        protocolVersion: "v2",
      });
      expect(handoffResult.status).toBe("RECORDED");

      const claimed = await dispatches.claimFairBatchForRunnerV2(runnerId, 10, 10, 120);
      const dispatch = claimed.find((item) => item.executionId === created.executionId);
      if (!dispatch) throw new Error("V2_LIFECYCLE_DISPATCH_NOT_CLAIMED");

      const persistedRequest = await setup.query<{
        protocol_version: string;
        policy_revision: string;
        request_sha256: string;
        request_bytes: Buffer;
      }>(
        "SELECT protocol_version, policy_revision, request_sha256, request_bytes FROM execution_protocol_requests WHERE execution_id = $1::uuid",
        [created.executionId],
      );
      expect(persistedRequest.rows).toHaveLength(1);
      expect(persistedRequest.rows[0]?.protocol_version).toBe("v2");
      expect(persistedRequest.rows[0]?.policy_revision).toBe(policy.policyRevision);
      expect(createHash("sha256").update(persistedRequest.rows[0]!.request_bytes).digest("hex"))
        .toBe(persistedRequest.rows[0]?.request_sha256.trim());

      const acceptanceInput = {
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: created.executionId,
        attemptId: created.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: createHash("sha256").update(dispatch.id + dispatch.leaseToken).digest("hex"),
      };
      const accepted = await acceptance.record(acceptanceInput);
      expect(accepted.replayed).toBe(false);
      const acceptedReplay = await acceptance.record(acceptanceInput);
      expect(acceptedReplay.replayed).toBe(true);
      expect(acceptedReplay.eventId).toBe(accepted.eventId);

      const startInput = {
        dispatchId: dispatch.id,
        executionId: created.executionId,
        attemptId: created.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };
      const started = await start.start(startInput);
      expect(started.replayed).toBe(false);
      const startedReplay = await start.start(startInput);
      expect(startedReplay.replayed).toBe(true);
      expect(startedReplay.eventId).toBe(started.eventId);

      const baseCompletionInput = makeResult({
        executionId: created.executionId,
        attemptId: created.attemptId,
        dispatchId: dispatch.id,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
      });
      const completionInput = {
        ...baseCompletionInput,
        resultSha256: await computeV2CanonicalResultSha256({
          executionId: created.executionId,
          attemptId: created.attemptId,
          dispatchId: dispatch.id,
          runnerId,
          keyId,
          requestSha256: persistedRequest.rows[0]!.request_sha256.trim(),
          policyRevision: persistedRequest.rows[0]!.policy_revision,
          runtimeImageDigest: baseCompletionInput.runtimeImageDigest!,
          infrastructureStatus: baseCompletionInput.infrastructureStatus,
          infrastructureErrorCode: baseCompletionInput.infrastructureErrorCode,
          compilationStatus: baseCompletionInput.compilationStatus,
          verdict: baseCompletionInput.verdict,
          cleanupStatus: baseCompletionInput.cleanupStatus,
          testsTotal: baseCompletionInput.testsTotal,
          testsPassed: baseCompletionInput.testsPassed,
          elapsedMs: baseCompletionInput.elapsedMs,
          peakMemoryBytes: baseCompletionInput.peakMemoryBytes,
          runnerVersion: baseCompletionInput.runnerVersion,
          startedAt: baseCompletionInput.startedAt,
          completedAt: baseCompletionInput.completedAt,
        }),
      };
      await expect(evidence.recordRunnerResult({
        ...completionInput,
        runtimeImageDigest: "d".repeat(64),
      })).rejects.toBeInstanceOf(RunnerCompletionRuntimeImageMismatchError);
      const afterRejectedRuntime = await setup.query<{
        job_state: string;
        result_count: string;
        completion_count: string;
      }>(
        [
          "SELECT job.state AS job_state,",
          "  (SELECT count(*)::text FROM execution_result_records WHERE execution_id=job.id) AS result_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_completions WHERE execution_id=job.id) AS completion_count",
          "FROM execution_jobs AS job WHERE job.id=$1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(afterRejectedRuntime.rows[0]).toEqual({
        job_state: "RUNNING",
        result_count: "0",
        completion_count: "0",
      });

      const completed = await evidence.recordRunnerResult(completionInput);
      expect(completed.replayed).toBe(false);
      expect(completed.state).toBe("COMPLETED");
      const completedReplay = await evidence.recordRunnerResult(completionInput);
      expect(completedReplay.replayed).toBe(true);
      expect(completedReplay.resultSha256).toBe(completed.resultSha256);

      const finalState = await setup.query<{
        protocol_version: string;
        job_state: string;
        dispatch_state: string;
        acceptance_events: string;
        start_events: string;
        completion_events: string;
        result_count: string;
      }>(
        [
          "SELECT dispatch.protocol_version, job.state AS job_state, dispatch.delivery_state AS dispatch_state,",
          "  (SELECT count(*)::text FROM execution_evidence_events WHERE execution_id=job.id AND event_type='RUNNER_ACCEPTED') AS acceptance_events,",
          "  (SELECT count(*)::text FROM execution_evidence_events WHERE execution_id=job.id AND event_type='RUNNER_STARTED') AS start_events,",
          "  (SELECT count(*)::text FROM execution_evidence_events WHERE execution_id=job.id AND event_type='EXECUTION_FINISHED') AS completion_events,",
          "  (SELECT count(*)::text FROM execution_result_records WHERE execution_id=job.id) AS result_count",
          "FROM execution_jobs AS job",
          "INNER JOIN runner_dispatch_outbox AS dispatch ON dispatch.execution_id=job.id",
          "WHERE job.id=$1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(finalState.rows[0]).toEqual({
        protocol_version: "v2",
        job_state: "COMPLETED",
        dispatch_state: "DELIVERED",
        acceptance_events: "1",
        start_events: "1",
        completion_events: "1",
        result_count: "1",
      });
    } finally {
      await setup.query(
        "DELETE FROM runner_machine_protocol_capabilities WHERE runner_id=$1",
        [runnerId],
      ).catch(() => undefined);
      await setup.query("DELETE FROM runner_machines WHERE id=$1", [runnerId]).catch(() => undefined);
      await setup.end();
    }
  }, 30_000);
});
