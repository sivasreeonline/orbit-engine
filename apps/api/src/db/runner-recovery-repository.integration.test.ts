import { randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";
import { PostgresRunnerRecoveryRepository } from "./runner-recovery-repository";

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
    sourceCode: `public class Main { // runner-recovery-${randomUUID()} }\n`,
    correlationId: `runner-recovery-${randomUUID()}`,
  }, `runner-recovery-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });

  const claimed = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RUNNER_RECOVERY_DISPATCH_NOT_CLAIMED");
  await acceptAndStart(runnerId, keyId, created.executionId, created.attemptId, dispatch);
  return { created, dispatch, dispatches };
}

async function acceptAndStart(
  runnerId: string,
  keyId: string,
  executionId: string,
  attemptId: string,
  dispatch: { id: string; leaseToken: string },
) {
  const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
  const start = new PostgresRunnerStartRepository(databaseUrl);
  await acceptance.record({
    acceptanceId: randomUUID(),
    dispatchId: dispatch.id,
    executionId,
    attemptId,
    runnerId,
    keyId,
    leaseToken: dispatch.leaseToken,
    receiptSha256: "f".repeat(64),
  });
  await start.start({
    dispatchId: dispatch.id,
    executionId,
    attemptId,
    leaseToken: dispatch.leaseToken,
    runnerId,
    keyId,
  });
}

async function expireLease(
  client: Client,
  dispatchId: string,
  executionId: string,
  divergent = false,
) {
  await client.query(
    "UPDATE runner_dispatch_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
    [dispatchId],
  );
  await client.query(
    divergent
      ? "UPDATE execution_jobs SET lease_expires_at = clock_timestamp() + interval '1 minute' WHERE id = $1::uuid"
      : "UPDATE execution_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
    [executionId],
  );
}

async function makeAvailableNow(client: Client, dispatchId: string, executionId: string) {
  await client.query(
    "UPDATE execution_jobs SET available_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
    [executionId],
  );
  await client.query(
    "UPDATE runner_dispatch_outbox SET available_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
    [dispatchId],
  );
}

describe.skipIf(!databaseUrl)("runner expiry recovery PostgreSQL integration", () => {
  it("requeues twice under fresh lease generations and then records one terminal infrastructure failure", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-recovery-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const recovery = new PostgresRunnerRecoveryRepository(databaseUrl);
    const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `recovery-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const first = await createStartedDispatch(runnerId, actorId, keyId);
      await expireLease(setup, first.dispatch.id, first.created.executionId, true);

      const firstRecovery = await recovery.recoverExpiredRunning({
        workerId: "recovery-integration",
        batchSize: 10,
        maxRetries: 2,
        baseDelaySeconds: 1,
        maxDelaySeconds: 5,
      });
      expect(firstRecovery).toHaveLength(1);
      expect(firstRecovery[0]).toMatchObject({
        dispatchId: first.dispatch.id,
        executionId: first.created.executionId,
        action: "REQUEUED",
        retryCount: 1,
        resultSha256: null,
      });
      expect(firstRecovery[0]!.availableAt).not.toBeNull();

      await makeAvailableNow(setup, first.dispatch.id, first.created.executionId);
      const secondClaim = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
      const secondDispatch = secondClaim.find((item) => item.executionId === first.created.executionId);
      expect(secondDispatch).toBeDefined();
      expect(secondDispatch!.leaseToken).not.toBe(first.dispatch.leaseToken);
      await acceptAndStart(
        runnerId, keyId, first.created.executionId, first.created.attemptId, secondDispatch!,
      );

      await expireLease(setup, first.dispatch.id, first.created.executionId);
      const secondRecovery = await recovery.recoverExpiredRunning({
        workerId: "recovery-integration",
        batchSize: 10,
        maxRetries: 2,
        baseDelaySeconds: 1,
        maxDelaySeconds: 5,
      });
      expect(secondRecovery).toHaveLength(1);
      expect(secondRecovery[0]).toMatchObject({
        action: "REQUEUED",
        retryCount: 2,
      });

      await makeAvailableNow(setup, first.dispatch.id, first.created.executionId);
      const thirdClaim = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
      const thirdDispatch = thirdClaim.find((item) => item.executionId === first.created.executionId);
      expect(thirdDispatch).toBeDefined();
      expect(thirdDispatch!.leaseToken).not.toBe(secondDispatch!.leaseToken);
      await acceptAndStart(
        runnerId, keyId, first.created.executionId, first.created.attemptId, thirdDispatch!,
      );

      await expireLease(setup, first.dispatch.id, first.created.executionId);
      const terminalRecovery = await recovery.recoverExpiredRunning({
        workerId: "recovery-integration",
        batchSize: 10,
        maxRetries: 2,
        baseDelaySeconds: 1,
        maxDelaySeconds: 5,
      });
      expect(terminalRecovery).toHaveLength(1);
      expect(terminalRecovery[0]).toMatchObject({
        action: "FAILED_INFRASTRUCTURE",
        retryCount: 2,
      });
      expect(terminalRecovery[0]!.resultSha256).toMatch(/^[0-9a-f]{64}$/);

      const persisted = await setup.query<{
        job_state: string;
        job_retry_count: number;
        job_owner: string | null;
        dispatch_state: string;
        start_count: string;
        recovery_count: string;
        requeued_count: string;
        failed_count: string;
        result_count: string;
        result_status: string;
        result_code: string;
        event_retry_count: string;
        event_failed_count: string;
      }>(
        [
          "SELECT job.state AS job_state, job.retry_count AS job_retry_count,",
          "  job.lease_owner AS job_owner, dispatch.delivery_state AS dispatch_state,",
          "  (SELECT count(*)::text FROM runner_dispatch_starts WHERE execution_id = job.id) AS start_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_recoveries WHERE execution_id = job.id) AS recovery_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_recoveries WHERE execution_id = job.id AND recovery_action = 'REQUEUED') AS requeued_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_recoveries WHERE execution_id = job.id AND recovery_action = 'FAILED_INFRASTRUCTURE') AS failed_count,",
          "  (SELECT count(*)::text FROM execution_result_records WHERE execution_id = job.id) AS result_count,",
          "  (SELECT infrastructure_status FROM execution_result_records WHERE execution_id = job.id) AS result_status,",
          "  (SELECT infrastructure_error_code FROM execution_result_records WHERE execution_id = job.id) AS result_code,",
          "  (SELECT count(*)::text FROM execution_evidence_events WHERE execution_id = job.id AND event_type = 'RETRY_SCHEDULED') AS event_retry_count,",
          "  (SELECT count(*)::text FROM execution_evidence_events WHERE execution_id = job.id AND event_type = 'INFRASTRUCTURE_FAILED') AS event_failed_count",
          "FROM execution_jobs AS job",
          "INNER JOIN runner_dispatch_outbox AS dispatch ON dispatch.execution_id = job.id",
          "WHERE job.id = $1::uuid",
        ].join("\n"),
        [first.created.executionId],
      );
      expect(persisted.rows[0]).toEqual({
        job_state: "FAILED_INFRASTRUCTURE",
        job_retry_count: 2,
        job_owner: null,
        dispatch_state: "DEAD_LETTER",
        start_count: "3",
        recovery_count: "3",
        requeued_count: "2",
        failed_count: "1",
        result_count: "1",
        result_status: "FAILED",
        result_code: "RUNNER_LEASE_EXPIRED",
        event_retry_count: "2",
        event_failed_count: "1",
      });

      await expect(setup.query(
        "DELETE FROM runner_dispatch_recoveries WHERE execution_id = $1::uuid",
        [first.created.executionId],
      )).rejects.toMatchObject({ code: "55000" });
    } finally {
      await setup.end();
    }
  }, 35_000);

  it("allows only one concurrent recovery decision for an expired lease", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-recovery-concurrent-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const recovery = new PostgresRunnerRecoveryRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `recovery-concurrent-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      const execution = await createStartedDispatch(runnerId, actorId, keyId);
      await expireLease(setup, execution.dispatch.id, execution.created.executionId);

      const [first, second] = await Promise.all([
        recovery.recoverExpiredRunning({ workerId: "recovery-worker-a", batchSize: 10 }),
        recovery.recoverExpiredRunning({ workerId: "recovery-worker-b", batchSize: 10 }),
      ]);
      expect(first.length + second.length).toBe(1);

      const receipts = await setup.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM runner_dispatch_recoveries WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid",
        [execution.dispatch.id, execution.dispatch.leaseToken],
      );
      expect(receipts.rows[0]?.count).toBe("1");
    } finally {
      await setup.end();
    }
  }, 25_000);
});
