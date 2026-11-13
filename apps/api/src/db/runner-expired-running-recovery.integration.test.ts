import { randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const MAX_RECOVERIES = 3;

interface TestRunner {
  readonly runnerId: string;
  readonly keyId: string;
}

async function createRunner(setup: Client, prefix: string): Promise<TestRunner> {
  const runnerId = randomUUID();
  const keyId = `${prefix}-${runnerId}`;
  await setup.query(
    "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
    [runnerId, `${prefix}-machine-${runnerId}`],
  );
  await setup.query(
    "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
    [keyId, runnerId, randomBytes(32)],
  );
  return { runnerId, keyId };
}

async function createDispatch(actorId: string, firstRunnerId: string) {
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action: "RUN",
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode: `public class Main { // recovery-${randomUUID()} }\n`,
    correlationId: `lease-recovery-${randomUUID()}`,
  }, `lease-recovery-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });
  const claimed = await dispatches.claimFairBatchForRunner(firstRunnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RECOVERY_INITIAL_DISPATCH_NOT_CLAIMED");
  return { created, dispatch };
}

async function acceptAndStart(runner: TestRunner, dispatch: {
  id: string;
  executionId: string;
  attemptId: string;
  leaseToken: string;
}) {
  const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
  const start = new PostgresRunnerStartRepository(databaseUrl);
  await acceptance.record({
    acceptanceId: randomUUID(),
    dispatchId: dispatch.id,
    executionId: dispatch.executionId,
    attemptId: dispatch.attemptId,
    runnerId: runner.runnerId,
    keyId: runner.keyId,
    leaseToken: dispatch.leaseToken,
    receiptSha256: "a".repeat(64),
  });
  return start.start({
    dispatchId: dispatch.id,
    executionId: dispatch.executionId,
    attemptId: dispatch.attemptId,
    leaseToken: dispatch.leaseToken,
    runnerId: runner.runnerId,
    keyId: runner.keyId,
  });
}

async function expireLease(setup: Client, dispatchId: string, executionId: string) {
  const expiry = await setup.query<{ expired_at: Date }>(
    "SELECT clock_timestamp() - interval '5 seconds' AS expired_at",
  );
  const expiredAt = expiry.rows[0]?.expired_at;
  if (!expiredAt) throw new Error("RECOVERY_TEST_EXPIRY_NOT_CREATED");

  await setup.query(
    "UPDATE runner_dispatch_outbox SET lease_expires_at = $2::timestamptz WHERE id = $1::uuid",
    [dispatchId, expiredAt],
  );
  await setup.query(
    "UPDATE execution_jobs SET lease_expires_at = $2::timestamptz WHERE id = $1::uuid",
    [executionId, expiredAt],
  );
}

describe.skipIf(!databaseUrl)("expired RUNNING runner lease recovery PostgreSQL integration", () => {
  it("reclaims three started lease generations and terminalizes the fourth expiry", async () => {
    const setup = new Client({ connectionString: databaseUrl });
    const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    await setup.connect();

    try {
      let currentRunner = await createRunner(setup, "recovery-generation-0");
      const actorId = randomUUID();
      const { created, dispatch: initialDispatch } = await createDispatch(actorId, currentRunner.runnerId);
      let currentDispatch = initialDispatch;

      const initialStart = await acceptAndStart(currentRunner, currentDispatch);
      expect(initialStart.replayed).toBe(false);

      const leaseTokens = [currentDispatch.leaseToken];
      const startEventIds = [initialStart.eventId];

      for (let recoveryAttempt = 1; recoveryAttempt <= MAX_RECOVERIES; recoveryAttempt += 1) {
        await expireLease(setup, currentDispatch.id, created.executionId);

        const nextRunner = await createRunner(setup, `recovery-generation-${recoveryAttempt}`);
        const recovered = await dispatches.claimFairBatchForRunner(
          nextRunner.runnerId,
          1,
          2,
          120,
        );

        expect(recovered).toHaveLength(1);
        const nextDispatch = recovered[0]!;
        expect(nextDispatch.id).toBe(initialDispatch.id);
        expect(nextDispatch.leaseToken).not.toBe(currentDispatch.leaseToken);
        expect(nextDispatch.deliveryAttempts).toBe(initialDispatch.deliveryAttempts + recoveryAttempt);

        const state = await setup.query<{
          state: string;
          retry_count: number;
          lease_owner: string;
          lease_token: string;
        }>(
          "SELECT state, retry_count, lease_owner, lease_token::text AS lease_token FROM execution_jobs WHERE id = $1::uuid",
          [created.executionId],
        );
        expect(state.rows[0]).toEqual({
          state: "CLAIMED",
          retry_count: recoveryAttempt,
          lease_owner: nextRunner.runnerId,
          lease_token: nextDispatch.leaseToken,
        });

        const receipt = await setup.query<{
          previous_lease_token: string;
          previous_runner_id: string;
          previous_start_event_id: string;
          new_lease_token: string;
          new_runner_id: string;
          recovery_attempt: number;
        }>(
          [
            "SELECT previous_lease_token::text AS previous_lease_token,",
            "  previous_runner_id::text AS previous_runner_id,",
            "  previous_start_event_id::text AS previous_start_event_id,",
            "  new_lease_token::text AS new_lease_token, new_runner_id::text AS new_runner_id,",
            "  recovery_attempt",
            "FROM runner_dispatch_lease_recoveries",
            "WHERE dispatch_id = $1::uuid AND previous_lease_token = $2::uuid",
          ].join("\n"),
          [initialDispatch.id, currentDispatch.leaseToken],
        );
        expect(receipt.rows[0]).toMatchObject({
          previous_lease_token: currentDispatch.leaseToken,
          previous_runner_id: currentRunner.runnerId,
          previous_start_event_id: startEventIds.at(-1),
          new_lease_token: nextDispatch.leaseToken,
          new_runner_id: nextRunner.runnerId,
          recovery_attempt: recoveryAttempt,
        });

        const retryEvidence = await setup.query<{ count: string }>(
          [
            "SELECT count(*)::text AS count FROM execution_evidence_events",
            "WHERE execution_id = $1::uuid AND event_type = 'RETRY_SCHEDULED'",
            "  AND safe_code = 'RUNNER_LEASE_EXPIRED'",
          ].join("\n"),
          [created.executionId],
        );
        expect(retryEvidence.rows[0]?.count).toBe(String(recoveryAttempt));

        const start = await acceptAndStart(nextRunner, nextDispatch);
        expect(start.replayed).toBe(false);
        currentRunner = nextRunner;
        currentDispatch = nextDispatch;
        leaseTokens.push(currentDispatch.leaseToken);
        startEventIds.push(start.eventId);
      }

      expect(new Set(leaseTokens).size).toBe(MAX_RECOVERIES + 1);

      const beforeExhaustion = await setup.query<{
        start_count: string;
        recovery_count: string;
      }>(
        [
          "SELECT",
          "  (SELECT count(*)::text FROM runner_dispatch_starts WHERE dispatch_id = $1::uuid) AS start_count,",
          "  (SELECT count(*)::text FROM runner_dispatch_lease_recoveries WHERE dispatch_id = $1::uuid) AS recovery_count",
        ].join("\n"),
        [initialDispatch.id],
      );
      expect(beforeExhaustion.rows[0]).toEqual({
        start_count: String(MAX_RECOVERIES + 1),
        recovery_count: String(MAX_RECOVERIES),
      });

      await expireLease(setup, currentDispatch.id, created.executionId);
      const finalRunner = await createRunner(setup, "recovery-exhausted");
      const afterLimit = await dispatches.claimFairBatchForRunner(
        finalRunner.runnerId,
        1,
        2,
        120,
      );
      expect(afterLimit).toHaveLength(0);

      const terminal = await setup.query<{
        state: string;
        retry_count: number;
        lease_owner: string | null;
        lease_token: string | null;
        outbox_state: string;
        outbox_lease_owner: string | null;
      }>(
        [
          "SELECT job.state, job.retry_count, job.lease_owner,",
          "  job.lease_token::text AS lease_token, dispatch.delivery_state AS outbox_state,",
          "  dispatch.lease_owner AS outbox_lease_owner",
          "FROM execution_jobs AS job",
          "INNER JOIN runner_dispatch_outbox AS dispatch ON dispatch.execution_id = job.id",
          "WHERE job.id = $1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(terminal.rows[0]).toEqual({
        state: "FAILED_INFRASTRUCTURE",
        retry_count: MAX_RECOVERIES,
        lease_owner: null,
        lease_token: null,
        outbox_state: "DEAD_LETTER",
        outbox_lease_owner: null,
      });

      const exhaustedEvent = await setup.query<{ count: string }>(
        [
          "SELECT count(*)::text AS count FROM execution_evidence_events",
          "WHERE execution_id = $1::uuid AND event_type = 'INFRASTRUCTURE_FAILED'",
          "  AND safe_code = 'RUNNER_LEASE_RECOVERIES_EXHAUSTED'",
        ].join("\n"),
        [created.executionId],
      );
      expect(exhaustedEvent.rows[0]?.count).toBe("1");
    } finally {
      await setup.end();
    }
  }, 45_000);

  it("does not reclaim a RUNNING job without its durable start receipt", async () => {
    const setup = new Client({ connectionString: databaseUrl });
    const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    await setup.connect();

    try {
      const originalRunner = await createRunner(setup, "recovery-missing-start-original");
      const nextRunner = await createRunner(setup, "recovery-missing-start-next");
      const actorId = randomUUID();
      const { created, dispatch } = await createDispatch(actorId, originalRunner.runnerId);

      await setup.query(
        "UPDATE execution_jobs SET state = 'RUNNING', lease_owner = $2, lease_token = $3::uuid, lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [created.executionId, originalRunner.runnerId, dispatch.leaseToken],
      );
      await expireLease(setup, dispatch.id, created.executionId);

      const claimed = await dispatches.claimFairBatchForRunner(nextRunner.runnerId, 1, 2, 120);
      expect(claimed).toHaveLength(0);

      const unchanged = await setup.query<{ state: string; lease_token: string }>(
        "SELECT state, lease_token::text AS lease_token FROM execution_jobs WHERE id = $1::uuid",
        [created.executionId],
      );
      expect(unchanged.rows[0]).toEqual({
        state: "RUNNING",
        lease_token: dispatch.leaseToken,
      });
    } finally {
      await setup.end();
    }
  }, 20_000);
});
