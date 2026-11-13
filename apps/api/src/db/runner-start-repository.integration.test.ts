import { randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import {
  PostgresRunnerStartRepository,
  RunnerStartNotAcceptedError,
  RunnerStartStaleLeaseError,
} from "./runner-start-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";

async function createClaimedDispatch(
  runnerId: string,
  actorId: string,
  keyId: string,
) {
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action: "RUN",
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode: `public class Main { // runner-start-${randomUUID()} }\n`,
    correlationId: `runner-start-${randomUUID()}`,
  }, `runner-start-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });
  const claimed = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RUNNER_START_DISPATCH_NOT_CLAIMED");
  return { created, dispatch };
}

describe.skipIf(!databaseUrl)("runner start receipt PostgreSQL integration", () => {
  it("transitions an accepted lease to RUNNING once and appends immutable RUNNER_STARTED evidence", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-start-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `start-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId, keyId);
      const acceptanceId = randomUUID();
      await acceptance.record({
        acceptanceId,
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "a".repeat(64),
      });

      const input = {
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };
      const first = await start.start(input);
      expect(first.replayed).toBe(false);
      expect(first.dispatchId).toBe(dispatch.id);
      expect(first.executionId).toBe(created.executionId);

      const replay = await start.start(input);
      expect(replay.replayed).toBe(true);
      expect(replay.eventId).toBe(first.eventId);
      expect(replay.startedAt).toBe(first.startedAt);

      const persisted = await setup.query<{
        job_state: string;
        job_owner: string | null;
        job_token: string | null;
        start_count: string;
        event_count: string;
        event_actor: string;
        event_phase: string;
      }>(
        [
          "SELECT job.state AS job_state, job.lease_owner AS job_owner,",
          "  job.lease_token::text AS job_token,",
          "  (SELECT count(*)::text FROM runner_dispatch_starts",
          "   WHERE dispatch_id = $2::uuid AND lease_token = $3::uuid) AS start_count,",
          "  (SELECT count(*)::text FROM execution_evidence_events",
          "   WHERE event_id = $4::uuid AND event_type = 'RUNNER_STARTED') AS event_count,",
          "  (SELECT actor_kind FROM execution_evidence_events WHERE event_id = $4::uuid) AS event_actor,",
          "  (SELECT phase_status FROM execution_evidence_events WHERE event_id = $4::uuid) AS event_phase",
          "FROM execution_jobs AS job WHERE job.id = $1::uuid",
        ].join("\n"),
        [created.executionId, dispatch.id, dispatch.leaseToken, first.eventId],
      );
      expect(persisted.rows[0]).toEqual({
        job_state: "RUNNING",
        job_owner: runnerId,
        job_token: dispatch.leaseToken,
        start_count: "1",
        event_count: "1",
        event_actor: "RUNNER",
        event_phase: "STARTED",
      });

      await expect(setup.query(
        "UPDATE runner_dispatch_starts SET key_id = 'other-key' WHERE dispatch_id = $1::uuid",
        [dispatch.id],
      )).rejects.toMatchObject({ code: "55000" });
      await expect(setup.query(
        "UPDATE execution_evidence_events SET phase_status = 'FAILED' WHERE event_id = $1::uuid",
        [first.eventId],
      )).rejects.toMatchObject({ code: "55000" });
    } finally {
      await setup.end();
    }
  }, 20_000);

  it("refuses start without acceptance and refuses a start after lease expiry", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-start-guard-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `start-guard-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId, keyId);
      const input = {
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };

      await expect(start.start(input)).rejects.toBeInstanceOf(RunnerStartNotAcceptedError);

      const beforeAcceptance = await setup.query<{ state: string }>(
        "SELECT state FROM execution_jobs WHERE id = $1::uuid",
        [created.executionId],
      );
      expect(beforeAcceptance.rows[0]?.state).toBe("CLAIMED");

      await acceptance.record({
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "b".repeat(64),
      });
      await setup.query(
        "UPDATE runner_dispatch_outbox SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.id],
      );
      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        [created.executionId],
      );

      await expect(start.start(input)).rejects.toBeInstanceOf(RunnerStartStaleLeaseError);
      const afterExpiry = await setup.query<{ state: string; event_count: string }>(
        [
          "SELECT job.state,",
          "  (SELECT count(*)::text FROM execution_evidence_events",
          "   WHERE execution_id = job.id AND event_type = 'RUNNER_STARTED') AS event_count",
          "FROM execution_jobs AS job WHERE job.id = $1::uuid",
        ].join("\n"),
        [created.executionId],
      );
      expect(afterExpiry.rows[0]).toEqual({ state: "CLAIMED", event_count: "0" });
    } finally {
      await setup.end();
    }
  }, 20_000);
});
