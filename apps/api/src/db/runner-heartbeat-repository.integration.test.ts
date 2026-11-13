import { randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";
import {
  PostgresRunnerHeartbeatRepository,
  RunnerHeartbeatNotStartedError,
  RunnerHeartbeatStaleLeaseError,
} from "./runner-heartbeat-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";

async function createClaimedDispatch(runnerId: string, actorId: string) {
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action: "RUN",
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode: `public class Main { // runner-heartbeat-${randomUUID()} }\n`,
    correlationId: `runner-heartbeat-${randomUUID()}`,
  }, `runner-heartbeat-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });
  const claimed = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RUNNER_HEARTBEAT_DISPATCH_NOT_CLAIMED");
  return { created, dispatch };
}

describe.skipIf(!databaseUrl)("runner heartbeat PostgreSQL integration", () => {
  it("extends both lease rows, persists an immutable receipt and replays idempotently", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-heartbeat-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);
    const heartbeat = new PostgresRunnerHeartbeatRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `heartbeat-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId);
      await acceptance.record({
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "c".repeat(64),
      });
      await start.start({
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      });

      const input = {
        heartbeatId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };
      const first = await heartbeat.renew(input);
      expect(first.replayed).toBe(false);
      expect(Date.parse(first.leaseExpiresAt)).toBeGreaterThan(Date.parse(dispatch.leaseExpiresAt));

      const replay = await heartbeat.renew(input);
      expect(replay.replayed).toBe(true);
      expect(replay.leaseExpiresAt).toBe(first.leaseExpiresAt);

      const second = await heartbeat.renew({ ...input, heartbeatId: randomUUID() });
      expect(second.replayed).toBe(false);
      expect(Date.parse(second.leaseExpiresAt)).toBeGreaterThan(Date.parse(first.leaseExpiresAt));

      const persisted = await setup.query<{
        job_state: string;
        dispatch_expiry: string;
        job_expiry: string;
        heartbeat_count: string;
        runner_id: string;
      }>(
        [
          "SELECT job.state AS job_state, dispatch.lease_expires_at::text AS dispatch_expiry,",
          "  job.lease_expires_at::text AS job_expiry,",
          "  (SELECT count(*)::text FROM runner_dispatch_lease_heartbeats",
          "   WHERE dispatch_id = dispatch.id AND lease_token = $2::uuid) AS heartbeat_count,",
          "  (SELECT runner_id::text FROM runner_dispatch_lease_heartbeats",
          "   WHERE heartbeat_id = $3::uuid) AS runner_id",
          "FROM runner_dispatch_outbox AS dispatch",
          "INNER JOIN execution_jobs AS job ON job.id = dispatch.execution_id",
          "WHERE dispatch.id = $1::uuid",
        ].join("\n"),
        [dispatch.id, dispatch.leaseToken, input.heartbeatId],
      );
      expect(persisted.rows[0]).toMatchObject({
        job_state: "RUNNING",
        heartbeat_count: "2",
        runner_id: runnerId,
      });
      expect(new Date(persisted.rows[0]!.dispatch_expiry).toISOString())
        .toBe(second.leaseExpiresAt);
      expect(new Date(persisted.rows[0]!.job_expiry).toISOString())
        .toBe(second.leaseExpiresAt);

      await expect(setup.query(
        "DELETE FROM runner_dispatch_lease_heartbeats WHERE heartbeat_id = $1::uuid",
        [input.heartbeatId],
      )).rejects.toMatchObject({ code: "55000" });
      expect(created.executionId).toBe(second.executionId);
    } finally {
      await setup.end();
    }
  }, 20_000);

  it("requires a start receipt and rejects expired or divergent leases", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-heartbeat-guard-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);
    const heartbeat = new PostgresRunnerHeartbeatRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `heartbeat-guard-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId);
      await acceptance.record({
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "d".repeat(64),
      });
      const input = {
        heartbeatId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };

      await expect(heartbeat.renew(input)).rejects.toBeInstanceOf(RunnerHeartbeatNotStartedError);
      await start.start({
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      });

      await setup.query(
        "UPDATE runner_dispatch_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.id],
      );
      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [created.executionId],
      );
      await expect(heartbeat.renew(input)).rejects.toBeInstanceOf(RunnerHeartbeatStaleLeaseError);

      const count = await setup.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM runner_dispatch_lease_heartbeats WHERE dispatch_id = $1::uuid",
        [dispatch.id],
      );
      expect(count.rows[0]?.count).toBe("0");
    } finally {
      await setup.end();
    }
  }, 20_000);

  it("rejects lease rows that no longer share the same expiry", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-heartbeat-split-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const start = new PostgresRunnerStartRepository(databaseUrl);
    const heartbeat = new PostgresRunnerHeartbeatRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `heartbeat-split-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId);
      await acceptance.record({
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "e".repeat(64),
      });
      await start.start({
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      });

      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = lease_expires_at + interval '1 second' WHERE id = $1::uuid",
        [created.executionId],
      );
      await expect(heartbeat.renew({
        heartbeatId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      })).rejects.toMatchObject({
        name: "DatabaseUnavailableError",
        message: "database_unavailable",
      });
    } finally {
      await setup.end();
    }
  }, 20_000);
});
