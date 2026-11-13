import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import {
  PostgresRunnerAcceptanceRepository,
  RunnerAcceptanceConflictError,
  RunnerAcceptanceStaleLeaseError,
} from "./runner-acceptance-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("runner acceptance receipt PostgreSQL integration", () => {
  it("records an immutable receipt once per lease and appends RUNNER_ACCEPTED evidence", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-accept-${runnerId}`;
    const dispatchRepo = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const acceptanceRepo = new PostgresRunnerAcceptanceRepository(databaseUrl);
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const setup = new Client({ connectionString: databaseUrl });

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `acceptance-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const created = await intake.create({
        principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        runtimeVersion: "25",
        sourceCode: `public class Main { // acceptance-${randomUUID()} }\n`,
        correlationId: `runner-acceptance-${randomUUID()}`,
      }, `runner-acceptance-${randomUUID()}`);
      await handoff.record({
        executionId: created.executionId,
        attemptId: created.attemptId,
        protocolVersion: "v1",
      });

      const claimed = await dispatchRepo.claimFairBatchForRunner(runnerId, 1, 2, 120);
      expect(claimed).toHaveLength(1);
      const dispatch = claimed[0]!;
      const acceptanceId = randomUUID();
      const body = JSON.stringify({
        acceptanceId,
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        leaseToken: dispatch.leaseToken,
      });
      const receiptSha256 = createHash("sha256").update(body).digest("hex");
      const input = {
        acceptanceId,
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256,
      };

      const first = await acceptanceRepo.record(input);
      expect(first.replayed).toBe(false);
      expect(first.acceptanceId).toBe(acceptanceId);

      const replay = await acceptanceRepo.record(input);
      expect(replay.replayed).toBe(true);
      expect(replay.eventId).toBe(first.eventId);

      await expect(acceptanceRepo.record({
        ...input,
        acceptanceId: randomUUID(),
        receiptSha256: "a".repeat(64),
      })).rejects.toBeInstanceOf(RunnerAcceptanceConflictError);

      const persisted = await setup.query<{
        receipt_count: string;
        event_count: string;
        event_actor: string;
      }>(
        `SELECT
           (SELECT count(*)::text FROM runner_dispatch_acceptances
            WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid) AS receipt_count,
           (SELECT count(*)::text FROM execution_evidence_events
            WHERE event_id = $3::uuid AND event_type = 'RUNNER_ACCEPTED') AS event_count,
           (SELECT actor_kind FROM execution_evidence_events WHERE event_id = $3::uuid) AS event_actor`,
        [dispatch.id, dispatch.leaseToken, first.eventId],
      );
      expect(persisted.rows[0]).toEqual({
        receipt_count: "1",
        event_count: "1",
        event_actor: "RUNNER",
      });

      await setup.query(
        "UPDATE runner_dispatch_outbox SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.id],
      );
      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.executionId],
      );
      await expect(acceptanceRepo.record({
        ...input,
        leaseToken: randomUUID(),
        acceptanceId: randomUUID(),
      })).rejects.toBeInstanceOf(RunnerAcceptanceStaleLeaseError);
    } finally {
      await setup.end();
    }
  }, 20_000);
});
