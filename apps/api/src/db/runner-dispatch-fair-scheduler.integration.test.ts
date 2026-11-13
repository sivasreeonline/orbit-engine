import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const firstActorId = "20000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("fair runner dispatch scheduler PostgreSQL integration", () => {
  it("rotates competing student lanes and preserves one-per-student batch fairness", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const secondActorId = randomUUID();
    const actors = [firstActorId, secondActorId];

    // Retire pending fixtures from other integration suites in this disposable DB.
    const leftovers = await leases.claimBatch("fair-test-cleanup", 100, 60);
    await Promise.all(leftovers.map((item) =>
      leases.markDeadLetter(item.id, "fair-test-cleanup", item.leaseToken),
    ));

    const createdByActor = new Map<string, string[]>();
    for (const actorId of actors) {
      const attemptIds: string[] = [];
      for (let index = 0; index < 2; index += 1) {
        const created = await intake.create({
          principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
          action: "RUN",
          problemSlug: "two-sum",
          language: "java",
          runtimeVersion: "25",
          sourceCode: `public class Main { // ${actorId}-${index}-${randomUUID()} }\n`,
          correlationId: `fair-scheduler-${randomUUID()}`,
        }, `fair-scheduler-${randomUUID()}`);
        attemptIds.push(created.attemptId);
        await handoff.record({
          executionId: created.executionId,
          attemptId: created.attemptId,
          protocolVersion: "v1",
        });
      }
      createdByActor.set(actorId, attemptIds);
    }

    // Concurrent schedulers lock separate least-served lane rows. A single
    // student's two-job burst cannot consume both one-slot claims.
    const [firstClaim, secondClaim] = await Promise.all([
      leases.claimFairBatch("fair-dispatcher-a", 1, 30),
      leases.claimFairBatch("fair-dispatcher-b", 1, 30),
    ]);
    expect(firstClaim).toHaveLength(1);
    expect(secondClaim).toHaveLength(1);

    const firstTwo = [firstClaim[0]!, secondClaim[0]!];
    const ownerByAttempt = new Map<string, string>();
    for (const [actorId, attemptIds] of createdByActor) {
      for (const attemptId of attemptIds) ownerByAttempt.set(attemptId, actorId);
    }
    const firstOwners = firstTwo.map((item) => ownerByAttempt.get(item.attemptId));
    expect(new Set(firstOwners)).toEqual(new Set(actors));

    const nextRound = await leases.claimFairBatch("fair-dispatcher-c", 2, 30);
    expect(nextRound).toHaveLength(2);
    const firstAttemptIds = new Set(firstTwo.map((item) => item.attemptId));
    expect(nextRound.every((item) => !firstAttemptIds.has(item.attemptId))).toBe(true);
    expect(new Set(nextRound.map((item) => ownerByAttempt.get(item.attemptId))))
      .toEqual(new Set(actors));

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-fair-dispatch-integration-test",
    });
    try {
      await verifier.connect();
      const lanes = await verifier.query<{
        actor_user_id: string;
        last_served_ticket: string;
      }>(
        `SELECT actor_user_id::text, last_served_ticket::text
         FROM runner_dispatch_scheduler_lanes
         WHERE tenant_id = $1::uuid AND actor_user_id = ANY($2::uuid[])`,
        [tenantId, actors],
      );
      expect(lanes.rows).toHaveLength(2);
      expect(new Set(lanes.rows.map((row) => row.last_served_ticket)).size).toBe(2);
      expect(lanes.rows.every((row) => BigInt(row.last_served_ticket) > 0n)).toBe(true);
    } finally {
      await verifier.end();
    }

    await Promise.all([...firstTwo, ...nextRound].map((item, index) =>
      leases.markDeadLetter(
        item.id,
        index === 0 ? "fair-dispatcher-a" :
          index === 1 ? "fair-dispatcher-b" : "fair-dispatcher-c",
        item.leaseToken,
      ),
    ));
  }, 20_000);

  it("serializes concurrent runner polls and enforces the per-runner active lease cap", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const runnerId = randomUUID();
    const secondActorId = randomUUID();
    const actors = [firstActorId, secondActorId];

    const leftovers = await leases.claimBatch("runner-capacity-cleanup", 100, 60);
    await Promise.all(leftovers.map((item) =>
      leases.markDeadLetter(item.id, "runner-capacity-cleanup", item.leaseToken),
    ));

    for (const actorId of actors) {
      for (let index = 0; index < 2; index += 1) {
        const created = await intake.create({
          principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
          action: "RUN",
          problemSlug: "two-sum",
          language: "java",
          runtimeVersion: "25",
          sourceCode: `public class Main { // capacity-${runnerId}-${actorId}-${index} }\n`,
          correlationId: `runner-capacity-${randomUUID()}`,
        }, `runner-capacity-${randomUUID()}`);
        await handoff.record({
          executionId: created.executionId,
          attemptId: created.attemptId,
          protocolVersion: "v1",
        });
      }
    }

    const [firstPoll, concurrentPoll] = await Promise.all([
      leases.claimFairBatchForRunner(runnerId, 2, 2, 60),
      leases.claimFairBatchForRunner(runnerId, 2, 2, 60),
    ]);
    const combined = [...firstPoll, ...concurrentPoll];
    expect(combined.length).toBe(2);
    expect(new Set(combined.map((item) => item.id)).size).toBe(2);

    const thirdPoll = await leases.claimFairBatchForRunner(runnerId, 2, 2, 60);
    expect(thirdPoll).toHaveLength(0);

    await Promise.all(combined.map((item) =>
      leases.markDeadLetter(item.id, runnerId, item.leaseToken),
    ));
  }, 20_000);
});
