import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("runner dispatch lease PostgreSQL integration", () => {
  it("coordinates competing dispatchers, reclaims expiry and rejects stale acknowledgement", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);

    // The disposable CI database also contains the SQL-acceptance and handoff
    // integration fixtures. Retire their pending intents so this test owns one row.
    const leftovers = await leases.claimBatch("integration-cleanup", 100, 60);
    await Promise.all(leftovers.map((lease) =>
      leases.markDeadLetter(lease.id, "integration-cleanup", lease.leaseToken),
    ));

    const created = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `dispatch-lease-${randomUUID()}`,
    }, `dispatch-lease-${randomUUID()}`);
    await handoff.record({
      executionId: created.executionId,
      attemptId: created.attemptId,
      protocolVersion: "v1",
    });

    const [firstBatch, secondBatch] = await Promise.all([
      leases.claimBatch("dispatcher-a", 1, 1),
      leases.claimBatch("dispatcher-b", 1, 1),
    ]);
    expect(firstBatch.length + secondBatch.length).toBe(1);
    const original = firstBatch[0] ?? secondBatch[0];
    if (!original) throw new Error("expected_one_dispatch_lease");

    await new Promise((resolve) => setTimeout(resolve, 1_150));
    const reclaimed = await leases.claimBatch("dispatcher-c", 1, 30);
    expect(reclaimed).toHaveLength(1);
    expect(reclaimed[0]?.id).toBe(original.id);
    expect(reclaimed[0]?.leaseToken).not.toBe(original.leaseToken);

    const oldWorker = firstBatch.length ? "dispatcher-a" : "dispatcher-b";
    await expect(leases.markDelivered(original.id, oldWorker, original.leaseToken)).resolves.toBe(false);
    await expect(leases.markDelivered(
      reclaimed[0]!.id, "dispatcher-c", reclaimed[0]!.leaseToken,
    )).resolves.toBe(true);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-runner-dispatch-lease-integration-test",
    });
    try {
      await verifier.connect();
      const state = await verifier.query<{ delivery_state: string; lease_owner: string | null }>(
        "SELECT delivery_state, lease_owner FROM runner_dispatch_outbox WHERE id = $1::uuid",
        [original.id],
      );
      expect(state.rows[0]).toEqual({ delivery_state: "DELIVERED", lease_owner: null });
    } finally {
      await verifier.end();
    }
  }, 15_000);
});
