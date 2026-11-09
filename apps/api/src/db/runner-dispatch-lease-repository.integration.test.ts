import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository, RunnerDispatchReceiptConflictError, StaleRunnerDispatchLeaseError } from "./runner-dispatch-lease-repository";

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
    const receiptId = randomUUID();
    const receiptHash = createHash("sha256")
      .update(JSON.stringify({
        dispatchId: reclaimed[0]!.id,
        executionId: reclaimed[0]!.executionId,
        attemptId: reclaimed[0]!.attemptId,
        runnerId: "dispatcher-c",
        receiptId,
      }))
      .digest("hex");

    await expect(leases.recordReceipt(
      original.id, oldWorker, original.leaseToken, randomUUID(), receiptHash,
    )).rejects.toBeInstanceOf(StaleRunnerDispatchLeaseError);
    const receiptReplays = await Promise.all(Array.from({ length: 8 }, () =>
      leases.recordReceipt(
        reclaimed[0]!.id, "dispatcher-c", reclaimed[0]!.leaseToken, receiptId, receiptHash,
      ),
    ));
    expect(receiptReplays.filter((result) => result.status === "RECORDED")).toHaveLength(1);
    expect(receiptReplays.filter((result) => result.status === "DUPLICATE")).toHaveLength(7);
    await expect(leases.recordReceipt(
      reclaimed[0]!.id, "dispatcher-c", reclaimed[0]!.leaseToken, randomUUID(), receiptHash,
    )).rejects.toBeInstanceOf(RunnerDispatchReceiptConflictError);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-runner-dispatch-lease-integration-test",
    });
    try {
      await verifier.connect();
      const state = await verifier.query<{
        delivery_state: string;
        lease_owner: string | null;
        receipt_count: string;
        receipt_id: string;
      }>(
        [
          "SELECT dispatch.delivery_state, dispatch.lease_owner,",
          "  count(receipt.id)::text AS receipt_count, max(receipt.receipt_id) AS receipt_id",
          "FROM runner_dispatch_outbox AS dispatch",
          "LEFT JOIN runner_dispatch_receipts AS receipt ON receipt.dispatch_id = dispatch.id",
          "WHERE dispatch.id = $1::uuid",
          "GROUP BY dispatch.id",
        ].join("\n"),
        [original.id],
      );
      expect(state.rows[0]).toEqual({
        delivery_state: "DELIVERED", lease_owner: null,
        receipt_count: "1", receipt_id: receiptId,
      });
    } finally {
      await verifier.end();
    }
  }, 15_000);
});
