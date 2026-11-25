import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import { Client } from "pg";
import { PostgresOutboxLeaseRepository } from "./outbox-lease-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("PostgresOutboxLeaseRepository PostgreSQL integration", () => {

  it("keeps v2 execution outbox rows pending and unleased by the v1 publisher", async () => {
    const policy: ExecutionProtocolV2Policy = {
      policyRevision: "v2-outbox-publication-gate-integration",
      runtimeImageDigests: {
        java: `sha256:${"1".repeat(64)}`,
        python: `sha256:${"2".repeat(64)}`,
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
    };
    const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, policy);
    const outbox = new PostgresOutboxLeaseRepository(databaseUrl);
    const created = await intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `v2-outbox-gate-${randomUUID()}`,
    }, `v2-outbox-gate-${randomUUID()}`);

    const claimed = await outbox.claimBatch("v2-publication-gate", 100, 60);
    expect(claimed.some((lease) => lease.executionId === created.executionId)).toBe(false);
    expect(claimed.every((lease) => lease.protocolVersion === "v1")).toBe(true);
    await Promise.all(claimed.map((lease) =>
      outbox.markPublished(lease.id, "v2-publication-gate", lease.leaseToken),
    ));

    const verifier = new Client({ connectionString: databaseUrl });
    await verifier.connect();
    try {
      const persisted = await verifier.query<{
        protocol_version: string;
        delivery_state: string;
        lease_owner: string | null;
        lease_token: string | null;
      }>(
        "SELECT protocol_version, delivery_state, lease_owner, lease_token::text AS lease_token FROM execution_outbox WHERE execution_id = $1::uuid",
        [created.executionId],
      );
      expect(persisted.rows).toEqual([{
        protocol_version: "v2",
        delivery_state: "PENDING",
        lease_owner: null,
        lease_token: null,
      }]);
    } finally {
      await verifier.end();
    }
  }, 15_000);

  it("coordinates concurrent publishers and fences a worker after lease expiry", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const outbox = new PostgresOutboxLeaseRepository(databaseUrl);
    const create = (suffix: string) => intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: `public class Main { // ${suffix} }\n`,
      correlationId: `outbox-${suffix}`,
    }, `outbox-${randomUUID()}`);

    await Promise.all([create("one"), create("two"), create("three")]);

    const [firstBatch, secondBatch] = await Promise.all([
      outbox.claimBatch("publisher-a", 1, 1),
      outbox.claimBatch("publisher-b", 1, 1),
    ]);
    expect(firstBatch).toHaveLength(1);
    expect(secondBatch).toHaveLength(1);
    expect(firstBatch[0]?.id).not.toBe(secondBatch[0]?.id);
    expect(firstBatch.every((lease) => lease.protocolVersion === "v1")).toBe(true);
    expect(secondBatch.every((lease) => lease.protocolVersion === "v1")).toBe(true);

    await expect(outbox.markPublished(
      firstBatch[0]!.id, "publisher-a", firstBatch[0]!.leaseToken,
    )).resolves.toBe(true);
    await expect(outbox.markPublished(
      secondBatch[0]!.id, "publisher-b", secondBatch[0]!.leaseToken,
    )).resolves.toBe(true);

    // Drain any other pending rows in this disposable database so only the
    // deliberately expiring lease can be reclaimed in the assertion below.
    const remaining = await outbox.claimBatch("publisher-c", 100, 1);
    expect(remaining.length).toBeGreaterThan(0);
    const [expiredCandidate, ...otherClaims] = remaining;
    await Promise.all(otherClaims.map((lease) =>
      outbox.markPublished(lease.id, "publisher-c", lease.leaseToken),
    ));

    await new Promise((resolve) => setTimeout(resolve, 1_150));
    const reclaimed = await outbox.claimBatch("publisher-d", 1, 30);
    expect(reclaimed).toHaveLength(1);
    expect(reclaimed[0]?.id).toBe(expiredCandidate?.id);
    expect(reclaimed[0]?.leaseToken).not.toBe(expiredCandidate?.leaseToken);

    await expect(outbox.markPublished(
      expiredCandidate!.id, "publisher-c", expiredCandidate!.leaseToken,
    )).resolves.toBe(false);
    await expect(outbox.markPublished(
      reclaimed[0]!.id, "publisher-d", reclaimed[0]!.leaseToken,
    )).resolves.toBe(true);
  }, 10_000);
});
