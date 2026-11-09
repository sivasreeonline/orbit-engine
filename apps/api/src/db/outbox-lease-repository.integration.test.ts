import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresOutboxLeaseRepository } from "./outbox-lease-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("PostgresOutboxLeaseRepository PostgreSQL integration", () => {
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

    const expiredCandidate = (await outbox.claimBatch("publisher-c", 1, 1))[0];
    expect(expiredCandidate).toBeDefined();

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
