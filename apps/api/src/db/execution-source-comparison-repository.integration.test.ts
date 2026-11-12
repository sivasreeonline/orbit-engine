import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import {
  ExecutionSourceComparisonNotFoundError,
  PostgresExecutionSourceComparisonRepository,
} from "./execution-source-comparison-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const otherActorId = "20000000-0000-4000-8000-000000000002";

describe.skipIf(!databaseUrl)("PostgresExecutionSourceComparisonRepository PostgreSQL integration", () => {
  it("compares immutable attempts for their owner and hides attempts belonging to another actor", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const comparison = new PostgresExecutionSourceComparisonRepository(databaseUrl);

    const base = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 1; }",
      correlationId: "source-compare-base",
    }, `source-compare-base-${randomUUID()}`);

    const target = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 2; }",
      correlationId: "source-compare-target",
    }, `source-compare-target-${randomUUID()}`);

    const foreign = await intake.create({
      principal: { tenantId, userId: otherActorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 3; }",
      correlationId: "source-compare-foreign",
    }, `source-compare-foreign-${randomUUID()}`);

    const result = await comparison.getComparableAttemptSources(
      tenantId, actorId, base.attemptId, target.attemptId,
    );

    expect(result.base.sourceCode).toBe("public class Main { int value = 1; }");
    expect(result.target.sourceCode).toBe("public class Main { int value = 2; }");
    expect(result.base.sourceSha256).not.toBe(result.target.sourceSha256);

    await expect(comparison.getComparableAttemptSources(
      tenantId, actorId, base.attemptId, foreign.attemptId,
    )).rejects.toBeInstanceOf(ExecutionSourceComparisonNotFoundError);
  });
});
