import { Client } from "pg";
import { randomUUID } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const createdConnections: Client[] = [];

afterAll(async () => {
  await Promise.all(createdConnections.map((client) => client.end().catch(() => undefined)));
});

describe.skipIf(!databaseUrl)("PostgresExecutionIntakeRepository PostgreSQL integration", () => {
  it("serializes concurrent same-key requests into exactly one persisted execution", async () => {
    const idempotencyKey = `integration-${randomUUID()}`;
    const repository = new PostgresExecutionIntakeRepository(databaseUrl);
    const requests = Array.from({ length: 12 }, (_, index) =>
      repository.create({
        principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        runtimeVersion: "25",
        sourceCode: "public class Main { public static void main(String[] args) {} }",
        correlationId: `integration-${index}`,
      }, idempotencyKey),
    );

    const results = await Promise.all(requests);
    const executionIds = new Set(results.map((result) => result.executionId));
    const attemptIds = new Set(results.map((result) => result.attemptId));

    expect(executionIds.size).toBe(1);
    expect(attemptIds.size).toBe(1);
    expect(results.filter((result) => !result.replayed)).toHaveLength(1);
    expect(results.filter((result) => result.replayed)).toHaveLength(11);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-execution-intake-integration-test",
    });
    createdConnections.push(verifier);
    await verifier.connect();
    const persisted = await verifier.query<{
      attempt_count: string;
      snapshot_count: string;
      job_count: string;
      outbox_count: string;
    }>(
      [
        "SELECT",
        "  count(DISTINCT ea.id)::text AS attempt_count,",
        "  count(DISTINCT ss.id)::text AS snapshot_count,",
        "  count(DISTINCT ej.id)::text AS job_count,",
        "  count(DISTINCT eo.id)::text AS outbox_count",
        "FROM execution_idempotency AS ei",
        "INNER JOIN execution_attempts AS ea ON ea.id = ei.attempt_id",
        "INNER JOIN source_snapshots AS ss ON ss.id = ea.source_snapshot_id",
        "INNER JOIN execution_jobs AS ej ON ej.attempt_id = ea.id",
        "INNER JOIN execution_outbox AS eo ON eo.execution_id = ej.id",
        "WHERE ei.tenant_id = $1::uuid AND ei.actor_user_id = $2::uuid",
        "  AND ei.endpoint = 'RUN' AND ei.idempotency_key = $3",
      ].join("\n"),
      [tenantId, actorId, idempotencyKey],
    );

    expect(persisted.rows[0]).toEqual({
      attempt_count: "1",
      snapshot_count: "1",
      job_count: "1",
      outbox_count: "1",
    });

    await expect(repository.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) { } }",
      correlationId: "integration-conflict",
    }, idempotencyKey)).rejects.toThrow("idempotency_key_reused_with_different_request");
  });
});
