import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { InvalidRunnerDispatchEnvelopeError, PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const connections: Client[] = [];

afterAll(async () => {
  await Promise.all(connections.map((client) => client.end().catch(() => undefined)));
});

describe.skipIf(!databaseUrl)("runner dispatch handoff PostgreSQL integration", () => {
  it("records exactly one durable intent for concurrent duplicate queue deliveries", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const created = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `handoff-${randomUUID()}`,
    }, `handoff-${randomUUID()}`);

    const envelope = {
      executionId: created.executionId,
      attemptId: created.attemptId,
      protocolVersion: "v1",
    };
    const results = await Promise.all(Array.from({ length: 12 }, () => handoff.record(envelope)));
    expect(results.filter((result) => result.status === "RECORDED")).toHaveLength(1);
    expect(results.filter((result) => result.status === "DUPLICATE")).toHaveLength(11);
    expect(new Set(results.map((result) => result.dispatchId)).size).toBe(1);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-runner-handoff-integration-test",
    });
    connections.push(verifier);
    await verifier.connect();
    const persisted = await verifier.query<{
      count: string;
      attempt_id: string;
      delivery_state: string;
    }>(
      [
        "SELECT count(*)::text AS count, min(attempt_id)::text AS attempt_id,",
        "  min(delivery_state) AS delivery_state",
        "FROM runner_dispatch_outbox WHERE execution_id = $1::uuid",
      ].join("\n"),
      [created.executionId],
    );
    expect(persisted.rows[0]).toEqual({
      count: "1",
      attempt_id: created.attemptId,
      delivery_state: "PENDING",
    });

    await expect(handoff.record({
      ...envelope,
      attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
    })).rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
  }, 15_000);
});
