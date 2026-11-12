import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresExecutionJobRepository } from "./execution-job-repository";
import { PostgresExecutionEvidenceRepository } from "./execution-evidence-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const verifierConnections: Client[] = [];

afterAll(async () => {
  await Promise.all(verifierConnections.map((client) => client.end().catch(() => undefined)));
});

async function createRunningExecution(leaseSeconds = 60) {
  if (!databaseUrl) throw new Error("DATABASE_URL_REQUIRED");
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const jobs = new PostgresExecutionJobRepository(databaseUrl);
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action: "RUN",
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode: `public class Main { public static void main(String[] args) { System.out.println("ok"); } }`,
    correlationId: `evidence-${randomUUID()}`,
  }, `evidence-${randomUUID()}`);

  const claim = await jobs.claim(created.executionId, `runner-${randomUUID()}`, leaseSeconds);
  if (claim.status !== "CLAIMED") throw new Error("EXECUTION_CLAIM_FAILED");
  const running = await jobs.markRunning(
    created.executionId,
    claim.lease.leaseOwner,
    claim.lease.leaseToken,
  );
  if (!running) throw new Error("EXECUTION_START_FAILED");

  return { created, lease: claim.lease };
}

function makeResult(executionId: string, attemptId: string, leaseOwner: string, leaseToken: string) {
  const completedAt = new Date();
  const startedAt = new Date(completedAt.getTime() - 75);
  return {
    executionId,
    attemptId,
    leaseOwner,
    leaseToken,
    infrastructureStatus: "SUCCEEDED" as const,
    compilationStatus: "SUCCEEDED" as const,
    verdict: "ACCEPTED" as const,
    cleanupStatus: "SUCCEEDED" as const,
    testsTotal: 2,
    testsPassed: 2,
    elapsedMs: 75,
    peakMemoryBytes: 4_194_304,
    runnerVersion: "integration-test",
    runtimeImageDigest: "a".repeat(64),
    resultSha256: "b".repeat(64),
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
  };
}

describe.skipIf(!databaseUrl)("PostgresExecutionEvidenceRepository PostgreSQL integration", () => {
  it("persists immutable events and a lease-fenced result, then serves owner-scoped history", async () => {
    const { created, lease } = await createRunningExecution();
    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);
    const event = {
      eventId: randomUUID(),
      executionId: created.executionId,
      attemptId: created.attemptId,
      eventType: "RUNNER_STARTED" as const,
      actorKind: "RUNNER" as const,
      phaseStatus: "STARTED" as const,
    };

    const firstEvent = await evidence.appendEvent(event);
    const duplicateEvent = await evidence.appendEvent(event);
    expect(firstEvent.replayed).toBe(false);
    expect(duplicateEvent).toEqual({ ...firstEvent, replayed: true });

    const resultInput = makeResult(
      created.executionId,
      created.attemptId,
      lease.leaseOwner,
      lease.leaseToken,
    );
    const recorded = await evidence.recordResult(resultInput);
    const replayed = await evidence.recordResult(resultInput);
    expect(recorded.replayed).toBe(false);
    expect(replayed.replayed).toBe(true);
    expect(recorded.state).toBe("COMPLETED");

    const history = await evidence.listProblemAttemptHistory(tenantId, actorId, "two-sum");
    const entry = history.find((item) => item.executionId === created.executionId);
    expect(entry).toMatchObject({
      attemptId: created.attemptId,
      executionId: created.executionId,
      action: "RUN",
      language: "java",
      sourceByteLength: expect.any(Number),
      executionState: "COMPLETED",
      infrastructureStatus: "SUCCEEDED",
      compilationStatus: "SUCCEEDED",
      verdict: "ACCEPTED",
      cleanupStatus: "SUCCEEDED",
      testsTotal: 2,
      testsPassed: 2,
      resultSha256: resultInput.resultSha256,
    });
    expect(entry).not.toHaveProperty("sourceCode");

    const events = await evidence.listExecutionEvents(tenantId, actorId, created.executionId);
    expect(events.map((item) => item.eventType)).toEqual([
      "RUNNER_STARTED",
      "EXECUTION_FINISHED",
    ]);

    const outsiderHistory = await evidence.listProblemAttemptHistory(
      tenantId,
      "20000000-0000-4000-8000-000000000099",
      "two-sum",
    );
    expect(outsiderHistory.some((item) => item.executionId === created.executionId)).toBe(false);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-execution-evidence-integration-test",
    });
    verifierConnections.push(verifier);
    await verifier.connect();

    await expect(verifier.query(
      "UPDATE execution_result_records SET verdict = 'WRONG_ANSWER' WHERE execution_id = $1::uuid",
      [created.executionId],
    )).rejects.toMatchObject({ code: "55000" });

    await expect(verifier.query(
      "UPDATE execution_evidence_events SET phase_status = 'FAILED' WHERE event_id = $1::uuid",
      [event.eventId],
    )).rejects.toMatchObject({ code: "55000" });

    const persisted = await verifier.query<{
      state: string;
      result_count: string;
      event_count: string;
    }>(
      [
        "SELECT ej.state,",
        "  (SELECT count(*) FROM execution_result_records WHERE execution_id = ej.id)::text AS result_count,",
        "  (SELECT count(*) FROM execution_evidence_events WHERE execution_id = ej.id)::text AS event_count",
        "FROM execution_jobs AS ej WHERE ej.id = $1::uuid",
      ].join("\n"),
      [created.executionId],
    );
    expect(persisted.rows[0]).toEqual({
      state: "COMPLETED",
      result_count: "1",
      event_count: "2",
    });
  }, 15_000);

  it("rejects a result from an expired lease without writing terminal evidence", async () => {
    const { created, lease } = await createRunningExecution(30);
    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-execution-evidence-stale-lease-test",
    });
    verifierConnections.push(verifier);
    await verifier.connect();
    await verifier.query(
      "UPDATE execution_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1::uuid",
      [created.executionId],
    );

    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);
    await expect(evidence.recordResult(makeResult(
      created.executionId,
      created.attemptId,
      lease.leaseOwner,
      lease.leaseToken,
    ))).rejects.toThrow("execution_result_rejected_for_stale_or_invalid_lease");

    const result = await verifier.query<{ state: string; count: string }>(
      [
        "SELECT ej.state,",
        "  (SELECT count(*) FROM execution_result_records WHERE execution_id = ej.id)::text AS count",
        "FROM execution_jobs AS ej WHERE ej.id = $1::uuid",
      ].join("\n"),
      [created.executionId],
    );
    expect(result.rows[0]).toEqual({ state: "RUNNING", count: "0" });
  }, 15_000);
});
