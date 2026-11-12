import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PostgresExecutionEvidenceRepository } from "./execution-evidence-repository";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const otherActorId = "20000000-0000-4000-8000-000000000002";

describe.skipIf(!databaseUrl)("Postgres execution attempt timeline integration", () => {
  it("returns each student's attempts with ordered events and excludes another student's activity", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const evidence = new PostgresExecutionEvidenceRepository(databaseUrl);

    const ownedAttempt = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 1; }",
      correlationId: "timeline-owned",
    }, `timeline-owned-${randomUUID()}`);

    const otherAttempt = await intake.create({
      principal: { tenantId, userId: otherActorId, roles: ["STUDENT"] },
      action: "SUBMIT",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 2; }",
      correlationId: "timeline-other",
    }, `timeline-other-${randomUUID()}`);

    const firstEventId = randomUUID();
    const secondEventId = randomUUID();
    await evidence.appendEvent({
      eventId: firstEventId,
      executionId: ownedAttempt.executionId,
      attemptId: ownedAttempt.attemptId,
      eventType: "ATTEMPT_ACCEPTED",
      actorKind: "API",
      phaseStatus: "SUCCEEDED",
    });
    await evidence.appendEvent({
      eventId: secondEventId,
      executionId: ownedAttempt.executionId,
      attemptId: ownedAttempt.attemptId,
      eventType: "JOB_QUEUED",
      actorKind: "QUEUE",
      phaseStatus: "SUCCEEDED",
    });
    await evidence.appendEvent({
      eventId: randomUUID(),
      executionId: otherAttempt.executionId,
      attemptId: otherAttempt.attemptId,
      eventType: "ATTEMPT_ACCEPTED",
      actorKind: "API",
      phaseStatus: "SUCCEEDED",
    });

    const timeline = await evidence.listProblemAttemptTimeline(
      tenantId, actorId, "two-sum", 100,
    );

    expect(timeline).toHaveLength(1);
    expect(timeline[0]?.attemptId).toBe(ownedAttempt.attemptId);
    expect(timeline[0]?.events.map((event) => event.eventId)).toEqual([
      firstEventId, secondEventId,
    ]);
    expect(timeline[0]?.events.map((event) => event.sequenceId)).toEqual(
      [...timeline[0]!.events.map((event) => event.sequenceId)].sort((a, b) => Number(a) - Number(b)),
    );
    expect(timeline[0]?.events.map((event) => event.eventType)).toEqual([
      "ATTEMPT_ACCEPTED", "JOB_QUEUED",
    ]);
  });
});
