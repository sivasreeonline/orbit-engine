import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PostgresExecutionEvidenceRepository } from "./execution-evidence-repository";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = randomUUID();
const otherActorId = randomUUID();

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

    const ownedSubmit = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "SUBMIT",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { int value = 10; }",
      correlationId: "timeline-owned-submit",
    }, `timeline-owned-submit-${randomUUID()}`);

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

    expect(timeline).toHaveLength(2);
    const runEntry = timeline.find((entry) => entry.attemptId === ownedAttempt.attemptId);
    const submitEntry = timeline.find((entry) => entry.attemptId === ownedSubmit.attemptId);
    expect(runEntry?.action).toBe("RUN");
    expect(submitEntry?.action).toBe("SUBMIT");
    expect(runEntry?.events.map((event) => event.eventId)).toEqual([firstEventId, secondEventId]);
    expect(runEntry?.events.map((event) => event.sequenceId)).toEqual(
      [...runEntry!.events.map((event) => event.sequenceId)].sort((a, b) => Number(a) - Number(b)),
    );
    expect(runEntry?.events.map((event) => event.eventType)).toEqual([
      "ATTEMPT_ACCEPTED", "JOB_QUEUED",
    ]);
    expect(submitEntry?.events).toEqual([]);
  });
});
