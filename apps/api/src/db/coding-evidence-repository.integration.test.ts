import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import {
  CodingEvidenceConflictError,
  CodingEvidenceSequenceConflictError,
  CodingEvidenceSessionClosedError,
  CodingEvidenceSessionNotFoundError,
  PostgresCodingEvidenceRepository,
  type CodingEvidenceRecordInput,
} from "./coding-evidence-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const outsiderId = "20000000-0000-4000-8000-000000000099";

function hash(source: string): string {
  return createHash("sha256").update(Buffer.from(source, "utf8")).digest("hex");
}

function makeEvent(
  sessionId: string,
  sequence: number,
  eventType: CodingEvidenceRecordInput["event"]["eventType"],
  fields: Partial<CodingEvidenceRecordInput["event"]> = {},
): CodingEvidenceRecordInput {
  return {
    event: {
      eventId: randomUUID(),
      sessionId,
      sequence,
      eventType,
      occurredAt: new Date().toISOString(),
      language: "java",
      ...fields,
    },
  };
}

function makeSnapshotRecord(
  sessionId: string,
  sequence: number,
  kind: "SESSION_START" | "PERIODIC" | "RUN" | "SUBMIT" | "SESSION_END",
  sourceCode: string,
): CodingEvidenceRecordInput {
  const snapshotId = randomUUID();
  const contentSha256 = hash(sourceCode);
  return {
    event: {
      eventId: randomUUID(),
      sessionId,
      sequence,
      eventType: "CODE_SNAPSHOT_CREATED",
      occurredAt: new Date().toISOString(),
      language: "java",
      snapshotId,
      contentSha256,
      metadata: { kind },
    },
    snapshot: {
      snapshotId,
      sessionId,
      sequence,
      kind,
      language: "java",
      sourceCode,
      sourceByteLength: Buffer.byteLength(sourceCode, "utf8"),
      contentSha256,
      capturedAt: new Date().toISOString(),
    },
  };
}

describe.skipIf(!databaseUrl)("PostgresCodingEvidenceRepository PostgreSQL integration", () => {
  it("creates owner-scoped sessions and appends immutable, idempotent, ordered editor evidence", async () => {
    const repository = new PostgresCodingEvidenceRepository(databaseUrl);
    const principal = { tenantId, userId: actorId, roles: ["STUDENT"] };
    const created = await repository.createSession({
      principal,
      problemSlug: "two-sum",
      language: "java",
      noticeVersion: "notice-v1",
    });

    expect(created.sessionId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(created.lastSequence).toBe(0);

    const start = makeEvent(created.sessionId, 1, "SESSION_STARTED", {
      metadata: { captureMode: "in-memory-preview" },
    });
    const initialSnapshot = makeSnapshotRecord(
      created.sessionId, 2, "SESSION_START", "public class Main {}",
    );
    const checkpoint = makeEvent(created.sessionId, 3, "CHECKPOINT_RECORDED", {
      snapshotId: initialSnapshot.snapshot!.snapshotId,
      contentSha256: initialSnapshot.snapshot!.contentSha256,
      metadata: { unchangedSincePreviousSnapshot: true },
    });
    const initialBatch = [start, initialSnapshot, checkpoint];

    const first = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: initialBatch,
    });
    expect(first).toEqual({
      accepted: 3,
      replayed: 0,
      sequenceGaps: [],
      lastSequence: 3,
      sessionEnded: false,
    });

    const replay = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: initialBatch,
    });
    expect(replay).toEqual({
      accepted: 0,
      replayed: 3,
      sequenceGaps: [],
      lastSequence: 3,
      sessionEnded: false,
    });

    const changedSameId = {
      ...start,
      event: { ...start.event, metadata: { captureMode: "tampered-replay" } },
    };
    await expect(repository.appendBatch({
      principal, sessionId: created.sessionId, events: [changedSameId],
    })).rejects.toBeInstanceOf(CodingEvidenceConflictError);

    const changedSequence = makeEvent(created.sessionId, 3, "CHECKPOINT_RECORDED");
    await expect(repository.appendBatch({
      principal, sessionId: created.sessionId, events: [changedSequence],
    })).rejects.toBeInstanceOf(CodingEvidenceSequenceConflictError);

    const gap = makeEvent(created.sessionId, 5, "CHECKPOINT_RECORDED");
    const gapResult = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: [gap],
    });
    expect(gapResult.sequenceGaps).toEqual([5]);
    expect(gapResult.lastSequence).toBe(5);

    const runSnapshot = makeSnapshotRecord(
      created.sessionId, 6, "RUN", "public class Main { public static void main(String[] args) {} }",
    );
    const runRequested = makeEvent(created.sessionId, 7, "RUN_REQUESTED", {
      snapshotId: runSnapshot.snapshot!.snapshotId,
      contentSha256: runSnapshot.snapshot!.contentSha256,
    });
    const runResult = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: [runSnapshot, runRequested],
    });
    expect(runResult.accepted).toBe(2);
    expect(runResult.lastSequence).toBe(7);

    const ended = makeEvent(created.sessionId, 8, "SESSION_ENDED", {
      snapshotId: runSnapshot.snapshot!.snapshotId,
      contentSha256: runSnapshot.snapshot!.contentSha256,
    });
    const endResult = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: [ended],
    });
    expect(endResult.sessionEnded).toBe(true);
    expect(endResult.lastSequence).toBe(8);

    await expect(repository.appendBatch({
      principal,
      sessionId: created.sessionId,
      events: [makeEvent(created.sessionId, 9, "CHECKPOINT_RECORDED")],
    })).rejects.toBeInstanceOf(CodingEvidenceSessionClosedError);

    await expect(repository.appendBatch({
      principal: { ...principal, userId: outsiderId },
      sessionId: created.sessionId,
      events: [start],
    })).rejects.toBeInstanceOf(CodingEvidenceSessionNotFoundError);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-coding-evidence-integration-test",
    });
    await verifier.connect();
    try {
      await expect(verifier.query(
        "UPDATE coding_evidence_events SET metadata = '{}'::jsonb WHERE event_id = $1::uuid",
        [start.event.eventId],
      )).rejects.toMatchObject({ code: "55000" });

      const persisted = await verifier.query<{
        status: string;
        last_sequence: string;
        event_count: string;
        snapshot_count: string;
        source_byte_length: string;
      }>(
        [
          "SELECT session.status, session.last_sequence::text AS last_sequence,",
          "  (SELECT count(*) FROM coding_evidence_events WHERE session_id = session.id)::text AS event_count,",
          "  (SELECT count(*) FROM editor_code_snapshots WHERE session_id = session.id)::text AS snapshot_count,",
          "  (SELECT byte_length::text FROM source_snapshots",
          "   WHERE id = (SELECT source_snapshot_id FROM editor_code_snapshots",
          "             WHERE session_id = session.id ORDER BY sequence LIMIT 1)) AS source_byte_length",
          "FROM coding_evidence_sessions AS session WHERE session.id = $1::uuid",
        ].join("\n"),
        [created.sessionId],
      );
      expect(persisted.rows[0]).toEqual({
        status: "ENDED",
        last_sequence: "8",
        event_count: "7",
        snapshot_count: "2",
        source_byte_length: String(Buffer.byteLength("public class Main {}", "utf8")),
      });
    } finally {
      await verifier.end();
    }
  }, 15_000);

  it("rejects an editor snapshot whose claimed hash differs from its source bytes", async () => {
    const repository = new PostgresCodingEvidenceRepository(databaseUrl);
    const principal = { tenantId, userId: actorId, roles: ["STUDENT"] };
    const created = await repository.createSession({
      principal,
      problemSlug: "two-sum",
      language: "python",
      noticeVersion: "notice-v1",
    });
    const start = makeEvent(created.sessionId, 1, "SESSION_STARTED", { language: "python" });
    await repository.appendBatch({ principal, sessionId: created.sessionId, events: [start] });

    const record = makeSnapshotRecord(created.sessionId, 2, "SESSION_START", "print('hello')");
    const snapshot = record.snapshot;
    if (!snapshot) throw new Error("TEST_SNAPSHOT_MISSING");
    const tampered = {
      ...record,
      snapshot: { ...snapshot, sourceCode: "print('tampered')" },
    };
    await expect(repository.appendBatch({
      principal, sessionId: created.sessionId, events: [tampered],
    })).rejects.toThrow("editor_code_snapshot_hash_mismatch");

    const untouched = await repository.appendBatch({
      principal, sessionId: created.sessionId, events: [record],
    });
    expect(untouched.accepted).toBe(1);
    expect(untouched.lastSequence).toBe(2);
  }, 15_000);
});
