import { describe, expect, it, vi } from "vitest";
import type { CapturedEvidence } from "./EditorEvidenceCollector";
import {
  CodingEvidenceApiClient,
  CodingEvidenceSyncQueue,
} from "./CodingEvidenceApiClient";

const sessionId = "91000000-0000-4000-8000-000000000099";

function makeRecord(sequence: number, eventType = "CHECKPOINT_RECORDED"): CapturedEvidence {
  return {
    event: {
      schemaVersion: 1,
      eventId: `92000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
      sessionId,
      sequence,
      eventType: eventType as CapturedEvidence["event"]["eventType"],
      occurredAt: "2026-11-13T05:00:00.000Z",
      problemId: "two-sum",
      problemVersion: "1",
      language: "java",
    },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Correlation-ID": "evidence-test" },
  });
}

function acknowledgement(events: readonly CapturedEvidence[], extras: Record<string, unknown> = {}) {
  return {
    data: {
      accepted: events.length,
      replayed: 0,
      sequenceGaps: [],
      lastSequence: events.at(-1)?.event.sequence ?? 0,
      sessionEnded: false,
      ...extras,
    },
  };
}

describe("CodingEvidenceApiClient", () => {
  it("creates an authenticated server-owned evidence session with the requested capture notice", async () => {
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({
        data: {
          sessionId,
          startedAt: "2026-11-13T05:00:00.000Z",
          lastSequence: 0,
          capturePolicy: {
            changedSnapshotIntervalSeconds: 120,
            checkpointIntervalSeconds: 300,
          },
        },
      }, 201),
    );
    const client = new CodingEvidenceApiClient({
      fetchImpl: fetchImpl as typeof fetch,
      getHeaders: () => ({ Authorization: "Bearer test-session-token" }),
    });

    const created = await client.createSession({
      problemSlug: "two-sum",
      language: "java",
      noticeVersion: "notice-v1",
    });

    expect(created.sessionId).toBe(sessionId);
    expect(created.lastSequence).toBe(0);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/evidence/sessions");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(init?.redirect).toBe("error");
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBe("Bearer test-session-token");
    expect(JSON.parse(String(init?.body))).toEqual({
      problemSlug: "two-sum",
      language: "java",
      noticeVersion: "notice-v1",
    });
  });

  it("sends event and immutable snapshot bytes as one bounded batch", async () => {
    const sourceCode = "public class Main {}";
    const eventRecord: CapturedEvidence = {
      event: {
        ...makeRecord(2, "CODE_SNAPSHOT_CREATED").event,
        snapshotId: "93000000-0000-4000-8000-000000000001",
        contentSha256: "a".repeat(64),
      },
      snapshot: {
        snapshotId: "93000000-0000-4000-8000-000000000001",
        sessionId,
        sequence: 2,
        problemId: "two-sum",
        problemVersion: "1",
        language: "java",
        kind: "PERIODIC",
        sourceCode,
        sourceByteLength: new TextEncoder().encode(sourceCode).byteLength,
        contentSha256: "a".repeat(64),
        capturedAt: "2026-11-13T05:02:00.000Z",
      },
    };
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse(acknowledgement([eventRecord])),
    );
    const client = new CodingEvidenceApiClient({ fetchImpl: fetchImpl as typeof fetch });

    const result = await client.appendBatch(sessionId, [eventRecord]);

    expect(result.accepted).toBe(1);
    const [url, init] = fetchImpl.mock.calls[0] ?? [];
    expect(url).toBe(`/api/v1/evidence/sessions/${sessionId}/events`);
    const body = JSON.parse(String(init?.body)) as {
      events: Array<{ event: { sequence: number }; snapshot: { sourceCode: string } }>;
    };
    expect(body.events).toHaveLength(1);
    expect(body.events[0]?.event.sequence).toBe(2);
    expect(body.events[0]?.snapshot.sourceCode).toBe(sourceCode);
  });

  it("rejects invalid server session and event acknowledgements", async () => {
    const invalidSessionFetch = vi.fn(async () => jsonResponse({
      data: {
        sessionId: "not-a-uuid",
        startedAt: "not-a-date",
        lastSequence: -1,
        capturePolicy: { changedSnapshotIntervalSeconds: 1, checkpointIntervalSeconds: 1 },
      },
    }, 201));
    const client = new CodingEvidenceApiClient({
      fetchImpl: invalidSessionFetch as unknown as typeof fetch,
    });
    await expect(client.createSession({
      problemSlug: "two-sum", language: "java", noticeVersion: "notice-v1",
    })).rejects.toThrow("invalid_coding_evidence_session_response");

    const wrongAckFetch = vi.fn(async () => jsonResponse({
      data: { accepted: 0, replayed: 0, sequenceGaps: [], lastSequence: 0, sessionEnded: false },
    }));
    const wrongAckClient = new CodingEvidenceApiClient({
      fetchImpl: wrongAckFetch as unknown as typeof fetch,
    });
    await expect(wrongAckClient.appendBatch(sessionId, [makeRecord(1, "SESSION_STARTED")]))
      .rejects.toThrow("coding_evidence_acknowledgement_count_mismatch");
  });

  it("surfaces structured authorization and service errors without hiding retryability", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({
      error: {
        code: "AUTH_PROVIDER_NOT_CONFIGURED",
        message: "Authentication is not connected.",
        retryable: false,
      },
      correlationId: "auth-not-configured",
    }, 503));
    const client = new CodingEvidenceApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await expect(client.createSession({
      problemSlug: "two-sum", language: "java", noticeVersion: "notice-v1",
    })).rejects.toMatchObject({
      status: 503,
      code: "AUTH_PROVIDER_NOT_CONFIGURED",
      retryable: false,
      correlationId: "auth-not-configured",
    });
  });
});

describe("CodingEvidenceSyncQueue", () => {
  it("retains an unacknowledged batch and retries identical event IDs after a lost response", async () => {
    const first = makeRecord(1, "SESSION_STARTED");
    const second = makeRecord(2, "CODE_SNAPSHOT_CREATED");
    const capturedBodies: string[] = [];
    let calls = 0;
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBodies.push(String(init?.body));
      calls += 1;
      if (calls === 1) {
        return jsonResponse({
          error: {
            code: "DATABASE_UNAVAILABLE",
            message: "Retry later.",
            retryable: true,
          },
          correlationId: "db-retry",
        }, 503);
      }
      return jsonResponse(acknowledgement([first, second], { accepted: 0, replayed: 2 }));
    });
    const client = new CodingEvidenceApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const queue = new CodingEvidenceSyncQueue(client, sessionId);
    queue.enqueue(first);
    queue.enqueue(second);

    await expect(queue.flush()).rejects.toMatchObject({
      code: "DATABASE_UNAVAILABLE",
      retryable: true,
    });
    expect(queue.getPendingCount()).toBe(2);

    const retried = await queue.flush();
    expect(retried[0]?.replayed).toBe(2);
    expect(queue.getPendingCount()).toBe(0);
    expect(capturedBodies).toHaveLength(2);
    expect(capturedBodies[0]).toBe(capturedBodies[1]);
  });

  it("batches at most twenty events and rejects records from another session", async () => {
    const records = Array.from({ length: 21 }, (_, index) => makeRecord(index + 1));
    const sizes: number[] = [];
    const fetchImpl = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { events: unknown[] };
      sizes.push(body.events.length);
      return jsonResponse(acknowledgement(
        records.slice(sizes.reduce((sum, size) => sum + size, 0) - body.events.length,
          sizes.reduce((sum, size) => sum + size, 0)),
      ));
    });
    const client = new CodingEvidenceApiClient({
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const queue = new CodingEvidenceSyncQueue(client, sessionId);
    records.forEach((record) => queue.enqueue(record));
    expect(await queue.flush()).toHaveLength(2);
    expect(sizes).toEqual([20, 1]);
    expect(queue.getPendingCount()).toBe(0);
    expect(() => queue.enqueue({
      ...makeRecord(22),
      event: { ...makeRecord(22).event, sessionId: "94000000-0000-4000-8000-000000000001" },
    })).toThrow("evidence_sync_queue_session_mismatch");
  });

  it("closes the queue after the final session event", () => {
    const queue = new CodingEvidenceSyncQueue(
      new CodingEvidenceApiClient({ fetchImpl: vi.fn() as unknown as typeof fetch }),
      sessionId,
    );
    queue.enqueue(makeRecord(1, "SESSION_ENDED"));
    expect(() => queue.enqueue(makeRecord(2))).toThrow("evidence_sync_queue_closed");
  });
});
