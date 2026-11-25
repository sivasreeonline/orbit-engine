import type {
  CapturedEvidence,
  EditorEvidenceEvent,
  EditorEvidenceSnapshot,
  EvidenceLanguage,
} from "./EditorEvidenceCollector";

export interface CreateEvidenceSessionRequest {
  readonly problemSlug: string;
  readonly language: EvidenceLanguage;
  readonly noticeVersion: string;
}

export interface CreatedEvidenceSession {
  readonly sessionId: string;
  readonly startedAt: string;
  readonly lastSequence: number;
  readonly capturePolicy: {
    readonly changedSnapshotIntervalSeconds: number;
    readonly checkpointIntervalSeconds: number;
  };
}

export interface AppendEvidenceBatchAcknowledgement {
  readonly accepted: number;
  readonly replayed: number;
  readonly sequenceGaps: readonly number[];
  readonly lastSequence: number;
  readonly sessionEnded: boolean;
}

export class CodingEvidenceApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;
  readonly correlationId: string | null;

  constructor(input: {
    readonly status: number;
    readonly code: string;
    readonly message: string;
    readonly retryable: boolean;
    readonly correlationId?: string | null;
  }) {
    super(input.message);
    this.name = "CodingEvidenceApiError";
    this.status = input.status;
    this.code = input.code;
    this.retryable = input.retryable;
    this.correlationId = input.correlationId ?? null;
  }
}

export interface CodingEvidenceApiClientOptions {
  readonly basePath?: string;
  readonly fetchImpl?: typeof fetch;
  readonly getHeaders?: () => HeadersInit | Promise<HeadersInit>;
}

const sessionIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCreatedSession(value: unknown): CreatedEvidenceSession {
  if (!isRecord(value) || !sessionIdPattern.test(String(value.sessionId ?? "")) ||
      typeof value.startedAt !== "string" || !Number.isFinite(Date.parse(value.startedAt)) ||
      !Number.isSafeInteger(value.lastSequence) || (value.lastSequence as number) < 0 ||
      !isRecord(value.capturePolicy) ||
      value.capturePolicy.changedSnapshotIntervalSeconds !== 120 ||
      value.capturePolicy.checkpointIntervalSeconds !== 300) {
    throw new Error("invalid_coding_evidence_session_response");
  }
  return {
    sessionId: value.sessionId as string,
    startedAt: value.startedAt,
    lastSequence: value.lastSequence as number,
    capturePolicy: {
      changedSnapshotIntervalSeconds: 120,
      checkpointIntervalSeconds: 300,
    },
  };
}

function parseBatchAcknowledgement(value: unknown): AppendEvidenceBatchAcknowledgement {
  if (!isRecord(value) ||
      !Number.isSafeInteger(value.accepted) || (value.accepted as number) < 0 ||
      !Number.isSafeInteger(value.replayed) || (value.replayed as number) < 0 ||
      !Array.isArray(value.sequenceGaps) ||
      !value.sequenceGaps.every((entry) => Number.isSafeInteger(entry) && (entry as number) > 0) ||
      !Number.isSafeInteger(value.lastSequence) || (value.lastSequence as number) < 0 ||
      typeof value.sessionEnded !== "boolean") {
    throw new Error("invalid_coding_evidence_batch_response");
  }
  return {
    accepted: value.accepted as number,
    replayed: value.replayed as number,
    sequenceGaps: value.sequenceGaps as number[],
    lastSequence: value.lastSequence as number,
    sessionEnded: value.sessionEnded,
  };
}

export class CodingEvidenceApiClient {
  private readonly basePath: string;
  private readonly fetchImpl: typeof fetch;
  private readonly getHeaders?: () => HeadersInit | Promise<HeadersInit>;

  constructor(options: CodingEvidenceApiClientOptions = {}) {
    this.basePath = (options.basePath ?? "/api/v1").replace(/\/$/, "");
    if (!this.basePath.startsWith("/") || this.basePath.startsWith("//")) {
      throw new Error("coding_evidence_api_base_path_must_be_same_origin");
    }
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.getHeaders = options.getHeaders;
  }

  async createSession(
    request: CreateEvidenceSessionRequest,
    signal?: AbortSignal,
  ): Promise<CreatedEvidenceSession> {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(request.problemSlug) ||
        request.problemSlug.length > 64 ||
        (request.language !== "java" && request.language !== "python") ||
        !/^[A-Za-z0-9._-]{1,32}$/.test(request.noticeVersion)) {
      throw new Error("invalid_coding_evidence_session_request");
    }
    const response = await this.request(
      "/evidence/sessions",
      {
        method: "POST",
        body: JSON.stringify(request),
        ...(signal ? { signal } : {}),
      },
    );
    if (!isRecord(response) || !isRecord(response.data)) {
      throw new Error("invalid_coding_evidence_session_envelope");
    }
    return parseCreatedSession(response.data);
  }

  async appendBatch(
    sessionId: string,
    events: readonly CapturedEvidence[],
    signal?: AbortSignal,
  ): Promise<AppendEvidenceBatchAcknowledgement> {
    if (!sessionIdPattern.test(sessionId) || events.length < 1 || events.length > 20) {
      throw new Error("invalid_coding_evidence_batch_request");
    }
    const payload = {
      events: events.map((record) => ({
        event: record.event as EditorEvidenceEvent,
        ...(record.snapshot
          ? { snapshot: record.snapshot as EditorEvidenceSnapshot }
          : {}),
      })),
    };
    const response = await this.request(
      `/evidence/sessions/${sessionId}/events`,
      {
        method: "POST",
        body: JSON.stringify(payload),
        ...(signal ? { signal } : {}),
      },
    );
    if (!isRecord(response) || !isRecord(response.data)) {
      throw new Error("invalid_coding_evidence_batch_envelope");
    }
    const acknowledgement = parseBatchAcknowledgement(response.data);
    if (acknowledgement.accepted + acknowledgement.replayed !== events.length) {
      throw new Error("coding_evidence_acknowledgement_count_mismatch");
    }
    if (acknowledgement.lastSequence < Math.max(...events.map((item) => item.event.sequence))) {
      throw new Error("coding_evidence_acknowledgement_sequence_regression");
    }
    return acknowledgement;
  }

  private async request(
    path: string,
    init: RequestInit,
  ): Promise<unknown> {
    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": "application/json",
    });
    const supplied = this.getHeaders ? new Headers(await this.getHeaders()) : null;
    supplied?.forEach((value, key) => headers.set(key, value));

    const response = await this.fetchImpl(`${this.basePath}${path}`, {
      ...init,
      headers,
      credentials: "include",
      cache: "no-store",
      redirect: "error",
    });

    let body: unknown;
    try {
      body = await response.json() as unknown;
    } catch {
      throw new CodingEvidenceApiError({
        status: response.status,
        code: "INVALID_API_RESPONSE",
        message: "The evidence service returned an invalid response.",
        retryable: response.status >= 500,
        correlationId: response.headers.get("X-Correlation-ID"),
      });
    }
    if (!response.ok) {
      const error = isRecord(body) && isRecord(body.error) ? body.error : {};
      throw new CodingEvidenceApiError({
        status: response.status,
        code: typeof error.code === "string" ? error.code : "CODING_EVIDENCE_REQUEST_FAILED",
        message: typeof error.message === "string"
          ? error.message
          : "The evidence service could not complete the request.",
        retryable: error.retryable === true,
        correlationId: typeof body === "object" && body !== null && "correlationId" in body &&
          typeof body.correlationId === "string" ? body.correlationId : null,
      });
    }
    return body;
  }
}

/**
 * Sequential, in-memory evidence synchronization. A batch is removed only
 * after the server confirms every event as accepted or replayed. A lost
 * response therefore leaves the identical event IDs available for safe retry.
 */
export class CodingEvidenceSyncQueue {
  private readonly client: CodingEvidenceApiClient;
  private readonly sessionId: string;
  private readonly pending: CapturedEvidence[] = [];
  private flushPromise: Promise<AppendEvidenceBatchAcknowledgement[]> | null = null;
  private ended = false;

  constructor(client: CodingEvidenceApiClient, sessionId: string) {
    if (!sessionIdPattern.test(sessionId)) throw new Error("invalid_evidence_session_id");
    this.client = client;
    this.sessionId = sessionId;
  }

  enqueue(record: CapturedEvidence): void {
    if (this.ended) throw new Error("evidence_sync_queue_closed");
    if (record.event.sessionId !== this.sessionId) {
      throw new Error("evidence_sync_queue_session_mismatch");
    }
    if (this.pending.some((pending) => pending.event.eventId === record.event.eventId)) {
      return;
    }
    this.pending.push(record);
    if (record.event.eventType === "SESSION_ENDED") this.ended = true;
  }

  getPendingCount(): number {
    return this.pending.length;
  }

  async flush(signal?: AbortSignal): Promise<AppendEvidenceBatchAcknowledgement[]> {
    if (this.flushPromise) return this.flushPromise;
    this.flushPromise = this.flushPending(signal);
    try {
      return await this.flushPromise;
    } finally {
      this.flushPromise = null;
    }
  }

  private async flushPending(signal?: AbortSignal): Promise<AppendEvidenceBatchAcknowledgement[]> {
    const acknowledgements: AppendEvidenceBatchAcknowledgement[] = [];
    while (this.pending.length > 0) {
      const batch = this.pending.slice(0, 20);
      const acknowledgement = await this.client.appendBatch(this.sessionId, batch, signal);
      acknowledgements.push(acknowledgement);
      this.pending.splice(0, batch.length);
    }
    return acknowledgements;
  }
}
