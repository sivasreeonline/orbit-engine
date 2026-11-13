import { Client } from "pg";
import type { Principal } from "../contracts";

type CodingLanguage = "java" | "python";
import { DatabaseUnavailableError } from "./database-errors";

export type CodingEvidenceEventType =
  | "SESSION_STARTED"
  | "CODE_SNAPSHOT_CREATED"
  | "CHECKPOINT_RECORDED"
  | "EDITOR_CONTEXT_CHANGED"
  | "RUN_REQUESTED"
  | "SUBMIT_REQUESTED"
  | "SESSION_ENDED";

export type EditorSnapshotKind =
  | "SESSION_START"
  | "PERIODIC"
  | "CONTEXT_CHANGE"
  | "RUN"
  | "SUBMIT"
  | "SESSION_END";

export interface CreateCodingEvidenceSessionInput {
  readonly principal: Principal;
  readonly problemId: string;
  readonly problemVersionId: string;
  readonly language: CodingLanguage;
  readonly noticeVersion: string;
}

export interface CreatedCodingEvidenceSession {
  readonly sessionId: string;
  readonly startedAt: string;
  readonly lastSequence: number;
}

export interface CodingEvidenceEventInput {
  readonly eventId: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly eventType: CodingEvidenceEventType;
  readonly occurredAt: string;
  readonly language: CodingLanguage;
  readonly snapshotId?: string;
  readonly contentSha256?: string;
  readonly metadata?: Readonly<Record<string, string | number | boolean>>;
}

export interface EditorCodeSnapshotInput {
  readonly snapshotId: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly kind: EditorSnapshotKind;
  readonly language: CodingLanguage;
  readonly sourceCode: string;
  readonly sourceByteLength: number;
  readonly contentSha256: string;
  readonly capturedAt: string;
}

export interface CodingEvidenceRecordInput {
  readonly event: CodingEvidenceEventInput;
  readonly snapshot?: EditorCodeSnapshotInput;
}

export interface AppendCodingEvidenceBatchInput {
  readonly principal: Principal;
  readonly sessionId: string;
  readonly events: readonly CodingEvidenceRecordInput[];
}

export interface AppendedCodingEvidenceBatch {
  readonly accepted: number;
  readonly replayed: number;
  readonly sequenceGaps: readonly number[];
  readonly lastSequence: number;
  readonly sessionEnded: boolean;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgEvidenceClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgEvidenceClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-editor-evidence",
  }) as unknown as PgEvidenceClient;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha256Pattern = /^[0-9a-f]{64}$/;

interface SessionRow extends Record<string, unknown> {
  readonly last_sequence: string | number;
  readonly status: string;
}

interface ExistingEventRow extends Record<string, unknown> {
  readonly event_id: string;
  readonly session_id: string;
  readonly sequence: string | number;
  readonly payload_sha256: string;
}

interface InsertedIdRow extends Record<string, unknown> {
  readonly id: string;
}

function isUuid(value: string): boolean {
  return uuidPattern.test(value);
}

function isLanguage(value: string): value is CodingLanguage {
  return value === "java" || value === "python";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Bytes(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return toHex(new Uint8Array(digest));
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  }
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function validTimestamp(value: string): boolean {
  return value.length <= 40 && Number.isFinite(Date.parse(value)) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
}

function validateSessionInput(input: CreateCodingEvidenceSessionInput): void {
  if (!input || !isUuid(input.principal.tenantId) || !isUuid(input.principal.userId) ||
      !isUuid(input.problemId) || !isUuid(input.problemVersionId) ||
      !isLanguage(input.language) ||
      typeof input.noticeVersion !== "string" ||
      input.noticeVersion.length < 1 || input.noticeVersion.length > 32) {
    throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_session");
  }
}

function validateEvidenceRecord(record: CodingEvidenceRecordInput, sessionId: string): void {
  const event = record?.event;
  if (!event || !isUuid(event.eventId) || event.sessionId !== sessionId ||
      !isUuid(event.sessionId) || !Number.isSafeInteger(event.sequence) || event.sequence < 1 ||
      !validTimestamp(event.occurredAt) || !isLanguage(event.language)) {
    throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_event");
  }
  if (![
    "SESSION_STARTED", "CODE_SNAPSHOT_CREATED", "CHECKPOINT_RECORDED",
    "EDITOR_CONTEXT_CHANGED", "RUN_REQUESTED", "SUBMIT_REQUESTED", "SESSION_ENDED",
  ].includes(event.eventType)) {
    throw new InvalidCodingEvidenceInputError("unsupported_coding_evidence_event_type");
  }
  if (event.snapshotId !== undefined && !isUuid(event.snapshotId)) {
    throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_snapshot_id");
  }
  if (event.contentSha256 !== undefined && !sha256Pattern.test(event.contentSha256)) {
    throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_content_hash");
  }
  if (event.metadata !== undefined) {
    if (!isRecord(event.metadata) || Object.keys(event.metadata).length > 32 ||
        new TextEncoder().encode(stableJson(event.metadata)).byteLength > 4096 ||
        Object.values(event.metadata).some((value) =>
          !(typeof value === "string" && value.length <= 512) &&
          !(typeof value === "boolean") &&
          !(typeof value === "number" && Number.isFinite(value)))) {
      throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_metadata");
    }
  }

  const snapshot = record.snapshot;
  if (snapshot) {
    if (!isUuid(snapshot.snapshotId) || snapshot.snapshotId !== event.snapshotId ||
        snapshot.sessionId !== sessionId || snapshot.sequence !== event.sequence ||
        snapshot.language !== event.language || !isLanguage(snapshot.language) ||
        !validTimestamp(snapshot.capturedAt) || !sha256Pattern.test(snapshot.contentSha256) ||
        event.contentSha256 !== snapshot.contentSha256 ||
        typeof snapshot.sourceCode !== "string" ||
        ![
          "SESSION_START", "PERIODIC", "CONTEXT_CHANGE", "RUN", "SUBMIT", "SESSION_END",
        ].includes(snapshot.kind)) {
      throw new InvalidCodingEvidenceInputError("invalid_editor_code_snapshot");
    }
    const byteLength = new TextEncoder().encode(snapshot.sourceCode).byteLength;
    if (!Number.isSafeInteger(snapshot.sourceByteLength) ||
        snapshot.sourceByteLength !== byteLength || byteLength > 256 * 1024) {
      throw new InvalidCodingEvidenceInputError("editor_code_snapshot_size_invalid");
    }
    if (event.eventType !== "CODE_SNAPSHOT_CREATED") {
      throw new InvalidCodingEvidenceInputError("editor_code_snapshot_event_mismatch");
    }
  } else if (
    event.eventType === "CODE_SNAPSHOT_CREATED" ||
    event.eventType === "EDITOR_CONTEXT_CHANGED" ||
    event.eventType === "RUN_REQUESTED" ||
    event.eventType === "SUBMIT_REQUESTED"
  ) {
    if (!event.snapshotId) {
      throw new InvalidCodingEvidenceInputError("coding_evidence_event_requires_snapshot");
    }
  }
}

async function recordDigest(record: CodingEvidenceRecordInput): Promise<string> {
  const normalized = {
    event: record.event,
    snapshot: record.snapshot ? {
      snapshotId: record.snapshot.snapshotId,
      sequence: record.snapshot.sequence,
      kind: record.snapshot.kind,
      language: record.snapshot.language,
      sourceByteLength: record.snapshot.sourceByteLength,
      contentSha256: record.snapshot.contentSha256,
      capturedAt: record.snapshot.capturedAt,
    } : null,
  };
  return sha256Bytes(new TextEncoder().encode(stableJson(normalized)));
}

export class CodingEvidenceSessionNotFoundError extends Error {
  constructor() {
    super("coding_evidence_session_not_found");
    this.name = "CodingEvidenceSessionNotFoundError";
  }
}

export class CodingEvidenceSessionClosedError extends Error {
  constructor() {
    super("coding_evidence_session_closed");
    this.name = "CodingEvidenceSessionClosedError";
  }
}

export class CodingEvidenceConflictError extends Error {
  constructor() {
    super("coding_evidence_event_conflict");
    this.name = "CodingEvidenceConflictError";
  }
}

export class CodingEvidenceSequenceConflictError extends Error {
  constructor() {
    super("coding_evidence_sequence_conflict");
    this.name = "CodingEvidenceSequenceConflictError";
  }
}

export class InvalidCodingEvidenceInputError extends Error {
  constructor(message = "invalid_coding_evidence_input") {
    super(message);
    this.name = "InvalidCodingEvidenceInputError";
  }
}

/**
 * Owns coding-session creation and append-only event ingestion. Editor source
 * bytes are stored through the existing source_snapshots table; session/event
 * rows hold metadata and references, so Run/Submit can share the same blob model.
 */
export class PostgresCodingEvidenceRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async createSession(
    input: CreateCodingEvidenceSessionInput,
  ): Promise<CreatedCodingEvidenceSession> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    validateSessionInput(input);

    return this.withClient(async (client) => {
      const result = await client.query<{
        id: string;
        started_at: Date | string;
        last_sequence: string | number;
      }>(
        [
          "INSERT INTO coding_evidence_sessions (",
          "  tenant_id, actor_user_id, problem_id, problem_version_id,",
          "  language, notice_version",
          ")",
          "SELECT $1::uuid, $2::uuid, problem.id, version.id, $5, $6",
          "FROM problems AS problem",
          "INNER JOIN problem_versions AS version",
          "  ON version.problem_id = problem.id AND version.id = $4::uuid",
          "WHERE problem.id = $3::uuid AND problem.lifecycle_status = 'PUBLISHED'",
          "  AND version.published_at IS NOT NULL",
          "  AND (problem.tenant_id IS NULL OR problem.tenant_id = $1::uuid)",
          "RETURNING id, started_at, last_sequence",
        ].join("\n"),
        [
          input.principal.tenantId, input.principal.userId, input.problemId,
          input.problemVersionId, input.language, input.noticeVersion,
        ],
      );
      const row = result.rows[0];
      if (!row) throw new CodingEvidenceSessionNotFoundError();
      return {
        sessionId: row.id,
        startedAt: isoTimestamp(row.started_at),
        lastSequence: Number(row.last_sequence),
      };
    }).catch((error: unknown) => {
      if (error instanceof CodingEvidenceSessionNotFoundError ||
          error instanceof InvalidCodingEvidenceInputError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  async appendBatch(
    input: AppendCodingEvidenceBatchInput,
  ): Promise<AppendedCodingEvidenceBatch> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!input || !isUuid(input.principal.tenantId) || !isUuid(input.principal.userId) ||
        !isUuid(input.sessionId) || !Array.isArray(input.events) ||
        input.events.length < 1 || input.events.length > 20) {
      throw new InvalidCodingEvidenceInputError("invalid_coding_evidence_batch");
    }
    for (const record of input.events) validateEvidenceRecord(record, input.sessionId);
    for (let index = 1; index < input.events.length; index += 1) {
      const prior = input.events[index - 1]?.event.sequence ?? 0;
      const current = input.events[index]?.event.sequence ?? 0;
      if (current <= prior) {
        throw new InvalidCodingEvidenceInputError("coding_evidence_batch_must_be_sequence_ordered");
      }
    }
    const endedIndex = input.events.findIndex((record) => record.event.eventType === "SESSION_ENDED");
    if (endedIndex >= 0 && endedIndex !== input.events.length - 1) {
      throw new InvalidCodingEvidenceInputError("session_ended_must_be_last_event");
    }

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        const sessionResult = await client.query<SessionRow>(
          [
            "SELECT last_sequence, status",
            "FROM coding_evidence_sessions",
            "WHERE id = $1::uuid AND tenant_id = $2::uuid AND actor_user_id = $3::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.sessionId, input.principal.tenantId, input.principal.userId],
        );
        const session = sessionResult.rows[0];
        if (!session) throw new CodingEvidenceSessionNotFoundError();

        let lastSequence = Number(session.last_sequence);
        if (!Number.isSafeInteger(lastSequence) || lastSequence < 0) {
          throw new Error("coding_evidence_session_sequence_corrupt");
        }
        let sessionEnded = session.status === "ENDED";
        let newlyEnded = false;
        let accepted = 0;
        let replayed = 0;
        const sequenceGaps: number[] = [];

        for (const record of input.events) {
          const event = record.event;
          const digest = await recordDigest(record);
          const priorById = await client.query<ExistingEventRow>(
            [
              "SELECT event_id, session_id, sequence, payload_sha256",
              "FROM coding_evidence_events WHERE event_id = $1::uuid",
            ].join("\n"),
            [event.eventId],
          );
          const priorIdRow = priorById.rows[0];
          if (priorIdRow) {
            if (priorIdRow.session_id !== input.sessionId ||
                Number(priorIdRow.sequence) !== event.sequence ||
                priorIdRow.payload_sha256.trim() !== digest) {
              throw new CodingEvidenceConflictError();
            }
            replayed += 1;
            continue;
          }

          const priorBySequence = await client.query<ExistingEventRow>(
            [
              "SELECT event_id, session_id, sequence, payload_sha256",
              "FROM coding_evidence_events",
              "WHERE session_id = $1::uuid AND sequence = $2",
            ].join("\n"),
            [input.sessionId, event.sequence],
          );
          if (priorBySequence.rows.length > 0 || event.sequence <= lastSequence) {
            throw new CodingEvidenceSequenceConflictError();
          }
          if (sessionEnded) throw new CodingEvidenceSessionClosedError();

          if (lastSequence === 0) {
            if (event.sequence !== 1 || event.eventType !== "SESSION_STARTED") {
              throw new CodingEvidenceSequenceConflictError();
            }
          } else if (event.eventType === "SESSION_STARTED") {
            throw new CodingEvidenceSequenceConflictError();
          }

          let snapshotId: string | null = event.snapshotId ?? null;
          if (record.snapshot) {
            const snapshot = record.snapshot;
            const sourceBytes = new TextEncoder().encode(snapshot.sourceCode);
            const sourceHash = await sha256Bytes(sourceBytes);
            if (sourceHash !== snapshot.contentSha256) {
              throw new InvalidCodingEvidenceInputError("editor_code_snapshot_hash_mismatch");
            }

            const sourceSnapshot = await client.query<InsertedIdRow>(
              [
                "INSERT INTO source_snapshots (",
                "  tenant_id, actor_user_id, sha256, byte_length, storage_kind, source_bytes",
                ")",
                "VALUES ($1::uuid, $2::uuid, $3, $4, 'DATABASE', convert_to($5, 'UTF8'))",
                "RETURNING id",
              ].join("\n"),
              [
                input.principal.tenantId, input.principal.userId, sourceHash,
                sourceBytes.byteLength, snapshot.sourceCode,
              ],
            );
            const sourceSnapshotId = sourceSnapshot.rows[0]?.id;
            if (!sourceSnapshotId) throw new Error("editor_source_snapshot_insert_returned_no_id");

            const insertedSnapshot = await client.query<InsertedIdRow>(
              [
                "INSERT INTO editor_code_snapshots (",
                "  id, session_id, source_snapshot_id, sequence, snapshot_kind, language, captured_at",
                ")",
                "VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::timestamptz)",
                "RETURNING id",
              ].join("\n"),
              [
                snapshot.snapshotId, input.sessionId, sourceSnapshotId,
                snapshot.sequence, snapshot.kind, snapshot.language, snapshot.capturedAt,
              ],
            );
            snapshotId = insertedSnapshot.rows[0]?.id ?? null;
            if (!snapshotId) throw new Error("editor_code_snapshot_insert_returned_no_id");
          }

          const gapBefore = event.sequence > lastSequence + 1;
          if (gapBefore) sequenceGaps.push(event.sequence);

          await client.query(
            [
              "INSERT INTO coding_evidence_events (",
              "  event_id, session_id, sequence, event_type, client_occurred_at,",
              "  language, snapshot_id, payload_sha256, metadata, sequence_gap_before",
              ")",
              "VALUES ($1::uuid, $2::uuid, $3, $4, $5::timestamptz,",
              "  $6, $7::uuid, $8, $9::jsonb, $10)",
            ].join("\n"),
            [
              event.eventId, input.sessionId, event.sequence, event.eventType,
              event.occurredAt, event.language, snapshotId, digest,
              JSON.stringify(event.metadata ?? {}), gapBefore,
            ],
          );

          lastSequence = event.sequence;
          accepted += 1;
          if (event.eventType === "SESSION_ENDED") {
            sessionEnded = true;
            newlyEnded = true;
          }
        }

        await client.query(
          [
            "UPDATE coding_evidence_sessions",
            "SET last_sequence = $4, last_received_at = now(),",
            "    status = CASE WHEN $5 THEN 'ENDED' ELSE status END,",
            "    ended_at = CASE WHEN $6 THEN now() ELSE ended_at END",
            "WHERE id = $1::uuid AND tenant_id = $2::uuid AND actor_user_id = $3::uuid",
          ].join("\n"),
          [input.sessionId, input.principal.tenantId, input.principal.userId, lastSequence, sessionEnded, newlyEnded],
        );
        await client.query("COMMIT");
        return {
          accepted,
          replayed,
          sequenceGaps,
          lastSequence,
          sessionEnded,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof CodingEvidenceSessionNotFoundError ||
          error instanceof CodingEvidenceSessionClosedError ||
          error instanceof CodingEvidenceConflictError ||
          error instanceof CodingEvidenceSequenceConflictError ||
          error instanceof InvalidCodingEvidenceInputError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private async withClient<T>(operation: (client: PgEvidenceClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof CodingEvidenceSessionNotFoundError ||
          error instanceof CodingEvidenceSessionClosedError ||
          error instanceof CodingEvidenceConflictError ||
          error instanceof CodingEvidenceSequenceConflictError ||
          error instanceof InvalidCodingEvidenceInputError ||
          error instanceof Error && error.message.startsWith("invalid_")) {
        throw error;
      }
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}

function isoTimestamp(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("invalid_coding_evidence_timestamp");
  return date.toISOString();
}
