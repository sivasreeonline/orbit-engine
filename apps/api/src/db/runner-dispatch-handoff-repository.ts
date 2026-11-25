import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export type ExecutionRequestedEnvelope =
  | { readonly executionId: string; readonly attemptId: string; readonly protocolVersion: "v1" }
  | { readonly executionId: string; readonly attemptId: string; readonly protocolVersion: "v2" };

export type RunnerDispatchHandoffResult =
  | { readonly status: "RECORDED"; readonly dispatchId: string }
  | { readonly status: "DUPLICATE"; readonly dispatchId: string };

interface QueryResult<T extends Record<string, unknown>> { readonly rows: T[]; }
interface PgHandoffClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResult<T>>;
  end(): Promise<void>;
}
type PgClientFactory = (connectionString: string) => PgHandoffClient;
const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({ connectionString, connectionTimeoutMillis: 5_000, application_name: "sky-high-runner-handoff-consumer" }) as unknown as PgHandoffClient;

interface AuthoritativeExecutionRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly job_state: string;
  readonly outbox_attempt_id: string;
  readonly outbox_protocol_version: string;
  readonly correlation_id: string;
  readonly request_attempt_id: string | null;
  readonly request_protocol_version: string | null;
  readonly request_correlation_id: string | null;
  readonly request_deadline_at: Date | string | null;
  readonly request_deadline_valid: boolean | null;
  readonly request_sha256: string | null;
  readonly request_bytes: Uint8Array | null;
}
interface DispatchRow extends Record<string, unknown> {
  readonly id: string;
  readonly attempt_id: string;
  readonly protocol_version: string;
  readonly correlation_id: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const V2_REQUEST_KEYS = [
  "protocolVersion", "correlationId", "executionId", "attemptId", "problemVersionId",
  "action", "language", "runtimeVersion", "runtimeImageDigest", "sourceArtifactId",
  "sourceSha256", "testBundleId", "comparisonPolicy", "deadlineAt", "cancellationRef", "limits",
];

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return toHex(new Uint8Array(digest));
}

function validateV2Request(row: AuthoritativeExecutionRow, envelope: ExecutionRequestedEnvelope): void {
  if (envelope.protocolVersion !== "v2" ||
      !row.request_bytes || !row.request_sha256 ||
      row.request_protocol_version !== "v2" ||
      row.request_attempt_id !== envelope.attemptId ||
      row.request_correlation_id !== row.correlation_id ||
      row.request_deadline_valid !== true) {
    throw new InvalidRunnerDispatchEnvelopeError();
  }
  const bytes = new Uint8Array(row.request_bytes);
  // The digest is checked asynchronously by the caller before parsing the document.
  void bytes;
}

async function verifyV2Request(row: AuthoritativeExecutionRow, envelope: ExecutionRequestedEnvelope): Promise<void> {
  validateV2Request(row, envelope);
  const bytes = new Uint8Array(row.request_bytes as Uint8Array);
  if (await sha256(bytes) !== (row.request_sha256 as string).trim()) {
    throw new InvalidRunnerDispatchEnvelopeError();
  }
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Record<string, unknown>;
  } catch {
    throw new InvalidRunnerDispatchEnvelopeError();
  }
  if (!document || typeof document !== "object" || Array.isArray(document) ||
      Object.keys(document).sort().join(",") !== [...V2_REQUEST_KEYS].sort().join(",") ||
      document.protocolVersion !== "v2" ||
      document.executionId !== envelope.executionId ||
      document.attemptId !== envelope.attemptId ||
      document.correlationId !== row.correlation_id ||
      document.deadlineAt === undefined ||
      Date.parse(String(document.deadlineAt)) <= Date.now() ||
      document.comparisonPolicy !== "EXACT_BYTES" ||
      typeof document.limits !== "object" || document.limits === null || Array.isArray(document.limits) ||
      Object.keys(document.limits as Record<string, unknown>).sort().join(",") !==
        ["cpuQuotaMillis", "memoryBytes", "wallTimeMillis", "processLimit", "outputBytes", "scratchBytes", "scratchInodes"].sort().join(",")) {
    throw new InvalidRunnerDispatchEnvelopeError();
  }
}

/**
 * Persists the durable queue-to-runner handoff. V2 is validated against the
 * immutable request row; the queue remains a metadata-only wake-up signal.
 */
export class PostgresRunnerDispatchHandoffRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async record(envelope: ExecutionRequestedEnvelope): Promise<RunnerDispatchHandoffResult> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateEnvelope(envelope);
    const client = this.clientFactory(this.connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      await client.query("BEGIN");
      try {
        const authoritative = await client.query<AuthoritativeExecutionRow>(
          [
            "SELECT ej.attempt_id, ej.state AS job_state,",
            "  eo.payload->>'attemptId' AS outbox_attempt_id,",
            "  eo.protocol_version AS outbox_protocol_version, eo.correlation_id,",
            "  v2.attempt_id::text AS request_attempt_id, v2.protocol_version AS request_protocol_version,",
            "  v2.correlation_id::text AS request_correlation_id, v2.deadline_at AS request_deadline_at,",
            "  (v2.deadline_at > now()) AS request_deadline_valid,",
            "  v2.request_sha256, v2.request_bytes",
            "FROM execution_jobs AS ej",
            "INNER JOIN execution_outbox AS eo ON eo.execution_id = ej.id",
            "LEFT JOIN execution_protocol_requests AS v2 ON v2.execution_id = ej.id",
            "WHERE ej.id = $1::uuid AND eo.event_type = 'EXECUTION_REQUESTED'",
            "  AND eo.payload->>'executionId' = ej.id::text",
            "FOR UPDATE OF ej",
          ].join("\n"),
          [envelope.executionId],
        );
        const current = authoritative.rows[0];
        if (!current || current.attempt_id !== envelope.attemptId ||
            current.outbox_attempt_id !== envelope.attemptId ||
            current.outbox_protocol_version !== envelope.protocolVersion) {
          throw new InvalidRunnerDispatchEnvelopeError();
        }
        if (envelope.protocolVersion === "v2") {
          await verifyV2Request(current, envelope);
        } else if (current.request_protocol_version !== null) {
          throw new InvalidRunnerDispatchEnvelopeError();
        }

        await client.query(
          [
            "INSERT INTO runner_dispatch_scheduler_lanes (tenant_id, actor_user_id)",
            "SELECT tenant_id, actor_user_id FROM execution_attempts WHERE id = $1::uuid",
            "ON CONFLICT (tenant_id, actor_user_id) DO NOTHING",
          ].join("\n"),
          [envelope.attemptId],
        );
        const existing = await client.query<DispatchRow>(
          "SELECT id, attempt_id, protocol_version, correlation_id FROM runner_dispatch_outbox WHERE execution_id = $1::uuid FOR UPDATE",
          [envelope.executionId],
        );
        const prior = existing.rows[0];
        if (prior) {
          if (prior.attempt_id !== envelope.attemptId ||
              prior.protocol_version !== envelope.protocolVersion ||
              prior.correlation_id !== current.correlation_id) {
            throw new InvalidRunnerDispatchEnvelopeError();
          }
          await client.query("COMMIT");
          return { status: "DUPLICATE", dispatchId: prior.id };
        }
        if (current.job_state !== "QUEUED") throw new InvalidRunnerDispatchEnvelopeError();

        const inserted = await client.query<DispatchRow>(
          [
            "INSERT INTO runner_dispatch_outbox (execution_id, attempt_id, protocol_version, correlation_id)",
            "VALUES ($1::uuid, $2::uuid, $3, $4)",
            "RETURNING id, attempt_id, protocol_version, correlation_id",
          ].join("\n"),
          [envelope.executionId, envelope.attemptId, envelope.protocolVersion, current.correlation_id],
        );
        const created = inserted.rows[0];
        if (!created) throw new Error("runner_dispatch_insert_returned_no_id");
        await client.query("COMMIT");
        return { status: "RECORDED", dispatchId: created.id };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    } catch (error) {
      if (error instanceof InvalidRunnerDispatchEnvelopeError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }

  private validateEnvelope(envelope: ExecutionRequestedEnvelope): void {
    if (!envelope || typeof envelope !== "object" ||
        !UUID.test(envelope.executionId) || !UUID.test(envelope.attemptId) ||
        (envelope.protocolVersion !== "v1" && envelope.protocolVersion !== "v2") ||
        Object.keys(envelope).some((key) => !["executionId", "attemptId", "protocolVersion"].includes(key))) {
      throw new InvalidRunnerDispatchEnvelopeError();
    }
  }
}

export class InvalidRunnerDispatchEnvelopeError extends Error {
  constructor() {
    super("invalid_runner_dispatch_envelope");
    this.name = "InvalidRunnerDispatchEnvelopeError";
  }
}
