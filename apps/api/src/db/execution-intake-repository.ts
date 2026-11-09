import { Client } from "pg";
import type { Env } from "../env";

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface TransactionClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type ClientFactory = (connectionString: string) => TransactionClient;

const defaultClientFactory: ClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-execution-intake-prototype",
  }) as unknown as TransactionClient;

/**
 * Internal, trusted input only. Do not construct this object directly from an
 * HTTP body: principal, problem version, runtime and requestHash must be
 * resolved by trusted server-side services.
 */
export interface ExecutionIntakeCommand {
  readonly principal: {
    readonly tenantId: string;
    readonly userId: string;
  };
  readonly endpoint: "RUN" | "SUBMIT";
  readonly idempotencyKey: string;
  /** SHA-256 of the server-canonicalized semantic request. */
  readonly requestHash: string;
  readonly problemId: string;
  readonly problemVersionId: string;
  readonly language: "java" | "python";
  readonly runtimeVersion: string;
  readonly sourceBytes: Uint8Array;
  readonly correlationId: string;
}

export type ExecutionIntakeResult =
  | {
      readonly kind: "CREATED" | "REPLAYED";
      readonly executionId: string;
      readonly attemptId: string;
    }
  | { readonly kind: "IDEMPOTENCY_CONFLICT" };

export class ExecutionIntakeDatabaseError extends Error {
  constructor() {
    super("Execution intake persistence is unavailable");
    this.name = "ExecutionIntakeDatabaseError";
  }
}

interface IdRow extends Record<string, unknown> {
  id: string;
}

interface ExistingIdempotencyRow extends Record<string, unknown> {
  request_sha256: string;
  attempt_id: string;
  execution_id: string;
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export class PostgresExecutionIntakeRepository {
  constructor(
    private readonly env: Env,
    private readonly clientFactory: ClientFactory = defaultClientFactory,
  ) {}

  async create(command: ExecutionIntakeCommand): Promise<ExecutionIntakeResult> {
    if (
      !isSha256(command.requestHash) ||
      !/^[A-Za-z0-9._:-]{1,96}$/.test(command.correlationId) ||
      command.idempotencyKey.length < 1 ||
      command.idempotencyKey.length > 128 ||
      sourceBytes.byteLength < 1 ||
      sourceBytes.byteLength > 1_048_576
    ) {
      throw new TypeError("Execution intake command is invalid");
    }

    // Snapshot caller-owned bytes before the first await so the digest and the
    // persisted byte sequence cannot diverge if the caller mutates its buffer.
    const sourceBytes = new Uint8Array(command.sourceBytes);
    const sourceHash = await sha256Hex(sourceBytes);
    const connectionString = this.env.HYPERDRIVE?.connectionString;
    if (!connectionString) throw new ExecutionIntakeDatabaseError();

    const client = this.clientFactory(connectionString);
    let transactionOpen = false;

    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      await client.query("BEGIN");
      transactionOpen = true;

      const sourceResult = await client.query<IdRow>(
        `INSERT INTO source_snapshots (
           tenant_id, actor_user_id, sha256, byte_length, storage_kind, source_bytes
         ) VALUES ($1::uuid, $2::uuid, $3, $4, 'DATABASE', $5)
         RETURNING id`,
        [
          command.principal.tenantId,
          command.principal.userId,
          sourceHash,
          sourceBytes.byteLength,
          `\\x${Array.from(sourceBytes, (byte) =>
            byte.toString(16).padStart(2, "0"),
          ).join("")}`,
        ],
      );
      const sourceSnapshotId = sourceResult.rows[0]?.id;
      if (!sourceSnapshotId) throw new Error("Source snapshot insert returned no ID");

      const attemptResult = await client.query<IdRow>(
        `INSERT INTO execution_attempts (
           tenant_id, actor_user_id, problem_id, problem_version_id,
           action, language, runtime_version, source_snapshot_id, source_sha256
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid,
           $5, $6, $7, $8::uuid, $9
         )
         RETURNING id`,
        [
          command.principal.tenantId,
          command.principal.userId,
          command.problemId,
          command.problemVersionId,
          command.endpoint,
          command.language,
          command.runtimeVersion,
          sourceSnapshotId,
          sourceHash,
        ],
      );
      const attemptId = attemptResult.rows[0]?.id;
      if (!attemptId) throw new Error("Execution attempt insert returned no ID");

      const jobResult = await client.query<IdRow>(
        "INSERT INTO execution_jobs (attempt_id) VALUES ($1::uuid) RETURNING id",
        [attemptId],
      );
      const executionId = jobResult.rows[0]?.id;
      if (!executionId) throw new Error("Execution job insert returned no ID");

      const idempotencyResult = await client.query<IdRow>(
        `INSERT INTO execution_idempotency (
           tenant_id, actor_user_id, endpoint, idempotency_key, request_sha256, attempt_id
         ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid)
         ON CONFLICT (tenant_id, actor_user_id, endpoint, idempotency_key)
         DO NOTHING
         RETURNING id`,
        [
          command.principal.tenantId,
          command.principal.userId,
          command.endpoint,
          command.idempotencyKey,
          command.requestHash,
          attemptId,
        ],
      );

      if (idempotencyResult.rows.length === 0) {
        // Under READ COMMITTED, ON CONFLICT waits for a competing insert; this
        // subsequent statement can then observe the committed reservation.
        const existing = await client.query<ExistingIdempotencyRow>(
          `SELECT i.request_sha256, i.attempt_id, j.id AS execution_id
           FROM execution_idempotency AS i
           INNER JOIN execution_jobs AS j ON j.attempt_id = i.attempt_id
           WHERE i.tenant_id = $1::uuid
             AND i.actor_user_id = $2::uuid
             AND i.endpoint = $3
             AND i.idempotency_key = $4
           LIMIT 1`,
          [
            command.principal.tenantId,
            command.principal.userId,
            command.endpoint,
            command.idempotencyKey,
          ],
        );
        const existingRow = existing.rows[0];
        if (!existingRow) throw new Error("Idempotency reservation conflict was not resolvable");

        await client.query("ROLLBACK");
        transactionOpen = false;

        if (existingRow.request_sha256 !== command.requestHash) {
          return { kind: "IDEMPOTENCY_CONFLICT" };
        }
        return {
          kind: "REPLAYED",
          executionId: existingRow.execution_id,
          attemptId: existingRow.attempt_id,
        };
      }

      await client.query(
        `INSERT INTO execution_outbox (
           execution_id, event_type, protocol_version, correlation_id, payload
         ) VALUES ($1::uuid, 'EXECUTION_REQUESTED', 'v1', $2, $3::jsonb)`,
        [
          executionId,
          command.correlationId,
          JSON.stringify({
            executionId,
            attemptId,
            protocolVersion: "v1",
          }),
        ],
      );

      await client.query("COMMIT");
      transactionOpen = false;
      return { kind: "CREATED", executionId, attemptId };
    } catch {
      if (transactionOpen) {
        await client.query("ROLLBACK").catch(() => undefined);
      }
      throw new ExecutionIntakeDatabaseError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
