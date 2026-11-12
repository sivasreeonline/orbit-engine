import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface ExecutionSourceSnapshot {
  readonly attemptId: string;
  readonly sourceSha256: string;
  readonly sourceByteLength: string;
  readonly sourceCode: string;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgSourceClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgSourceClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-execution-source-evidence",
  }) as unknown as PgSourceClient;

interface SourceSnapshotRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly sha256: string;
  readonly byte_length: string | number | bigint;
  readonly storage_kind: "DATABASE" | "R2";
  readonly source_bytes: Uint8Array | null;
}

export class ExecutionSourceSnapshotNotFoundError extends Error {
  constructor() {
    super("execution_source_snapshot_not_found");
    this.name = "ExecutionSourceSnapshotNotFoundError";
  }
}

export class ExecutionSourceSnapshotUnavailableError extends Error {
  constructor() {
    super("execution_source_snapshot_storage_unavailable");
    this.name = "ExecutionSourceSnapshotUnavailableError";
  }
}

export class ExecutionSourceSnapshotIntegrityError extends Error {
  constructor() {
    super("execution_source_snapshot_integrity_failed");
    this.name = "ExecutionSourceSnapshotIntegrityError";
  }
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
}

/**
 * Reads the exact immutable source snapshot attached to an attempt.
 * Ownership is enforced in SQL using the authenticated tenant and actor.
 * DATABASE snapshots are supported here; R2 retrieval is intentionally
 * unavailable until an authenticated private-object reader is configured.
 */
export class PostgresExecutionSourceSnapshotRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async getAttemptSourceSnapshot(
    tenantId: string,
    actorUserId: string,
    attemptId: string,
  ): Promise<ExecutionSourceSnapshot> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!isUuid(tenantId) || !isUuid(actorUserId) || !isUuid(attemptId)) {
      throw new Error("invalid_execution_source_snapshot_scope");
    }

    const client = this.clientFactory(this.connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      const result = await client.query<SourceSnapshotRow>(
        [
          "SELECT ea.id AS attempt_id, ss.sha256, ss.byte_length,",
          "  ss.storage_kind, ss.source_bytes",
          "FROM execution_attempts AS ea",
          "INNER JOIN source_snapshots AS ss ON ss.id = ea.source_snapshot_id",
          "WHERE ea.id = $1::uuid",
          "  AND ea.tenant_id = $2::uuid",
          "  AND ea.actor_user_id = $3::uuid",
          "LIMIT 1",
        ].join("\n"),
        [attemptId, tenantId, actorUserId],
      );

      const row = result.rows[0];
      if (!row) throw new ExecutionSourceSnapshotNotFoundError();
      if (row.storage_kind !== "DATABASE" || row.source_bytes === null) {
        throw new ExecutionSourceSnapshotUnavailableError();
      }
      if (!(row.source_bytes instanceof Uint8Array) || !/^[0-9a-f]{64}$/.test(row.sha256.trim())) {
        throw new ExecutionSourceSnapshotIntegrityError();
      }

      let expectedByteLength: bigint;
      try {
        expectedByteLength = BigInt(row.byte_length);
      } catch {
        throw new ExecutionSourceSnapshotIntegrityError();
      }
      if (expectedByteLength < 1n || BigInt(row.source_bytes.byteLength) !== expectedByteLength) {
        throw new ExecutionSourceSnapshotIntegrityError();
      }

      const actualHash = await sha256(row.source_bytes);
      if (actualHash !== row.sha256.trim()) {
        throw new ExecutionSourceSnapshotIntegrityError();
      }

      let sourceCode: string;
      try {
        sourceCode = new TextDecoder("utf-8", { fatal: true }).decode(row.source_bytes);
      } catch {
        throw new ExecutionSourceSnapshotIntegrityError();
      }

      return {
        attemptId: row.attempt_id,
        sourceSha256: actualHash,
        sourceByteLength: expectedByteLength.toString(),
        sourceCode,
      };
    } catch (error) {
      if (
        error instanceof ExecutionSourceSnapshotNotFoundError ||
        error instanceof ExecutionSourceSnapshotUnavailableError ||
        error instanceof ExecutionSourceSnapshotIntegrityError ||
        error instanceof DatabaseUnavailableError ||
        error instanceof Error && error.message.startsWith("invalid_")
      ) {
        throw error;
      }
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
