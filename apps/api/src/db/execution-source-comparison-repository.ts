import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";
import {
  ExecutionSourceSnapshotIntegrityError,
  ExecutionSourceSnapshotUnavailableError,
  type ExecutionSourceSnapshot,
} from "./execution-source-snapshot-repository";

export class ExecutionSourceComparisonNotFoundError extends Error {
  constructor() {
    super("execution_source_comparison_not_found");
    this.name = "ExecutionSourceComparisonNotFoundError";
  }
}

export class ExecutionSourceComparisonLimitError extends Error {
  constructor() {
    super("execution_source_comparison_source_limit_exceeded");
    this.name = "ExecutionSourceComparisonLimitError";
  }
}

export class ExecutionSourceComparisonConflictError extends Error {
  constructor() {
    super("execution_source_comparison_not_eligible");
    this.name = "ExecutionSourceComparisonConflictError";
  }
}

interface ComparisonRow extends Record<string, unknown> {
  readonly base_attempt_id: string;
  readonly base_problem_id: string;
  readonly base_problem_version_id: string;
  readonly base_language: string;
  readonly base_runtime_version: string;
  readonly base_attempt_sha256: string;
  readonly base_sha256: string;
  readonly base_byte_length: string | number | bigint;
  readonly base_storage_kind: "DATABASE" | "R2";
  readonly base_source_bytes: Uint8Array | null;
  readonly target_attempt_id: string;
  readonly target_problem_id: string;
  readonly target_problem_version_id: string;
  readonly target_language: string;
  readonly target_runtime_version: string;
  readonly target_attempt_sha256: string;
  readonly target_sha256: string;
  readonly target_byte_length: string | number | bigint;
  readonly target_storage_kind: "DATABASE" | "R2";
  readonly target_source_bytes: Uint8Array | null;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgComparisonClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgComparisonClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-execution-source-comparison",
  }) as unknown as PgComparisonClient;

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

async function verifiedSnapshot(
  attemptId: string,
  sha: string,
  byteLength: string | number | bigint,
  storageKind: "DATABASE" | "R2",
  sourceBytes: Uint8Array | null,
): Promise<ExecutionSourceSnapshot> {
  if (storageKind !== "DATABASE" || sourceBytes === null) {
    throw new ExecutionSourceSnapshotUnavailableError();
  }
  if (!(sourceBytes instanceof Uint8Array) || !/^[0-9a-f]{64}$/.test(sha.trim())) {
    throw new ExecutionSourceSnapshotIntegrityError();
  }

  let expectedLength: bigint;
  try {
    expectedLength = BigInt(byteLength);
  } catch {
    throw new ExecutionSourceSnapshotIntegrityError();
  }
  if (expectedLength < 1n || BigInt(sourceBytes.byteLength) !== expectedLength) {
    throw new ExecutionSourceSnapshotIntegrityError();
  }

  const actualHash = await sha256(sourceBytes);
  if (actualHash !== sha.trim()) throw new ExecutionSourceSnapshotIntegrityError();

  let sourceCode: string;
  try {
    sourceCode = new TextDecoder("utf-8", { fatal: true }).decode(sourceBytes);
  } catch {
    throw new ExecutionSourceSnapshotIntegrityError();
  }

  return {
    attemptId,
    sourceSha256: actualHash,
    sourceByteLength: expectedLength.toString(),
    sourceCode,
  };
}

/**
 * Loads two snapshots in one owner-scoped SQL statement and verifies that
 * both attempts target the same immutable problem version and runtime context.
 */
export class PostgresExecutionSourceComparisonRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async getComparableAttemptSources(
    tenantId: string,
    actorUserId: string,
    baseAttemptId: string,
    targetAttemptId: string,
  ): Promise<{ readonly base: ExecutionSourceSnapshot; readonly target: ExecutionSourceSnapshot }> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (![tenantId, actorUserId, baseAttemptId, targetAttemptId].every(isUuid) ||
        baseAttemptId === targetAttemptId) {
      throw new Error("invalid_execution_source_comparison_scope");
    }

    const client = this.clientFactory(this.connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = 5000");
      const result = await client.query<ComparisonRow>(
        [
          "SELECT",
          "  b.id AS base_attempt_id, b.problem_id AS base_problem_id,",
          "  b.problem_version_id AS base_problem_version_id, b.language AS base_language,",
          "  b.runtime_version AS base_runtime_version, b.source_sha256 AS base_attempt_sha256,",
          "  bs.sha256 AS base_sha256,",
          "  bs.byte_length AS base_byte_length, bs.storage_kind AS base_storage_kind,",
          "  CASE WHEN bs.byte_length <= $5 THEN bs.source_bytes ELSE NULL END AS base_source_bytes",
          "  t.id AS target_attempt_id, t.problem_id AS target_problem_id,",
          "  t.problem_version_id AS target_problem_version_id, t.language AS target_language,",
          "  t.runtime_version AS target_runtime_version, t.source_sha256 AS target_attempt_sha256,",
          "  ts.sha256 AS target_sha256,",
          "  ts.byte_length AS target_byte_length, ts.storage_kind AS target_storage_kind,",
          "  CASE WHEN ts.byte_length <= $5 THEN ts.source_bytes ELSE NULL END AS target_source_bytes",
          "FROM execution_attempts AS b",
          "INNER JOIN source_snapshots AS bs ON bs.id = b.source_snapshot_id",
          "INNER JOIN execution_attempts AS t ON t.id = $2::uuid",
          "INNER JOIN source_snapshots AS ts ON ts.id = t.source_snapshot_id",
          "WHERE b.id = $1::uuid",
          "  AND b.tenant_id = $3::uuid AND b.actor_user_id = $4::uuid",
          "  AND t.tenant_id = $3::uuid AND t.actor_user_id = $4::uuid",
          "  AND bs.tenant_id = $3::uuid AND bs.actor_user_id = $4::uuid",
          "  AND ts.tenant_id = $3::uuid AND ts.actor_user_id = $4::uuid",
          "LIMIT 1",
        ].join("\n"),
        [baseAttemptId, targetAttemptId, tenantId, actorUserId, 128 * 1024],
      );

      const row = result.rows[0];
      if (!row) throw new ExecutionSourceComparisonNotFoundError();
      if (BigInt(row.base_byte_length) > 128n * 1024n ||
          BigInt(row.target_byte_length) > 128n * 1024n) {
        throw new ExecutionSourceComparisonLimitError();
      }
      if (
        row.base_problem_id !== row.target_problem_id ||
        row.base_problem_version_id !== row.target_problem_version_id ||
        row.base_language !== row.target_language ||
        row.base_runtime_version !== row.target_runtime_version
      ) {
        throw new ExecutionSourceComparisonConflictError();
      }

      if (row.base_attempt_sha256.trim() !== row.base_sha256.trim() ||
          row.target_attempt_sha256.trim() !== row.target_sha256.trim()) {
        throw new ExecutionSourceSnapshotIntegrityError();
      }

      const [base, target] = await Promise.all([
        verifiedSnapshot(row.base_attempt_id, row.base_sha256, row.base_byte_length,
          row.base_storage_kind, row.base_source_bytes),
        verifiedSnapshot(row.target_attempt_id, row.target_sha256, row.target_byte_length,
          row.target_storage_kind, row.target_source_bytes),
      ]);
      return { base, target };
    } catch (error) {
      if (
        error instanceof ExecutionSourceComparisonNotFoundError ||
        error instanceof ExecutionSourceComparisonConflictError ||\n        error instanceof ExecutionSourceComparisonLimitError ||
        error instanceof ExecutionSourceSnapshotIntegrityError ||
        error instanceof ExecutionSourceSnapshotUnavailableError ||
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
