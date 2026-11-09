import type { Principal } from "../contracts";
import { DatabaseUnavailableError } from "./database-errors";

export type ExecutionAction = "RUN" | "SUBMIT";
export type ExecutionLanguage = "java" | "python";

export interface CreateExecutionInput {
  /** Must be populated from the authenticated request context, never the request body. */
  readonly principal: Principal;
  readonly action: ExecutionAction;
  readonly problemSlug: string;
  readonly language: ExecutionLanguage;
  /** Runtime version is selected by trusted server policy, not by the student. */
  readonly runtimeVersion: string;
  readonly sourceCode: string;
  /** Generated/validated at the trusted API boundary. */
  readonly correlationId: string;
}

export interface CreatedExecution {
  readonly executionId: string;
  readonly attemptId: string;
  readonly replayed: boolean;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgTransactionClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgTransactionClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({ connectionString, connectionTimeoutMillis: 5_000,
    application_name: "sky-high-coding-judge-api" }) as unknown as PgTransactionClient;

import { Client } from "pg";

export class ExecutionProblemNotFoundError extends Error {
  constructor() {
    super("execution_problem_not_found");
    this.name = "ExecutionProblemNotFoundError";
  }
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("idempotency_key_reused_with_different_request");
    this.name = "IdempotencyConflictError";
  }
}

interface ExistingExecutionRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly execution_id: string;
  readonly request_sha256: string;
}

interface IdRow extends Record<string, unknown> {
  readonly id: string;
}

interface ProblemRow extends Record<string, unknown> {
  readonly problem_id: string;
  readonly problem_version_id: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toHex(new Uint8Array(digest));
}

function idempotencyScope(input: CreateExecutionInput, key: string): string {
  return JSON.stringify([
    input.principal.tenantId,
    input.principal.userId,
    input.action,
    key,
  ]);
}

/**
 * Transactional persistence prototype for the proposed 0003 schema.
 * It is deliberately not wired to HTTP routes or queue dispatch.
 */
export class PostgresExecutionIntakeRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async create(
    input: CreateExecutionInput,
    idempotencyKey: string,
  ): Promise<CreatedExecution> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!input.principal.tenantId || !input.principal.userId) {
      throw new Error("trusted_principal_required");
    }
    if (!/^[A-Za-z0-9._:-]{1,96}$/.test(input.correlationId)) {
      throw new Error("invalid_correlation_id");
    }
    if (!/^[A-Za-z0-9._~-]{1,128}$/.test(idempotencyKey)) {
      throw new Error("invalid_idempotency_key");
    }
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.problemSlug) ||
        input.problemSlug.length > 64) {
      throw new Error("invalid_problem_slug");
    }
    if (!input.runtimeVersion || input.runtimeVersion.length > 32) {
      throw new Error("invalid_runtime_version");
    }

    const sourceHash = await sha256(input.sourceCode);
    // Array serialization gives the prototype a deterministic field order.
    // The canonicalization policy remains subject to API contract approval.
    const requestHash = await sha256(JSON.stringify([
      input.action, input.problemSlug, input.language, input.runtimeVersion, input.sourceCode,
    ]));
    const sourceByteLength = new TextEncoder().encode(input.sourceCode).byteLength;
    const client = this.clientFactory(this.connectionString);

    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      await client.query("BEGIN");

      try {
        // A hash collision can only cause extra serialization; it cannot mix scopes.
        // This transaction-scoped lock prevents two requests racing to reserve one key.
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          [idempotencyScope(input, idempotencyKey)],
        );

        const existing = await client.query<ExistingExecutionRow>(
          [
            "SELECT ei.attempt_id, ej.id AS execution_id, ei.request_sha256",
            "FROM execution_idempotency AS ei",
            "INNER JOIN execution_jobs AS ej ON ej.attempt_id = ei.attempt_id",
            "WHERE ei.tenant_id = $1::uuid AND ei.actor_user_id = $2::uuid",
            "  AND ei.endpoint = $3 AND ei.idempotency_key = $4",
            "FOR UPDATE OF ei",
          ].join("\n"),
          [input.principal.tenantId, input.principal.userId, input.action, idempotencyKey],
        );

        const prior = existing.rows[0];
        if (prior) {
          if (prior.request_sha256.trim() !== requestHash) {
            throw new IdempotencyConflictError();
          }
          await client.query("COMMIT");
          return {
            executionId: prior.execution_id,
            attemptId: prior.attempt_id,
            replayed: true,
          };
        }

        const problem = await client.query<ProblemRow>(
          [
            "SELECT p.id AS problem_id, pv.id AS problem_version_id",
            "FROM problems AS p",
            "INNER JOIN problem_versions AS pv ON pv.id = p.current_version_id",
            "WHERE p.slug = $1 AND p.lifecycle_status = 'PUBLISHED'",
            "  AND (p.tenant_id IS NULL OR p.tenant_id = $2::uuid)",
            "  AND pv.published_at IS NOT NULL",
            "LIMIT 1",
          ].join("\n"),
          [input.problemSlug, input.principal.tenantId],
        );
        const selectedProblem = problem.rows[0];
        if (!selectedProblem) throw new ExecutionProblemNotFoundError();

        const snapshot = await client.query<IdRow>(
          [
            "INSERT INTO source_snapshots",
            "  (tenant_id, actor_user_id, sha256, byte_length, storage_kind, source_bytes)",
            "VALUES ($1::uuid, $2::uuid, $3, $4, 'DATABASE', convert_to($5, 'UTF8'))",
            "RETURNING id",
          ].join("\n"),
          [
            input.principal.tenantId, input.principal.userId, sourceHash,
            sourceByteLength, input.sourceCode,
          ],
        );
        const snapshotId = snapshot.rows[0]?.id;
        if (!snapshotId) throw new Error("source_snapshot_insert_returned_no_id");

        const attempt = await client.query<IdRow>(
          [
            "INSERT INTO execution_attempts",
            "  (tenant_id, actor_user_id, problem_id, problem_version_id, action,",
            "   language, runtime_version, source_snapshot_id, source_sha256)",
            "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8::uuid, $9)",
            "RETURNING id",
          ].join("\n"),
          [
            input.principal.tenantId, input.principal.userId,
            selectedProblem.problem_id, selectedProblem.problem_version_id,
            input.action, input.language, input.runtimeVersion, snapshotId, sourceHash,
          ],
        );
        const attemptId = attempt.rows[0]?.id;
        if (!attemptId) throw new Error("execution_attempt_insert_returned_no_id");

        const job = await client.query<IdRow>(
          "INSERT INTO execution_jobs (attempt_id) VALUES ($1::uuid) RETURNING id",
          [attemptId],
        );
        const executionId = job.rows[0]?.id;
        if (!executionId) throw new Error("execution_job_insert_returned_no_id");

        const payload = JSON.stringify({
          executionId,
          attemptId,
          protocolVersion: "v1",
        });
        await client.query(
          [
            "INSERT INTO execution_outbox",
            "  (execution_id, event_type, protocol_version, correlation_id, payload)",
            "VALUES ($1::uuid, 'EXECUTION_REQUESTED', 'v1', $2, $3::jsonb)",
          ].join("\n"),
          [executionId, input.correlationId, payload],
        );

        await client.query(
          [
            "INSERT INTO execution_idempotency",
            "  (tenant_id, actor_user_id, endpoint, idempotency_key, request_sha256, attempt_id)",
            "VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid)",
          ].join("\n"),
          [
            input.principal.tenantId, input.principal.userId, input.action,
            idempotencyKey, requestHash, attemptId,
          ],
        );

        await client.query("COMMIT");
        return { executionId, attemptId, replayed: false };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    } catch (error) {
      if (error instanceof IdempotencyConflictError ||
          error instanceof ExecutionProblemNotFoundError) {
        throw error;
      }
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
