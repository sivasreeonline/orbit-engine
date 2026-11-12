import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export type ExecutionEvidenceEventType =
  | "ATTEMPT_ACCEPTED"
  | "JOB_QUEUED"
  | "JOB_CLAIMED"
  | "RUNNER_STARTED"
  | "COMPILATION_STARTED"
  | "COMPILATION_FINISHED"
  | "TEST_STARTED"
  | "TEST_FINISHED"
  | "EXECUTION_FINISHED"
  | "INFRASTRUCTURE_FAILED"
  | "CANCELLED"
  | "RETRY_SCHEDULED";

export type EvidenceActorKind = "STUDENT" | "API" | "QUEUE" | "RUNNER" | "JUDGE" | "SYSTEM";
export type EvidencePhaseStatus = "STARTED" | "SUCCEEDED" | "FAILED" | "SKIPPED" | "CANCELLED";

export type ExecutionInfrastructureStatus = "SUCCEEDED" | "FAILED";
export type ExecutionCompilationStatus = "NOT_STARTED" | "SUCCEEDED" | "FAILED";
export type ExecutionVerdict =
  | "NOT_EVALUATED"
  | "ACCEPTED"
  | "WRONG_ANSWER"
  | "COMPILATION_ERROR"
  | "RUNTIME_ERROR"
  | "TIME_LIMIT_EXCEEDED"
  | "MEMORY_LIMIT_EXCEEDED"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "INTERNAL_ERROR";
export type ExecutionCleanupStatus = "SUCCEEDED" | "FAILED" | "UNKNOWN";

export interface AppendExecutionEvidenceEventInput {
  readonly eventId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly eventType: ExecutionEvidenceEventType;
  readonly actorKind: EvidenceActorKind;
  readonly phaseStatus?: EvidencePhaseStatus;
  /** Allowlisted machine code only. Never put raw compiler/runtime diagnostics here. */
  readonly safeCode?: string;
  readonly durationMs?: number;
}

export interface AppendedExecutionEvidenceEvent {
  readonly sequenceId: string;
  readonly replayed: boolean;
}

export interface RecordExecutionResultInput {
  readonly executionId: string;
  readonly attemptId: string;
  readonly leaseOwner: string;
  readonly leaseToken: string;
  readonly infrastructureStatus: ExecutionInfrastructureStatus;
  readonly infrastructureErrorCode?: string;
  readonly compilationStatus: ExecutionCompilationStatus;
  readonly verdict: ExecutionVerdict;
  readonly cleanupStatus: ExecutionCleanupStatus;
  readonly testsTotal: number;
  readonly testsPassed: number;
  readonly elapsedMs: number;
  readonly peakMemoryBytes?: number;
  readonly runnerVersion: string;
  /** SHA-256 hex digest of the pinned runtime image, when available. */
  readonly runtimeImageDigest?: string;
  /** Digest of the canonical, versioned runner result envelope. */
  readonly resultSha256: string;
  readonly startedAt: string;
  readonly completedAt: string;
}

export interface RecordedExecutionResult {
  readonly executionId: string;
  readonly attemptId: string;
  readonly state: "COMPLETED" | "FAILED_INFRASTRUCTURE";
  readonly resultSha256: string;
  readonly replayed: boolean;
}

export interface ExecutionAttemptHistoryEntry {
  readonly attemptId: string;
  readonly executionId: string;
  readonly action: "RUN" | "SUBMIT";
  readonly language: "java" | "python";
  readonly runtimeVersion: string;
  readonly sourceSha256: string;
  readonly sourceByteLength: number;
  readonly createdAt: string;
  readonly executionState: string;
  readonly infrastructureStatus: ExecutionInfrastructureStatus | null;
  readonly compilationStatus: ExecutionCompilationStatus | null;
  readonly verdict: ExecutionVerdict | null;
  readonly cleanupStatus: ExecutionCleanupStatus | null;
  readonly testsTotal: number | null;
  readonly testsPassed: number | null;
  readonly elapsedMs: string | null;
  readonly peakMemoryBytes: string | null;
  readonly resultSha256: string | null;
}

export interface ExecutionEvidenceEvent {
  readonly sequenceId: string;
  readonly eventId: string;
  readonly eventType: ExecutionEvidenceEventType;
  readonly actorKind: EvidenceActorKind;
  readonly phaseStatus: EvidencePhaseStatus | null;
  readonly safeCode: string | null;
  readonly durationMs: string | null;
  readonly createdAt: string;
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
    application_name: "sky-high-execution-evidence",
  }) as unknown as PgEvidenceClient;

export class ExecutionEvidenceConflictError extends Error {
  constructor() {
    super("execution_evidence_conflict");
    this.name = "ExecutionEvidenceConflictError";
  }
}

export class ExecutionEvidenceNotFoundError extends Error {
  constructor() {
    super("execution_evidence_execution_not_found");
    this.name = "ExecutionEvidenceNotFoundError";
  }
}

export class StaleExecutionLeaseError extends Error {
  constructor() {
    super("execution_result_rejected_for_stale_or_invalid_lease");
    this.name = "StaleExecutionLeaseError";
  }
}

interface EventRow extends Record<string, unknown> {
  readonly sequence_id: string | number;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly event_id: string;
  readonly event_type: ExecutionEvidenceEventType;
  readonly actor_kind: EvidenceActorKind;
  readonly phase_status: EvidencePhaseStatus | null;
  readonly safe_code: string | null;
  readonly duration_ms: string | number | null;
  readonly created_at: Date | string;
}

interface ResultRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly result_sha256: string;
}

interface UpdatedJobRow extends Record<string, unknown> {
  readonly id: string;
}

interface HistoryRow extends Record<string, unknown> {
  readonly attempt_id: string;
  readonly execution_id: string;
  readonly action: "RUN" | "SUBMIT";
  readonly language: "java" | "python";
  readonly runtime_version: string;
  readonly source_sha256: string;
  readonly source_byte_length: string | number;
  readonly created_at: Date | string;
  readonly execution_state: string;
  readonly infrastructure_status: ExecutionInfrastructureStatus | null;
  readonly compilation_status: ExecutionCompilationStatus | null;
  readonly verdict: ExecutionVerdict | null;
  readonly cleanup_status: ExecutionCleanupStatus | null;
  readonly tests_total: number | null;
  readonly tests_passed: number | null;
  readonly elapsed_ms: string | number | null;
  readonly peak_memory_bytes: string | number | null;
  readonly result_sha256: string | null;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isSafeCode(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(value);
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function isoTimestamp(value: Date | string): string {
  const parsed = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error("invalid_database_timestamp");
  return parsed.toISOString();
}

function validateEvent(input: AppendExecutionEvidenceEventInput): void {
  const eventTypes: readonly string[] = [
    "ATTEMPT_ACCEPTED", "JOB_QUEUED", "JOB_CLAIMED", "RUNNER_STARTED",
    "COMPILATION_STARTED", "COMPILATION_FINISHED", "TEST_STARTED", "TEST_FINISHED",
    "EXECUTION_FINISHED", "INFRASTRUCTURE_FAILED", "CANCELLED", "RETRY_SCHEDULED",
  ];
  const actorKinds: readonly string[] = ["STUDENT", "API", "QUEUE", "RUNNER", "JUDGE", "SYSTEM"];
  const phaseStatuses: readonly string[] = ["STARTED", "SUCCEEDED", "FAILED", "SKIPPED", "CANCELLED"];
  if (!eventTypes.includes(input.eventType) || !actorKinds.includes(input.actorKind) ||
      (input.phaseStatus !== undefined && !phaseStatuses.includes(input.phaseStatus))) {
    throw new Error("invalid_execution_evidence_event_type");
  }
  if (!isUuid(input.eventId) || !isUuid(input.executionId) || !isUuid(input.attemptId)) {
    throw new Error("invalid_execution_evidence_identifier");
  }
  if (input.safeCode !== undefined && !isSafeCode(input.safeCode)) {
    throw new Error("invalid_execution_evidence_safe_code");
  }
  if (input.durationMs !== undefined &&
      (!Number.isSafeInteger(input.durationMs) || input.durationMs < 0)) {
    throw new Error("invalid_execution_evidence_duration");
  }
}

function validateResult(input: RecordExecutionResultInput): void {
  const compilationStatuses: readonly string[] = ["NOT_STARTED", "SUCCEEDED", "FAILED"];
  const verdicts: readonly string[] = [
    "NOT_EVALUATED", "ACCEPTED", "WRONG_ANSWER", "COMPILATION_ERROR",
    "RUNTIME_ERROR", "TIME_LIMIT_EXCEEDED", "MEMORY_LIMIT_EXCEEDED",
    "OUTPUT_LIMIT_EXCEEDED", "INTERNAL_ERROR",
  ];
  const cleanupStatuses: readonly string[] = ["SUCCEEDED", "FAILED", "UNKNOWN"];
  if (!compilationStatuses.includes(input.compilationStatus) ||
      !verdicts.includes(input.verdict) ||
      !cleanupStatuses.includes(input.cleanupStatus)) {
    throw new Error("invalid_execution_result_classification");
  }
  if (!isUuid(input.executionId) || !isUuid(input.attemptId) ||
      !isUuid(input.leaseToken)) {
    throw new Error("invalid_execution_result_identifier");
  }
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(input.leaseOwner)) {
    throw new Error("invalid_execution_result_lease_owner");
  }
  if (!isSha256(input.resultSha256)) throw new Error("invalid_execution_result_digest");
  if (input.runtimeImageDigest !== undefined && !isSha256(input.runtimeImageDigest)) {
    throw new Error("invalid_runtime_image_digest");
  }
  if (input.infrastructureStatus === "FAILED") {
    if (!input.infrastructureErrorCode || !isSafeCode(input.infrastructureErrorCode) ||
        input.verdict !== "NOT_EVALUATED") {
      throw new Error("invalid_infrastructure_failure_outcome");
    }
  } else if (input.infrastructureStatus === "SUCCEEDED") {
    if (input.infrastructureErrorCode !== undefined || input.verdict === "NOT_EVALUATED") {
      throw new Error("invalid_successful_infrastructure_outcome");
    }
  } else {
    throw new Error("invalid_infrastructure_status");
  }
  if (input.compilationStatus === "FAILED" && input.verdict !== "COMPILATION_ERROR") {
    throw new Error("compilation_failure_requires_compilation_error_verdict");
  }
  if (input.compilationStatus !== "FAILED" && input.verdict === "COMPILATION_ERROR") {
    throw new Error("compilation_error_requires_failed_compilation");
  }
  if (!Number.isSafeInteger(input.testsTotal) || input.testsTotal < 0 ||
      !Number.isSafeInteger(input.testsPassed) || input.testsPassed < 0 ||
      input.testsPassed > input.testsTotal) {
    throw new Error("invalid_execution_test_counts");
  }
  if (input.compilationStatus === "FAILED" && input.testsTotal !== 0) {
    throw new Error("compilation_failure_cannot_have_test_results");
  }
  if (input.verdict === "ACCEPTED" &&
      (input.testsTotal === 0 || input.testsPassed !== input.testsTotal)) {
    throw new Error("accepted_verdict_requires_all_tests_to_pass");
  }
  if (!Number.isSafeInteger(input.elapsedMs) || input.elapsedMs < 0) {
    throw new Error("invalid_execution_elapsed_time");
  }
  if (input.peakMemoryBytes !== undefined &&
      (!Number.isSafeInteger(input.peakMemoryBytes) || input.peakMemoryBytes < 0)) {
    throw new Error("invalid_execution_peak_memory");
  }
  if (!/^[A-Za-z0-9._+-]{1,64}$/.test(input.runnerVersion)) {
    throw new Error("invalid_execution_runner_version");
  }
  const startedAt = Date.parse(input.startedAt);
  const completedAt = Date.parse(input.completedAt);
  if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt) || startedAt > completedAt) {
    throw new Error("invalid_execution_result_time_order");
  }
}

/**
 * Persistence primitives for the proposed 0004 evidence schema.
 * All evidence writes are append-only. Final result writes additionally require
 * the current, unexpired PostgreSQL runner lease.
 */
export class PostgresExecutionEvidenceRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async appendEvent(
    input: AppendExecutionEvidenceEventInput,
  ): Promise<AppendedExecutionEvidenceEvent> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    validateEvent(input);

    return this.withClient(async (client) => {
      const inserted = await client.query<{ sequence_id: string | number }>(
        [
          "INSERT INTO execution_evidence_events",
          "  (event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
          "   event_type, actor_kind, phase_status, safe_code, duration_ms)",
          "SELECT $1::uuid, ej.id, ea.id, ea.tenant_id, ea.actor_user_id,",
          "  $4, $5, $6, $7, $8",
          "FROM execution_jobs AS ej",
          "INNER JOIN execution_attempts AS ea ON ea.id = ej.attempt_id",
          "WHERE ej.id = $2::uuid AND ea.id = $3::uuid",
          "ON CONFLICT (event_id) DO NOTHING",
          "RETURNING sequence_id",
        ].join("\n"),
        [
          input.eventId, input.executionId, input.attemptId, input.eventType,
          input.actorKind, input.phaseStatus ?? null, input.safeCode ?? null,
          input.durationMs ?? null,
        ],
      );

      const insertedRow = inserted.rows[0];
      if (insertedRow) {
        return { sequenceId: String(insertedRow.sequence_id), replayed: false };
      }

      const existing = await client.query<EventRow>(
        [
          "SELECT sequence_id, event_id, execution_id, attempt_id, event_type, actor_kind, phase_status,",
          "  safe_code, duration_ms, created_at",
          "FROM execution_evidence_events WHERE event_id = $1::uuid",
        ].join("\n"),
        [input.eventId],
      );
      const prior = existing.rows[0];
      if (!prior) throw new ExecutionEvidenceNotFoundError();
      if (
        prior.execution_id !== input.executionId ||
        prior.attempt_id !== input.attemptId ||
        prior.event_type !== input.eventType ||
        prior.actor_kind !== input.actorKind ||
        prior.phase_status !== (input.phaseStatus ?? null) ||
        prior.safe_code !== (input.safeCode ?? null) ||
        Number(prior.duration_ms ?? 0) !== (input.durationMs ?? 0)
      ) {
        throw new ExecutionEvidenceConflictError();
      }
      return { sequenceId: String(prior.sequence_id), replayed: true };
    });
  }

  async recordResult(input: RecordExecutionResultInput): Promise<RecordedExecutionResult> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    validateResult(input);

    const terminalState = input.infrastructureStatus === "FAILED"
      ? "FAILED_INFRASTRUCTURE"
      : "COMPLETED";
    const eventType: ExecutionEvidenceEventType = input.infrastructureStatus === "FAILED"
      ? "INFRASTRUCTURE_FAILED"
      : "EXECUTION_FINISHED";
    const safeCode = input.infrastructureErrorCode ??
      (input.cleanupStatus === "FAILED" ? "CLEANUP_FAILED" : `VERDICT_${input.verdict}`);

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        // Lock the job row first so concurrent completion retries serialize.
        // A waiter then observes the committed result and returns an idempotent replay.
        const job = await client.query<{ id: string }>(
          [
            "SELECT id FROM execution_jobs",
            "WHERE id = $1::uuid AND attempt_id = $2::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.executionId, input.attemptId],
        );
        if (job.rows.length !== 1) throw new ExecutionEvidenceNotFoundError();

        const existing = await client.query<ResultRow>(
          [
            "SELECT attempt_id, result_sha256",
            "FROM execution_result_records",
            "WHERE execution_id = $1::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.executionId],
        );
        const prior = existing.rows[0];
        if (prior) {
          if (prior.attempt_id !== input.attemptId ||
              prior.result_sha256.trim() !== input.resultSha256) {
            throw new ExecutionEvidenceConflictError();
          }
          await client.query("COMMIT");
          return {
            executionId: input.executionId,
            attemptId: input.attemptId,
            state: terminalState,
            resultSha256: input.resultSha256,
            replayed: true,
          };
        }

        const claimed = await client.query<UpdatedJobRow>(
          [
            "UPDATE execution_jobs",
            "SET state = $4,",
            "    state_version = state_version + 1,",
            "    completed_at = now(),",
            "    updated_at = now(),",
            "    lease_owner = NULL,",
            "    lease_token = NULL,",
            "    lease_expires_at = NULL",
            "WHERE id = $1::uuid AND attempt_id = $2::uuid",
            "  AND state = 'RUNNING'",
            "  AND lease_owner = $3",
            "  AND lease_token = $5::uuid",
            "  AND lease_expires_at > now()",
            "RETURNING id",
          ].join("\n"),
          [
            input.executionId, input.attemptId, input.leaseOwner, terminalState,
            input.leaseToken,
          ],
        );
        if (claimed.rows.length !== 1) throw new StaleExecutionLeaseError();

        const result = await client.query<UpdatedJobRow>(
          [
            "INSERT INTO execution_result_records (",
            "  execution_id, attempt_id, tenant_id, actor_user_id,",
            "  infrastructure_status, infrastructure_error_code, compilation_status,",
            "  verdict, cleanup_status, tests_total, tests_passed, elapsed_ms,",
            "  peak_memory_bytes, runner_version, runtime_image_digest, result_sha256,",
            "  started_at, completed_at",
            ")",
            "SELECT $1::uuid, ea.id, ea.tenant_id, ea.actor_user_id,",
            "  $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::timestamptz, $16::timestamptz",
            "FROM execution_attempts AS ea",
            "WHERE ea.id = $2::uuid",
            "RETURNING execution_id",
          ].join("\n"),
          [
            input.executionId, input.attemptId, input.infrastructureStatus,
            input.infrastructureErrorCode ?? null, input.compilationStatus, input.verdict,
            input.cleanupStatus, input.testsTotal, input.testsPassed, input.elapsedMs,
            input.peakMemoryBytes ?? null, input.runnerVersion, input.runtimeImageDigest ?? null,
            input.resultSha256, input.startedAt, input.completedAt,
          ],
        );
        if (result.rows.length !== 1) throw new ExecutionEvidenceNotFoundError();

        await client.query(
          [
            "INSERT INTO execution_evidence_events (",
            "  event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
            "  event_type, actor_kind, phase_status, safe_code, duration_ms",
            ")",
            "SELECT $1::uuid, ej.id, ea.id, ea.tenant_id, ea.actor_user_id,",
            "  $4, 'JUDGE', $5, $6, $7",
            "FROM execution_jobs AS ej",
            "INNER JOIN execution_attempts AS ea ON ea.id = ej.attempt_id",
            "WHERE ej.id = $2::uuid AND ea.id = $3::uuid",
          ].join("\n"),
          [
            crypto.randomUUID(), input.executionId, input.attemptId, eventType,
            input.infrastructureStatus === "FAILED" ? "FAILED" : "SUCCEEDED",
            safeCode, input.elapsedMs,
          ],
        );

        await client.query("COMMIT");
        return {
          executionId: input.executionId,
          attemptId: input.attemptId,
          state: terminalState,
          resultSha256: input.resultSha256,
          replayed: false,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof ExecutionEvidenceConflictError ||
          error instanceof ExecutionEvidenceNotFoundError ||
          error instanceof StaleExecutionLeaseError) {
        throw error;
      }
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  async listProblemAttemptHistory(
    tenantId: string,
    actorUserId: string,
    problemSlug: string,
    limit = 30,
  ): Promise<readonly ExecutionAttemptHistoryEntry[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!isUuid(tenantId) || !isUuid(actorUserId)) {
      throw new Error("invalid_execution_history_owner");
    }
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(problemSlug) || problemSlug.length > 64) {
      throw new Error("invalid_execution_history_problem");
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("invalid_execution_history_limit");
    }

    return this.withClient(async (client) => {
      const result = await client.query<HistoryRow>(
        [
          "SELECT ea.id AS attempt_id, ej.id AS execution_id, ea.action, ea.language,",
          "  ea.runtime_version, ea.source_sha256, ss.byte_length AS source_byte_length,",
          "  ea.created_at, ej.state AS execution_state,",
          "  rr.infrastructure_status, rr.compilation_status, rr.verdict, rr.cleanup_status,",
          "  rr.tests_total, rr.tests_passed, rr.elapsed_ms, rr.peak_memory_bytes, rr.result_sha256",
          "FROM execution_attempts AS ea",
          "INNER JOIN execution_jobs AS ej ON ej.attempt_id = ea.id",
          "INNER JOIN source_snapshots AS ss ON ss.id = ea.source_snapshot_id",
          "INNER JOIN problems AS p ON p.id = ea.problem_id",
          "LEFT JOIN execution_result_records AS rr ON rr.execution_id = ej.id",
          "WHERE ea.tenant_id = $1::uuid",
          "  AND ea.actor_user_id = $2::uuid",
          "  AND p.slug = $3",
          "ORDER BY ea.created_at DESC, ea.id DESC",
          "LIMIT $4",
        ].join("\n"),
        [tenantId, actorUserId, problemSlug, limit],
      );

      return result.rows.map((row) => ({
        attemptId: row.attempt_id,
        executionId: row.execution_id,
        action: row.action,
        language: row.language,
        runtimeVersion: row.runtime_version,
        sourceSha256: row.source_sha256.trim(),
        sourceByteLength: Number(row.source_byte_length),
        createdAt: isoTimestamp(row.created_at),
        executionState: row.execution_state,
        infrastructureStatus: row.infrastructure_status,
        compilationStatus: row.compilation_status,
        verdict: row.verdict,
        cleanupStatus: row.cleanup_status,
        testsTotal: row.tests_total,
        testsPassed: row.tests_passed,
        elapsedMs: row.elapsed_ms === null ? null : String(row.elapsed_ms),
        peakMemoryBytes: row.peak_memory_bytes === null ? null : String(row.peak_memory_bytes),
        resultSha256: row.result_sha256?.trim() ?? null,
      }));
    });
  }

  async listExecutionEvents(
    tenantId: string,
    actorUserId: string,
    executionId: string,
  ): Promise<readonly ExecutionEvidenceEvent[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!isUuid(tenantId) || !isUuid(actorUserId) || !isUuid(executionId)) {
      throw new Error("invalid_execution_evidence_scope");
    }

    return this.withClient(async (client) => {
      const result = await client.query<EventRow>(
        [
          "SELECT sequence_id, event_id, event_type, actor_kind, phase_status,",
          "  safe_code, duration_ms, created_at",
          "FROM execution_evidence_events",
          "WHERE execution_id = $1::uuid",
          "  AND tenant_id = $2::uuid AND actor_user_id = $3::uuid",
          "ORDER BY sequence_id ASC",
        ].join("\n"),
        [executionId, tenantId, actorUserId],
      );
      return result.rows.map((row) => ({
        sequenceId: String(row.sequence_id),
        eventId: row.event_id,
        eventType: row.event_type,
        actorKind: row.actor_kind,
        phaseStatus: row.phase_status,
        safeCode: row.safe_code,
        durationMs: row.duration_ms === null ? null : String(row.duration_ms),
        createdAt: isoTimestamp(row.created_at),
      }));
    });
  }

  private async withClient<T>(operation: (client: PgEvidenceClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof ExecutionEvidenceConflictError ||
          error instanceof ExecutionEvidenceNotFoundError ||
          error instanceof StaleExecutionLeaseError ||
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
