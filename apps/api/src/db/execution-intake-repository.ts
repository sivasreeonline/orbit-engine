import { Client } from "pg";
import type { Principal } from "../contracts";
import { DatabaseUnavailableError } from "./database-errors";
import { canonicalTestBundleIdentity, TestBundleEncodingError, type CanonicalTestBundleCase } from "./canonical-test-bundle";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import { buildExecutionProtocolV2Request } from "../security/execution-protocol-v2-request";

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
  readonly testBundleId: string;
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

export class ExecutionProblemNotFoundError extends Error {
  constructor() {
    super("execution_problem_not_found");
    this.name = "ExecutionProblemNotFoundError";
  }
}

export class ExecutionTestBundleIntegrityError extends Error {
  constructor(message = "execution_test_bundle_integrity_failed") {
    super(message);
    this.name = "ExecutionTestBundleIntegrityError";
  }
}

export class ExecutionProtocolRequestIntegrityError extends Error {
  constructor(message = "execution_protocol_request_integrity_failed") {
    super(message);
    this.name = "ExecutionProtocolRequestIntegrityError";
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
  readonly problem_version_id: string;
  readonly protocol_version?: string;
  readonly protocol_request_bytes?: Uint8Array | null;
  readonly protocol_request_sha256?: string | null;
  readonly protocol_request_correlation_id?: string | null;
  readonly outbox_correlation_id?: string | null;
}

interface TestCaseRow extends Record<string, unknown> {
  readonly id: string;
  readonly sequence: number;
  readonly visibility: "PUBLIC" | "HIDDEN";
  readonly input_data: Uint8Array;
  readonly expected_output: Uint8Array;
}

const MAX_TEST_CASES = 200;
const MAX_TEST_BUNDLE_BYTES = 1024 * 1024;

function decodeTestBytes(value: Uint8Array, field: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    throw new ExecutionTestBundleIntegrityError(`${field}_invalid_utf8`);
  }
}

async function loadTestBundleIdentity(
  client: PgTransactionClient,
  problemVersionId: string,
  action: ExecutionAction,
): Promise<string> {
  const result = await client.query<TestCaseRow>(
    [
      "SELECT id, sequence, visibility, input_data, expected_output",
      "FROM problem_test_cases",
      "WHERE problem_version_id = $1::uuid",
      "  AND ($2::varchar = 'SUBMIT' OR visibility = 'PUBLIC')",
      "ORDER BY sequence",
      "LIMIT $3",
    ].join("\n"),
    [problemVersionId, action, MAX_TEST_CASES + 1],
  );
  if (result.rows.length < 1 || result.rows.length > MAX_TEST_CASES) {
    throw new ExecutionTestBundleIntegrityError("execution_test_case_count_invalid");
  }

  let totalBytes = 0;
  const testCases: CanonicalTestBundleCase[] = result.rows.map((row) => {
    const inputBytes = new Uint8Array(row.input_data);
    const outputBytes = new Uint8Array(row.expected_output);
    totalBytes += inputBytes.byteLength + outputBytes.byteLength;
    if (totalBytes > MAX_TEST_BUNDLE_BYTES) {
      throw new ExecutionTestBundleIntegrityError("execution_test_bundle_too_large");
    }
    if (row.visibility !== "PUBLIC" && row.visibility !== "HIDDEN") {
      throw new ExecutionTestBundleIntegrityError("execution_test_case_visibility_invalid");
    }
    return {
      testCaseId: row.id,
      sequence: row.sequence,
      visibility: row.visibility,
      input: decodeTestBytes(inputBytes, "test_input"),
      expectedOutput: decodeTestBytes(outputBytes, "test_expected_output"),
    };
  });

  try {
    const identity = await canonicalTestBundleIdentity(problemVersionId, action, testCases);
    return identity.testBundleId;
  } catch (error) {
    if (error instanceof TestBundleEncodingError) {
      throw new ExecutionTestBundleIntegrityError(error.message);
    }
    throw error;
  }
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

async function sha256Bytes(value: Uint8Array): Promise<string> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return toHex(new Uint8Array(digest));
}

function persistedProtocolTestBundleId(row: ExistingExecutionRow): string {
  if (!row.protocol_request_bytes || !row.protocol_request_sha256) {
    throw new ExecutionProtocolRequestIntegrityError("persisted_protocol_request_missing");
  }
  const bytes = new Uint8Array(row.protocol_request_bytes);
  let document: Record<string, unknown>;
  try {
    const documentText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    document = JSON.parse(documentText) as Record<string, unknown>;
  } catch {
    throw new ExecutionProtocolRequestIntegrityError("persisted_protocol_request_encoding_invalid");
  }
  if (document.protocolVersion !== "v2" ||
      document.executionId !== row.execution_id ||
      document.attemptId !== row.attempt_id ||
      document.correlationId !== row.protocol_request_correlation_id ||
      document.correlationId !== row.outbox_correlation_id ||
      typeof document.testBundleId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(document.testBundleId)) {
    throw new ExecutionProtocolRequestIntegrityError("persisted_protocol_request_invalid");
  }
  return document.testBundleId;
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
 * Transactional persistence for the proposal-stage execution intake schema.
 * V2 persistence is opt-in; the outbox publisher deliberately remains v1-only.
 */
export class PostgresExecutionIntakeRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
    private readonly protocolV2Policy: ExecutionProtocolV2Policy | null = null,
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
            "SELECT ei.attempt_id, ej.id AS execution_id, ei.request_sha256, attempt.problem_version_id,",
            "  eo.protocol_version, eo.correlation_id AS outbox_correlation_id,",
            "  v2.request_bytes AS protocol_request_bytes,",
            "  v2.request_sha256 AS protocol_request_sha256,",
            "  v2.correlation_id::text AS protocol_request_correlation_id",
            "FROM execution_idempotency AS ei",
            "INNER JOIN execution_jobs AS ej ON ej.attempt_id = ei.attempt_id",
            "INNER JOIN execution_attempts AS attempt ON attempt.id = ei.attempt_id",
            "LEFT JOIN execution_outbox AS eo ON eo.execution_id = ej.id",
            "LEFT JOIN execution_protocol_requests AS v2 ON v2.execution_id = ej.id",
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
          let testBundleId: string;
          if (prior.protocol_version === "v2") {
            if (await sha256Bytes(new Uint8Array(prior.protocol_request_bytes ?? [])) !==
                (prior.protocol_request_sha256 ?? "").trim()) {
              throw new ExecutionProtocolRequestIntegrityError("persisted_protocol_request_digest_invalid");
            }
            testBundleId = persistedProtocolTestBundleId(prior);
          } else {
            testBundleId = await loadTestBundleIdentity(
              client,
              prior.problem_version_id,
              input.action,
            );
          }
          await client.query("COMMIT");
          return {
            executionId: prior.execution_id,
            attemptId: prior.attempt_id,
            testBundleId,
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

        // Match the runner artifact repository's visibility filter, ordering,
        // byte limits and canonical encoder before any durable intake writes.
        const testBundleId = await loadTestBundleIdentity(
          client,
          selectedProblem.problem_version_id,
          input.action,
        );

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

        let protocolVersion: "v1" | "v2" = "v1";
        let outboxCorrelationId = input.correlationId;
        if (this.protocolV2Policy) {
          const built = await buildExecutionProtocolV2Request({
            executionId,
            attemptId,
            problemVersionId: selectedProblem.problem_version_id,
            action: input.action,
            language: input.language,
            runtimeVersion: input.runtimeVersion,
            sourceArtifactId: snapshotId,
            sourceSha256: sourceHash,
            testBundleId,
            intakeAt: new Date(),
          }, this.protocolV2Policy);
          await client.query(
            [
              "INSERT INTO execution_protocol_requests",
              "  (execution_id, attempt_id, protocol_version, correlation_id, intake_at,",
              "   deadline_at, policy_revision, request_sha256, request_bytes)",
              "VALUES ($1::uuid, $2::uuid, 'v2', $3::uuid, $4::timestamptz,",
              "   $5::timestamptz, $6, $7, $8)",
            ].join("\n"),
            [
              executionId, attemptId, built.request.correlationId,
              built.intakeAt.toISOString(), built.request.deadlineAt,
              this.protocolV2Policy.policyRevision, built.requestSha256, built.requestBytes,
            ],
          );
          protocolVersion = "v2";
          outboxCorrelationId = built.request.correlationId;
        }

        const payload = JSON.stringify({
          executionId,
          attemptId,
          protocolVersion,
        });
        await client.query(
          [
            "INSERT INTO execution_outbox",
            "  (execution_id, event_type, protocol_version, correlation_id, payload)",
            "VALUES ($1::uuid, 'EXECUTION_REQUESTED', $2, $3, $4::jsonb)",
          ].join("\n"),
          [executionId, protocolVersion, outboxCorrelationId, payload],
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
        return { executionId, attemptId, testBundleId, replayed: false };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    } catch (error) {
      if (error instanceof IdempotencyConflictError ||
          error instanceof ExecutionProblemNotFoundError ||
          error instanceof ExecutionTestBundleIntegrityError ||
          error instanceof ExecutionProtocolRequestIntegrityError) {
        throw error;
      }
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
