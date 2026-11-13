import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

const MAX_SOURCE_BYTES = 256 * 1024;
const MAX_TEST_CASES = 200;
const MAX_TEST_BUNDLE_BYTES = 1024 * 1024;

export interface FetchRunnerArtifactInput {
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly leaseToken: string;
  readonly runnerId: string;
  readonly keyId: string;
}

export interface RunnerArtifactTestCase {
  readonly testCaseId: string;
  readonly sequence: number;
  readonly visibility: "PUBLIC" | "HIDDEN";
  readonly input: string;
  readonly expectedOutput: string;
}

export interface RunnerExecutionArtifact {
  readonly executionId: string;
  readonly attemptId: string;
  readonly problemVersionId: string;
  readonly problemSlug: string;
  readonly problemTitle: string;
  readonly action: "RUN" | "SUBMIT";
  readonly language: "java" | "python";
  readonly runtimeVersion: string;
  readonly sourceArtifactId: string;
  readonly sourceSha256: string;
  readonly sourceCode: string;
  readonly testBundleId: string;
  readonly testBundleSha256: string;
  readonly testCases: readonly RunnerArtifactTestCase[];
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgArtifactClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgArtifactClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-private-artifact",
  }) as unknown as PgArtifactClient;

interface ArtifactRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly delivery_state: string;
  readonly dispatch_owner: string | null;
  readonly dispatch_token: string | null;
  readonly dispatch_expires_at: Date | string | null;
  readonly job_state: string;
  readonly job_owner: string | null;
  readonly job_token: string | null;
  readonly job_expires_at: Date | string | null;
  readonly attempt_tenant_id: string;
  readonly attempt_actor_user_id: string;
  readonly action: "RUN" | "SUBMIT";
  readonly language: "java" | "python";
  readonly runtime_version: string;
  readonly problem_version_id: string;
  readonly problem_slug: string;
  readonly problem_title: string;
  readonly source_snapshot_id: string;
  readonly attempt_source_sha256: string;
  readonly snapshot_sha256: string;
  readonly snapshot_byte_length: string | number;
  readonly storage_kind: string;
  readonly source_bytes: Uint8Array | null;
  readonly acceptance_id: string | null;
  readonly accepted_runner_id: string | null;
  readonly accepted_key_id: string | null;
  readonly start_event_id: string | null;
  readonly started_runner_id: string | null;
  readonly started_key_id: string | null;
}

interface TestCaseRow extends Record<string, unknown> {
  readonly id: string;
  readonly sequence: number;
  readonly visibility: "PUBLIC" | "HIDDEN";
  readonly input_data: Uint8Array;
  readonly expected_output: Uint8Array;
}

interface RunnerKeyRow extends Record<string, unknown> {
  readonly key_id: string;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function timestampMs(value: Date | string | null): number {
  if (value === null) return 0;
  const parsed = value instanceof Date ? value : new Date(value);
  return parsed.getTime();
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer)));
}

function decodeUtf8(value: Uint8Array, field: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    throw new RunnerArtifactIntegrityError(`${field}_invalid_utf8`);
  }
}

export class RunnerArtifactNotFoundError extends Error {
  constructor() {
    super("runner_artifact_dispatch_not_found");
    this.name = "RunnerArtifactNotFoundError";
  }
}

export class RunnerArtifactUnauthorizedError extends Error {
  constructor() {
    super("runner_artifact_machine_not_authorized");
    this.name = "RunnerArtifactUnauthorizedError";
  }
}

export class RunnerArtifactNotStartedError extends Error {
  constructor() {
    super("runner_artifact_start_required");
    this.name = "RunnerArtifactNotStartedError";
  }
}

export class RunnerArtifactStaleLeaseError extends Error {
  constructor() {
    super("runner_artifact_stale_lease");
    this.name = "RunnerArtifactStaleLeaseError";
  }
}

export class RunnerArtifactNotStartedError extends Error {
  constructor() {
    super("runner_artifact_start_required");
    this.name = "RunnerArtifactNotStartedError";
  }
}

export class RunnerArtifactStorageUnavailableError extends Error {
  constructor() {
    super("runner_artifact_storage_unavailable");
    this.name = "RunnerArtifactStorageUnavailableError";
  }
}

export class RunnerArtifactIntegrityError extends Error {
  constructor(message = "runner_artifact_integrity_failed") {
    super(message);
    this.name = "RunnerArtifactIntegrityError";
  }
}

/**
 * Resolves source and the immutable problem-version test bundle only for the
 * active runner/lease that has durable acceptance and start receipts. R2
 * artifacts fail closed in this first database-local implementation.
 */
export class PostgresRunnerArtifactRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async fetch(input: FetchRunnerArtifactInput): Promise<RunnerExecutionArtifact> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validate(input);

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        const key = await client.query<RunnerKeyRow>(
          [
            "SELECT machine_key.key_id",
            "FROM runner_machine_keys AS machine_key",
            "INNER JOIN runner_machines AS machine ON machine.id = machine_key.runner_id",
            "WHERE machine_key.key_id = $1 AND machine_key.runner_id = $2::uuid",
            "  AND machine.status = 'ACTIVE' AND machine_key.status = 'ACTIVE'",
            "  AND machine_key.revoked_at IS NULL",
            "  AND machine_key.valid_from <= clock_timestamp()",
            "  AND (machine_key.expires_at IS NULL OR machine_key.expires_at > clock_timestamp())",
            "FOR UPDATE OF machine_key, machine",
          ].join("\n"),
          [input.keyId, input.runnerId],
        );
        if (key.rows.length !== 1) throw new RunnerArtifactUnauthorizedError();

        const result = await client.query<ArtifactRow>(
          [
            "SELECT dispatch.id AS dispatch_id, dispatch.execution_id, dispatch.attempt_id,",
            "  dispatch.delivery_state, dispatch.lease_owner AS dispatch_owner,",
            "  dispatch.lease_token::text AS dispatch_token, dispatch.lease_expires_at AS dispatch_expires_at,",
            "  job.state AS job_state, job.lease_owner AS job_owner,",
            "  job.lease_token::text AS job_token, job.lease_expires_at AS job_expires_at,",
            "  attempt.tenant_id AS attempt_tenant_id, attempt.actor_user_id AS attempt_actor_user_id,",
            "  attempt.action, attempt.language, attempt.runtime_version, attempt.problem_version_id,",
            "  problem.slug AS problem_slug, version.title AS problem_title,",
            "  attempt.source_snapshot_id, attempt.source_sha256 AS attempt_source_sha256,",
            "  snapshot.sha256 AS snapshot_sha256, snapshot.byte_length AS snapshot_byte_length,",
            "  snapshot.storage_kind, snapshot.source_bytes,",
            "  accepted.acceptance_id::text AS acceptance_id, accepted.runner_id::text AS accepted_runner_id,",
            "  accepted.key_id AS accepted_key_id,",
            "  started.event_id::text AS start_event_id, started.runner_id::text AS started_runner_id,",
            "  started.key_id AS started_key_id",
            "FROM runner_dispatch_outbox AS dispatch",
            "INNER JOIN execution_jobs AS job ON job.id = dispatch.execution_id",
            "INNER JOIN execution_attempts AS attempt ON attempt.id = dispatch.attempt_id",
            "INNER JOIN problems AS problem ON problem.id = attempt.problem_id",
            "INNER JOIN problem_versions AS version",
            "  ON version.id = attempt.problem_version_id AND version.problem_id = attempt.problem_id",
            "INNER JOIN source_snapshots AS snapshot ON snapshot.id = attempt.source_snapshot_id",
            "LEFT JOIN runner_dispatch_acceptances AS accepted",
            "  ON accepted.dispatch_id = dispatch.id AND accepted.lease_token = dispatch.lease_token",
            "LEFT JOIN runner_dispatch_starts AS started",
            "  ON started.dispatch_id = dispatch.id AND started.lease_token = dispatch.lease_token",
            "WHERE dispatch.id = $1::uuid AND dispatch.execution_id = $2::uuid",
            "  AND dispatch.attempt_id = $3::uuid AND job.attempt_id = $3::uuid",
            "  AND accepted.runner_id = $4::uuid AND accepted.key_id = $5",
            "  AND started.runner_id = $4::uuid AND started.key_id = $5",
            "FOR UPDATE OF dispatch, job",
          ].join("\n"),
          [
            input.dispatchId, input.executionId, input.attemptId,
            input.runnerId, input.keyId,
          ],
        );
        const artifact = result.rows[0];
        if (!artifact) throw new RunnerArtifactNotFoundError();

        if (!artifact.acceptance_id || !artifact.start_event_id) {
          throw new RunnerArtifactNotStartedError();
        }
        if (artifact.accepted_runner_id !== input.runnerId ||
            artifact.accepted_key_id !== input.keyId ||
            artifact.started_runner_id !== input.runnerId ||
            artifact.started_key_id !== input.keyId) {
          throw new RunnerArtifactUnauthorizedError();
        }

        if (artifact.delivery_state !== "PENDING" ||
            artifact.dispatch_owner !== input.runnerId ||
            artifact.dispatch_token !== input.leaseToken ||
            artifact.job_state !== "RUNNING" ||
            artifact.job_owner !== input.runnerId ||
            artifact.job_token !== input.leaseToken ||
            !Number.isFinite(timestampMs(artifact.dispatch_expires_at)) ||
            timestampMs(artifact.dispatch_expires_at) <= Date.now() ||
            !Number.isFinite(timestampMs(artifact.job_expires_at)) ||
            timestampMs(artifact.job_expires_at) <= Date.now()) {
          throw new RunnerArtifactStaleLeaseError();
        }

        if (artifact.storage_kind !== "DATABASE" || artifact.source_bytes === null) {
          throw new RunnerArtifactStorageUnavailableError();
        }
        const sourceBytes = new Uint8Array(artifact.source_bytes);
        const declaredSourceLength = Number(artifact.snapshot_byte_length);
        if (!Number.isSafeInteger(declaredSourceLength) ||
            declaredSourceLength < 0 || declaredSourceLength > MAX_SOURCE_BYTES ||
            sourceBytes.byteLength !== declaredSourceLength) {
          throw new RunnerArtifactIntegrityError("runner_artifact_source_size_invalid");
        }
        const computedSourceHash = await sha256(sourceBytes);
        if (computedSourceHash !== artifact.snapshot_sha256.trim() ||
            computedSourceHash !== artifact.attempt_source_sha256.trim()) {
          throw new RunnerArtifactIntegrityError("runner_artifact_source_hash_mismatch");
        }
        const sourceCode = decodeUtf8(sourceBytes, "source_code");

        const testResult = await client.query<TestCaseRow>(
          [
            "SELECT id, sequence, visibility, input_data, expected_output",
            "FROM problem_test_cases",
            "WHERE problem_version_id = $1::uuid",
            "  AND ($2::varchar = 'SUBMIT' OR visibility = 'PUBLIC')",
            "ORDER BY sequence",
            "LIMIT $3",
          ].join("\n"),
          [artifact.problem_version_id, artifact.action, MAX_TEST_CASES + 1],
        );
        if (testResult.rows.length < 1 || testResult.rows.length > MAX_TEST_CASES) {
          throw new RunnerArtifactIntegrityError("runner_artifact_test_case_count_invalid");
        }

        let totalTestBytes = 0;
        const testCases: RunnerArtifactTestCase[] = testResult.rows.map((row) => {
          const inputBytes = new Uint8Array(row.input_data);
          const outputBytes = new Uint8Array(row.expected_output);
          totalTestBytes += inputBytes.byteLength + outputBytes.byteLength;
          if (totalTestBytes > MAX_TEST_BUNDLE_BYTES) {
            throw new RunnerArtifactIntegrityError("runner_artifact_test_bundle_too_large");
          }
          return {
            testCaseId: row.id,
            sequence: row.sequence,
            visibility: row.visibility,
            input: decodeUtf8(inputBytes, "test_input"),
            expectedOutput: decodeUtf8(outputBytes, "test_expected_output"),
          };
        });

        const canonicalTestBundle = JSON.stringify(testCases.map((testCase) => ({
          testCaseId: testCase.testCaseId,
          sequence: testCase.sequence,
          visibility: testCase.visibility,
          input: testCase.input,
          expectedOutput: testCase.expectedOutput,
        })));
        const testBundleSha256 = await sha256(new TextEncoder().encode(canonicalTestBundle));

        await client.query("COMMIT");
        return {
          executionId: artifact.execution_id,
          attemptId: artifact.attempt_id,
          problemVersionId: artifact.problem_version_id,
          problemSlug: artifact.problem_slug,
          problemTitle: artifact.problem_title,
          action: artifact.action,
          language: artifact.language,
          runtimeVersion: artifact.runtime_version,
          sourceArtifactId: artifact.source_snapshot_id,
          sourceSha256: computedSourceHash,
          sourceCode,
          testBundleId: `${artifact.problem_version_id}-${artifact.action.toLowerCase()}-${testBundleSha256.slice(0, 16)}`,
          testBundleSha256,
          testCases,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof RunnerArtifactNotFoundError ||
          error instanceof RunnerArtifactUnauthorizedError ||
          error instanceof RunnerArtifactNotStartedError ||
          error instanceof RunnerArtifactStaleLeaseError ||
          error instanceof RunnerArtifactStorageUnavailableError ||
          error instanceof RunnerArtifactIntegrityError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private validate(input: FetchRunnerArtifactInput): void {
    if (!input || !isUuid(input.dispatchId) || !isUuid(input.executionId) ||
        !isUuid(input.attemptId) || !isUuid(input.leaseToken) ||
        !isUuid(input.runnerId) || !/^[A-Za-z0-9._:-]{1,128}$/.test(input.keyId)) {
      throw new Error("invalid_runner_artifact_fetch_input");
    }
  }

  private async withClient<T>(operation: (client: PgArtifactClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '8s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof RunnerArtifactNotFoundError ||
          error instanceof RunnerArtifactUnauthorizedError ||
          error instanceof RunnerArtifactNotStartedError ||
          error instanceof RunnerArtifactStaleLeaseError ||
          error instanceof RunnerArtifactStorageUnavailableError ||
          error instanceof RunnerArtifactIntegrityError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
