import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface RecoverExpiredRunnerLeasesInput {
  readonly workerId: string;
  readonly batchSize?: number;
  /** Number of requeues permitted after the initial lease. */
  readonly maxRetries?: number;
  readonly baseDelaySeconds?: number;
  readonly maxDelaySeconds?: number;
}

export interface RecoveredRunnerLease {
  readonly recoveryId: string;
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly action: "REQUEUED" | "FAILED_INFRASTRUCTURE";
  readonly retryCount: number;
  readonly availableAt: string | null;
  readonly resultSha256: string | null;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgRecoveryClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgRecoveryClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-expiry-recovery",
  }) as unknown as PgRecoveryClient;

interface ExpiredLeaseRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly lease_token: string;
  readonly runner_id: string;
  readonly key_id: string;
  readonly retry_count: number;
  readonly dispatch_lease_expires_at: Date | string;
  readonly job_lease_expires_at: Date | string;
}

interface QueuedRow extends Record<string, unknown> {
  readonly available_at: Date | string;
  readonly retry_count: number;
}

interface TerminalRow extends Record<string, unknown> {
  readonly started_at: Date | string;
  readonly completed_at: Date | string;
  readonly retry_count: number;
}

interface UpdatedRow extends Record<string, unknown> {
  readonly id: string;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function toIso(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("invalid_runner_recovery_timestamp");
  return date.toISOString();
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer)));
}

/**
 * Reconciles expired RUNNING leases under row locks. The first two expiries
 * (by default) requeue the same execution with a new lease generation. The
 * next expiry becomes a durable infrastructure failure. Each old generation
 * receives one immutable recovery receipt, preventing duplicate sweeps.
 */
export class PostgresRunnerRecoveryRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async recoverExpiredRunning(
    input: RecoverExpiredRunnerLeasesInput,
  ): Promise<readonly RecoveredRunnerLease[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validate(input);

    const batchSize = input.batchSize ?? 25;
    const maxRetries = input.maxRetries ?? 2;
    const baseDelaySeconds = input.baseDelaySeconds ?? 5;
    const maxDelaySeconds = input.maxDelaySeconds ?? 60;

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        const expired = await client.query<ExpiredLeaseRow>(
          [
            "SELECT dispatch.id AS dispatch_id, dispatch.execution_id, dispatch.attempt_id,",
            "  dispatch.lease_token::text AS lease_token, start.runner_id::text AS runner_id,",
            "  start.key_id, job.retry_count,",
            "  dispatch.lease_expires_at AS dispatch_lease_expires_at,",
            "  job.lease_expires_at AS job_lease_expires_at",
            "FROM runner_dispatch_outbox AS dispatch",
            "INNER JOIN execution_jobs AS job ON job.id = dispatch.execution_id",
            "INNER JOIN runner_dispatch_starts AS start",
            "  ON start.dispatch_id = dispatch.id AND start.lease_token = dispatch.lease_token",
            "WHERE dispatch.delivery_state = 'PENDING'",
            "  AND job.state = 'RUNNING'",
            "  AND dispatch.lease_token IS NOT NULL AND job.lease_token = dispatch.lease_token",
            "  AND dispatch.lease_owner = start.runner_id::text",
            "  AND job.lease_owner = start.runner_id::text",
            "  AND dispatch.lease_expires_at IS NOT NULL AND job.lease_expires_at IS NOT NULL",
            "  AND (dispatch.lease_expires_at <= clock_timestamp()",
            "    OR job.lease_expires_at <= clock_timestamp())",
            "ORDER BY LEAST(dispatch.lease_expires_at, job.lease_expires_at), dispatch.id",
            "LIMIT $1",
            "FOR UPDATE OF dispatch, job SKIP LOCKED",
          ].join("\n"),
          [batchSize],
        );

        const recovered: RecoveredRunnerLease[] = [];
        for (const lease of expired.rows) {
          const priorExpiry = new Date(Math.min(
            new Date(lease.dispatch_lease_expires_at).getTime(),
            new Date(lease.job_lease_expires_at).getTime(),
          ));
          if (!Number.isFinite(priorExpiry.getTime())) {
            throw new Error("invalid_expired_runner_lease_timestamp");
          }

          const recoveryId = crypto.randomUUID();
          const eventId = crypto.randomUUID();

          if (lease.retry_count < maxRetries) {
            const retryCount = lease.retry_count + 1;
            const exponent = Math.min(lease.retry_count, 16);
            const delaySeconds = Math.min(maxDelaySeconds, baseDelaySeconds * (2 ** exponent));
            const queued = await client.query<QueuedRow>(
              [
                "UPDATE execution_jobs",
                "SET state = 'QUEUED', state_version = state_version + 1,",
                "    retry_count = retry_count + 1,",
                "    available_at = clock_timestamp() + make_interval(secs => $4),",
                "    started_at = NULL, completed_at = NULL, updated_at = clock_timestamp(),",
                "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
                "WHERE id = $1::uuid AND attempt_id = $2::uuid",
                "  AND state = 'RUNNING' AND lease_token = $3::uuid",
                "  AND lease_expires_at <= clock_timestamp()",
                "RETURNING available_at, retry_count",
              ].join("\n"),
              [lease.execution_id, lease.attempt_id, lease.lease_token, delaySeconds],
            );
            const queuedRow = queued.rows[0];
            if (!queuedRow || queuedRow.retry_count !== retryCount) {
              throw new Error("runner_recovery_job_requeue_conflict");
            }
            const availableAt = toIso(queuedRow.available_at);

            const released = await client.query<UpdatedRow>(
              [
                "UPDATE runner_dispatch_outbox",
                "SET available_at = $4::timestamptz,",
                "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
                "WHERE id = $1::uuid AND execution_id = $2::uuid AND attempt_id = $3::uuid",
                "  AND delivery_state = 'PENDING' AND lease_token = $5::uuid",
                "  AND lease_expires_at <= clock_timestamp()",
                "RETURNING id",
              ].join("\n"),
              [lease.dispatch_id, lease.execution_id, lease.attempt_id, availableAt, lease.lease_token],
            );
            if (released.rows.length !== 1) throw new Error("runner_recovery_dispatch_release_conflict");

            await client.query(
              [
                "INSERT INTO execution_evidence_events (",
                "  event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
                "  event_type, actor_kind, phase_status, safe_code, duration_ms",
                ")",
                "SELECT $1::uuid, job.id, attempt.id, attempt.tenant_id, attempt.actor_user_id,",
                "  'RETRY_SCHEDULED', 'SYSTEM', 'SUCCEEDED', 'RUNNER_LEASE_EXPIRED', NULL",
                "FROM execution_jobs AS job",
                "INNER JOIN execution_attempts AS attempt ON attempt.id = job.attempt_id",
                "WHERE job.id = $2::uuid AND attempt.id = $3::uuid",
              ].join("\n"),
              [eventId, lease.execution_id, lease.attempt_id],
            );

            await client.query(
              [
                "INSERT INTO runner_dispatch_recoveries (",
                "  recovery_id, dispatch_id, lease_token, execution_id, attempt_id,",
                "  runner_id, key_id, recovery_worker_id, event_id, recovery_action,",
                "  retry_count, prior_lease_expires_at, available_at",
                ")",
                "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,",
                "  $6::uuid, $7, $8, $9::uuid, 'REQUEUED', $10, $11::timestamptz, $12::timestamptz)",
              ].join("\n"),
              [
                recoveryId, lease.dispatch_id, lease.lease_token, lease.execution_id,
                lease.attempt_id, lease.runner_id, lease.key_id, input.workerId,
                eventId, retryCount, priorExpiry.toISOString(), availableAt,
              ],
            );

            recovered.push({
              recoveryId,
              dispatchId: lease.dispatch_id,
              executionId: lease.execution_id,
              attemptId: lease.attempt_id,
              action: "REQUEUED",
              retryCount,
              availableAt,
              resultSha256: null,
            });
            continue;
          }

          const terminal = await client.query<TerminalRow>(
            [
              "UPDATE execution_jobs",
              "SET state = 'FAILED_INFRASTRUCTURE', state_version = state_version + 1,",
              "    completed_at = clock_timestamp(), updated_at = clock_timestamp(),",
              "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
              "WHERE id = $1::uuid AND attempt_id = $2::uuid",
              "  AND state = 'RUNNING' AND lease_token = $3::uuid",
              "  AND lease_expires_at <= clock_timestamp()",
              "RETURNING started_at, completed_at, retry_count",
            ].join("\n"),
            [lease.execution_id, lease.attempt_id, lease.lease_token],
          );
          const terminalRow = terminal.rows[0];
          if (!terminalRow || terminalRow.started_at === null) {
            throw new Error("runner_recovery_terminal_transition_conflict");
          }

          const deadLetter = await client.query<UpdatedRow>(
            [
              "UPDATE runner_dispatch_outbox",
              "SET delivery_state = 'DEAD_LETTER',",
              "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
              "WHERE id = $1::uuid AND execution_id = $2::uuid AND attempt_id = $3::uuid",
              "  AND delivery_state = 'PENDING' AND lease_token = $4::uuid",
              "  AND lease_expires_at <= clock_timestamp()",
              "RETURNING id",
            ].join("\n"),
            [lease.dispatch_id, lease.execution_id, lease.attempt_id, lease.lease_token],
          );
          if (deadLetter.rows.length !== 1) throw new Error("runner_recovery_dead_letter_conflict");

          const resultSha256 = await sha256(JSON.stringify({
            schema: "SKYHIGH-RUNNER-RECOVERY-RESULT-V1",
            executionId: lease.execution_id,
            attemptId: lease.attempt_id,
            dispatchId: lease.dispatch_id,
            leaseToken: lease.lease_token,
            recoveryId,
            reason: "RUNNER_LEASE_EXPIRED",
            retryCount: terminalRow.retry_count,
          }));

          const insertedResult = await client.query<UpdatedRow>(
            [
              "INSERT INTO execution_result_records (",
              "  execution_id, attempt_id, tenant_id, actor_user_id,",
              "  infrastructure_status, infrastructure_error_code, compilation_status,",
              "  verdict, cleanup_status, tests_total, tests_passed, elapsed_ms,",
              "  peak_memory_bytes, runner_version, runtime_image_digest, result_sha256,",
              "  started_at, completed_at",
              ")",
              "SELECT job.id, attempt.id, attempt.tenant_id, attempt.actor_user_id,",
              "  'FAILED', 'RUNNER_LEASE_EXPIRED', 'NOT_STARTED', 'NOT_EVALUATED',",
              "  'UNKNOWN', 0, 0, 0, NULL, 'control-plane-recovery', NULL, $3,",
              "  $4::timestamptz, $5::timestamptz",
              "FROM execution_jobs AS job",
              "INNER JOIN execution_attempts AS attempt ON attempt.id = job.attempt_id",
              "WHERE job.id = $1::uuid AND attempt.id = $2::uuid",
              "RETURNING execution_id",
            ].join("\n"),
            [
              lease.execution_id, lease.attempt_id, resultSha256,
              toIso(terminalRow.started_at), toIso(terminalRow.completed_at),
            ],
          );
          if (insertedResult.rows.length !== 1) throw new Error("runner_recovery_result_insert_failed");

          await client.query(
            [
              "INSERT INTO execution_evidence_events (",
              "  event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
              "  event_type, actor_kind, phase_status, safe_code, duration_ms",
              ")",
              "SELECT $1::uuid, job.id, attempt.id, attempt.tenant_id, attempt.actor_user_id,",
              "  'INFRASTRUCTURE_FAILED', 'SYSTEM', 'FAILED', 'RUNNER_LEASE_EXPIRED', 0",
              "FROM execution_jobs AS job",
              "INNER JOIN execution_attempts AS attempt ON attempt.id = job.attempt_id",
              "WHERE job.id = $2::uuid AND attempt.id = $3::uuid",
            ].join("\n"),
            [eventId, lease.execution_id, lease.attempt_id],
          );

          await client.query(
            [
              "INSERT INTO runner_dispatch_recoveries (",
              "  recovery_id, dispatch_id, lease_token, execution_id, attempt_id,",
              "  runner_id, key_id, recovery_worker_id, event_id, recovery_action,",
              "  retry_count, prior_lease_expires_at, available_at",
              ")",
              "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,",
              "  $6::uuid, $7, $8, $9::uuid, 'FAILED_INFRASTRUCTURE', $10, $11::timestamptz, NULL)",
            ].join("\n"),
            [
              recoveryId, lease.dispatch_id, lease.lease_token, lease.execution_id,
              lease.attempt_id, lease.runner_id, lease.key_id, input.workerId,
              eventId, terminalRow.retry_count, priorExpiry.toISOString(),
            ],
          );

          recovered.push({
            recoveryId,
            dispatchId: lease.dispatch_id,
            executionId: lease.execution_id,
            attemptId: lease.attempt_id,
            action: "FAILED_INFRASTRUCTURE",
            retryCount: terminalRow.retry_count,
            availableAt: null,
            resultSha256,
          });
        }

        await client.query("COMMIT");
        return recovered;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private validate(input: RecoverExpiredRunnerLeasesInput): void {
    if (!input || !/^[A-Za-z0-9._:-]{1,128}$/.test(input.workerId)) {
      throw new Error("invalid_runner_recovery_worker_id");
    }
    const batchSize = input.batchSize ?? 25;
    const maxRetries = input.maxRetries ?? 2;
    const baseDelaySeconds = input.baseDelaySeconds ?? 5;
    const maxDelaySeconds = input.maxDelaySeconds ?? 60;
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100 ||
        !Number.isSafeInteger(maxRetries) || maxRetries < 0 || maxRetries > 10 ||
        !Number.isSafeInteger(baseDelaySeconds) || baseDelaySeconds < 1 || baseDelaySeconds > 300 ||
        !Number.isSafeInteger(maxDelaySeconds) || maxDelaySeconds < baseDelaySeconds ||
        maxDelaySeconds > 3600) {
      throw new Error("invalid_runner_recovery_policy");
    }
  }

  private async withClient<T>(operation: (client: PgRecoveryClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '10s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
