import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

const RENEWED_LEASE_SECONDS = 120;

export interface RecordRunnerHeartbeatInput {
  readonly heartbeatId: string;
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly leaseToken: string;
  readonly runnerId: string;
  readonly keyId: string;
}

export interface RecordedRunnerHeartbeat {
  readonly heartbeatId: string;
  readonly dispatchId: string;
  readonly executionId: string;
  readonly leaseExpiresAt: string;
  readonly replayed: boolean;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgHeartbeatClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgHeartbeatClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-heartbeat",
  }) as unknown as PgHeartbeatClient;

interface LeaseRow extends Record<string, unknown> {
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
}

interface RunnerIdentityRow extends Record<string, unknown> {
  readonly runner_id: string;
  readonly key_id: string;
}

interface ExistingHeartbeatRow extends Record<string, unknown> {
  readonly heartbeat_id: string;
  readonly dispatch_id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly lease_token: string;
  readonly runner_id: string;
  readonly key_id: string;
  readonly lease_expires_at: Date | string;
}

interface ExpiryRow extends Record<string, unknown> {
  readonly lease_expires_at: Date | string;
}

interface UpdatedRow extends Record<string, unknown> {
  readonly id: string;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function timestampMs(value: Date | string | null): number {
  if (value === null) return 0;
  const parsed = value instanceof Date ? value : new Date(value);
  return parsed.getTime();
}

function iso(value: Date | string): string {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error("invalid_runner_heartbeat_timestamp");
  return parsed.toISOString();
}

export class RunnerHeartbeatNotFoundError extends Error {
  constructor() {
    super("runner_heartbeat_dispatch_not_found");
    this.name = "RunnerHeartbeatNotFoundError";
  }
}

export class RunnerHeartbeatUnauthorizedError extends Error {
  constructor() {
    super("runner_heartbeat_machine_not_authorized");
    this.name = "RunnerHeartbeatUnauthorizedError";
  }
}

export class RunnerHeartbeatNotStartedError extends Error {
  constructor() {
    super("runner_heartbeat_start_required");
    this.name = "RunnerHeartbeatNotStartedError";
  }
}

export class RunnerHeartbeatStaleLeaseError extends Error {
  constructor() {
    super("runner_heartbeat_stale_lease");
    this.name = "RunnerHeartbeatStaleLeaseError";
  }
}

export class RunnerHeartbeatConflictError extends Error {
  constructor() {
    super("runner_heartbeat_conflict");
    this.name = "RunnerHeartbeatConflictError";
  }
}

/**
 * Renews the dispatch and execution-job lease together. A heartbeat is accepted
 * only for a dispatch that has a durable acceptance and start receipt. The
 * heartbeat ID makes a retry idempotent after an acknowledgement is lost.
 */
export class PostgresRunnerHeartbeatRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async renew(input: RecordRunnerHeartbeatInput): Promise<RecordedRunnerHeartbeat> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validate(input);

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        const machineKey = await client.query<{ key_id: string }>(
          [
            "SELECT machine_key.key_id",
            "FROM runner_machine_keys AS machine_key",
            "INNER JOIN runner_machines AS machine ON machine.id = machine_key.runner_id",
            "WHERE machine_key.key_id = $1 AND machine_key.runner_id = $2::uuid",
            "  AND machine.status = 'ACTIVE' AND machine_key.status = 'ACTIVE'",
            "  AND machine_key.revoked_at IS NULL",
            "  AND machine_key.valid_from <= now()",
            "  AND (machine_key.expires_at IS NULL OR machine_key.expires_at > now())",
            "FOR UPDATE OF machine_key, machine",
          ].join("\n"),
          [input.keyId, input.runnerId],
        );
        if (machineKey.rows.length !== 1) throw new RunnerHeartbeatUnauthorizedError();

        const leaseResult = await client.query<LeaseRow>(
          [
            "SELECT dispatch.id AS dispatch_id, dispatch.execution_id, dispatch.attempt_id,",
            "  dispatch.delivery_state, dispatch.lease_owner AS dispatch_owner,",
            "  dispatch.lease_token::text AS dispatch_token,",
            "  dispatch.lease_expires_at AS dispatch_expires_at,",
            "  job.state AS job_state, job.lease_owner AS job_owner,",
            "  job.lease_token::text AS job_token, job.lease_expires_at AS job_expires_at",
            "FROM runner_dispatch_outbox AS dispatch",
            "INNER JOIN execution_jobs AS job ON job.id = dispatch.execution_id",
            "WHERE dispatch.id = $1::uuid AND dispatch.execution_id = $2::uuid",
            "  AND dispatch.attempt_id = $3::uuid AND job.attempt_id = $3::uuid",
            "FOR UPDATE OF dispatch, job",
          ].join("\n"),
          [input.dispatchId, input.executionId, input.attemptId],
        );
        const lease = leaseResult.rows[0];
        if (!lease) throw new RunnerHeartbeatNotFoundError();

        const existingResult = await client.query<ExistingHeartbeatRow>(
          [
            "SELECT heartbeat_id, dispatch_id, execution_id, attempt_id,",
            "  lease_token::text AS lease_token, runner_id, key_id, lease_expires_at",
            "FROM runner_dispatch_lease_heartbeats",
            "WHERE heartbeat_id = $1::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.heartbeatId],
        );
        const existing = existingResult.rows[0];
        if (existing) {
          if (existing.dispatch_id !== input.dispatchId ||
              existing.execution_id !== input.executionId ||
              existing.attempt_id !== input.attemptId ||
              existing.lease_token !== input.leaseToken ||
              existing.runner_id !== input.runnerId ||
              existing.key_id !== input.keyId) {
            throw new RunnerHeartbeatConflictError();
          }
          await client.query("COMMIT");
          return {
            heartbeatId: existing.heartbeat_id,
            dispatchId: existing.dispatch_id,
            executionId: existing.execution_id,
            leaseExpiresAt: iso(existing.lease_expires_at),
            replayed: true,
          };
        }

        const startResult = await client.query<RunnerIdentityRow>(
          [
            "SELECT runner_id, key_id",
            "FROM runner_dispatch_starts",
            "WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.dispatchId, input.leaseToken],
        );
        const started = startResult.rows[0];
        if (!started || started.runner_id !== input.runnerId || started.key_id !== input.keyId) {
          throw new RunnerHeartbeatNotStartedError();
        }

        if (lease.delivery_state !== "PENDING" ||
            lease.dispatch_owner !== input.runnerId ||
            lease.dispatch_token !== input.leaseToken ||
            lease.job_state !== "RUNNING" ||
            lease.job_owner !== input.runnerId ||
            lease.job_token !== input.leaseToken ||
            !Number.isFinite(timestampMs(lease.dispatch_expires_at)) ||
            timestampMs(lease.dispatch_expires_at) <= Date.now() ||
            !Number.isFinite(timestampMs(lease.job_expires_at)) ||
            timestampMs(lease.job_expires_at) <= Date.now()) {
          throw new RunnerHeartbeatStaleLeaseError();
        }

        const expiryResult = await client.query<ExpiryRow>(
          [
            "SELECT clock_timestamp() + make_interval(secs => $1) AS lease_expires_at",
          ].join("\n"),
          [RENEWED_LEASE_SECONDS],
        );
        const leaseExpiresAt = expiryResult.rows[0]?.lease_expires_at;
        if (!leaseExpiresAt) throw new Error("runner_heartbeat_expiry_not_generated");

        await client.query(
          [
            "INSERT INTO runner_dispatch_lease_heartbeats (",
            "  heartbeat_id, dispatch_id, lease_token, execution_id, attempt_id,",
            "  runner_id, key_id, lease_expires_at",
            ")",
            "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7, $8::timestamptz)",
          ].join("\n"),
          [
            input.heartbeatId, input.dispatchId, input.leaseToken, input.executionId,
            input.attemptId, input.runnerId, input.keyId, iso(leaseExpiresAt),
          ],
        );

        const renewedDispatch = await client.query<UpdatedRow>(
          [
            "UPDATE runner_dispatch_outbox",
            "SET lease_expires_at = $5::timestamptz",
            "WHERE id = $1::uuid AND execution_id = $2::uuid AND attempt_id = $3::uuid",
            "  AND delivery_state = 'PENDING' AND lease_owner = $4",
            "  AND lease_token = $6::uuid AND lease_expires_at > clock_timestamp()",
            "RETURNING id",
          ].join("\n"),
          [
            input.dispatchId, input.executionId, input.attemptId, input.runnerId,
            iso(leaseExpiresAt), input.leaseToken,
          ],
        );
        if (renewedDispatch.rows.length !== 1) throw new RunnerHeartbeatStaleLeaseError();

        const renewedJob = await client.query<UpdatedRow>(
          [
            "UPDATE execution_jobs",
            "SET lease_expires_at = $5::timestamptz, updated_at = now()",
            "WHERE id = $1::uuid AND attempt_id = $2::uuid AND state = 'RUNNING'",
            "  AND lease_owner = $3 AND lease_token = $4::uuid",
            "  AND lease_expires_at > clock_timestamp()",
            "RETURNING id",
          ].join("\n"),
          [
            input.executionId, input.attemptId, input.runnerId,
            input.leaseToken, iso(leaseExpiresAt),
          ],
        );
        if (renewedJob.rows.length !== 1) throw new RunnerHeartbeatStaleLeaseError();

        await client.query("COMMIT");
        return {
          heartbeatId: input.heartbeatId,
          dispatchId: input.dispatchId,
          executionId: input.executionId,
          leaseExpiresAt: iso(leaseExpiresAt),
          replayed: false,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof RunnerHeartbeatNotFoundError ||
          error instanceof RunnerHeartbeatUnauthorizedError ||
          error instanceof RunnerHeartbeatNotStartedError ||
          error instanceof RunnerHeartbeatStaleLeaseError ||
          error instanceof RunnerHeartbeatConflictError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private validate(input: RecordRunnerHeartbeatInput): void {
    if (!input || !isUuid(input.heartbeatId) || !isUuid(input.dispatchId) ||
        !isUuid(input.executionId) || !isUuid(input.attemptId) ||
        !isUuid(input.leaseToken) || !isUuid(input.runnerId) ||
        !/^[A-Za-z0-9._:-]{1,128}$/.test(input.keyId)) {
      throw new Error("invalid_runner_heartbeat_input");
    }
  }

  private async withClient<T>(operation: (client: PgHeartbeatClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof RunnerHeartbeatNotFoundError ||
          error instanceof RunnerHeartbeatUnauthorizedError ||
          error instanceof RunnerHeartbeatNotStartedError ||
          error instanceof RunnerHeartbeatStaleLeaseError ||
          error instanceof RunnerHeartbeatConflictError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
