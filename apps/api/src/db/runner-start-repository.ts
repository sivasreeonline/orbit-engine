import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface RecordRunnerStartInput {
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly leaseToken: string;
  readonly runnerId: string;
  readonly keyId: string;
}

export interface RecordedRunnerStart {
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly eventId: string;
  readonly startedAt: string;
  readonly replayed: boolean;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgStartClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgStartClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-start",
  }) as unknown as PgStartClient;

interface LeaseRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly dispatch_owner: string | null;
  readonly dispatch_token: string | null;
  readonly dispatch_expires_at: Date | string | null;
  readonly delivery_state: string;
  readonly job_state: string;
  readonly job_owner: string | null;
  readonly job_token: string | null;
  readonly job_expires_at: Date | string | null;
}

interface ExistingStartRow extends Record<string, unknown> {
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly runner_id: string;
  readonly key_id: string;
  readonly event_id: string;
  readonly started_at: Date | string;
}

interface InsertedEventRow extends Record<string, unknown> {
  readonly event_id: string;
}

interface InsertedStartRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly event_id: string;
  readonly started_at: Date | string;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function iso(value: Date | string): string {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error("invalid_runner_start_timestamp");
  return parsed.toISOString();
}

function timestampMs(value: Date | string | null): number {
  if (value === null) return 0;
  const parsed = value instanceof Date ? value : new Date(value);
  return parsed.getTime();
}

export class RunnerStartNotFoundError extends Error {
  constructor() {
    super("runner_start_dispatch_not_found");
    this.name = "RunnerStartNotFoundError";
  }
}

export class RunnerStartUnauthorizedError extends Error {
  constructor() {
    super("runner_start_machine_not_authorized");
    this.name = "RunnerStartUnauthorizedError";
  }
}

export class RunnerStartStaleLeaseError extends Error {
  constructor() {
    super("runner_start_stale_lease");
    this.name = "RunnerStartStaleLeaseError";
  }
}

export class RunnerStartNotAcceptedError extends Error {
  constructor() {
    super("runner_start_acceptance_required");
    this.name = "RunnerStartNotAcceptedError";
  }
}

export class RunnerStartConflictError extends Error {
  constructor() {
    super("runner_start_conflict");
    this.name = "RunnerStartConflictError";
  }
}

/**
 * Performs the lease-fenced CLAIMED -> RUNNING transition only after the
 * identical runner/dispatch/lease generation has a durable acceptance receipt.
 * Job state, RUNNER_STARTED evidence and the start receipt commit atomically.
 */
export class PostgresRunnerStartRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async start(input: RecordRunnerStartInput): Promise<RecordedRunnerStart> {
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
        if (machineKey.rows.length !== 1) throw new RunnerStartUnauthorizedError();

        const leaseResult = await client.query<LeaseRow>(
          [
            "SELECT dispatch.id AS dispatch_id, dispatch.execution_id, dispatch.attempt_id,",
            "  dispatch.lease_owner AS dispatch_owner, dispatch.lease_token::text AS dispatch_token,",
            "  dispatch.lease_expires_at AS dispatch_expires_at, dispatch.delivery_state,",
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
        if (!lease) throw new RunnerStartNotFoundError();

        const existingResult = await client.query<ExistingStartRow>(
          [
            "SELECT execution_id, attempt_id, runner_id, key_id, event_id, started_at",
            "FROM runner_dispatch_starts",
            "WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.dispatchId, input.leaseToken],
        );
        const existing = existingResult.rows[0];
        if (existing) {
          if (existing.execution_id !== input.executionId ||
              existing.attempt_id !== input.attemptId ||
              existing.runner_id !== input.runnerId ||
              existing.key_id !== input.keyId) {
            throw new RunnerStartConflictError();
          }

          const replayNow = Date.now();
          const dispatchExpiry = timestampMs(lease.dispatch_expires_at);
          const jobExpiry = timestampMs(lease.job_expires_at);
          if (lease.delivery_state !== "PENDING" ||
              lease.dispatch_owner !== input.runnerId ||
              lease.dispatch_token !== input.leaseToken ||
              lease.job_state !== "RUNNING" ||
              lease.job_owner !== input.runnerId ||
              lease.job_token !== input.leaseToken ||
              !Number.isFinite(dispatchExpiry) || dispatchExpiry <= replayNow ||
              !Number.isFinite(jobExpiry) || jobExpiry <= replayNow) {
            throw new RunnerStartStaleLeaseError();
          }
          await client.query("COMMIT");
          return {
            dispatchId: input.dispatchId,
            executionId: existing.execution_id,
            attemptId: existing.attempt_id,
            eventId: existing.event_id,
            startedAt: iso(existing.started_at),
            replayed: true,
          };
        }

        const acceptance = await client.query<{ runner_id: string; key_id: string }>(
          [
            "SELECT runner_id, key_id",
            "FROM runner_dispatch_acceptances",
            "WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.dispatchId, input.leaseToken],
        );
        const accepted = acceptance.rows[0];
        if (!accepted || accepted.runner_id !== input.runnerId || accepted.key_id !== input.keyId) {
          throw new RunnerStartNotAcceptedError();
        }

        const now = Date.now();
        if (lease.delivery_state !== "PENDING" ||
            lease.dispatch_owner !== input.runnerId ||
            lease.dispatch_token !== input.leaseToken ||
            lease.job_state !== "CLAIMED" ||
            lease.job_owner !== input.runnerId ||
            lease.job_token !== input.leaseToken ||
            !Number.isFinite(timestampMs(lease.dispatch_expires_at)) ||
            timestampMs(lease.dispatch_expires_at) <= now ||
            !Number.isFinite(timestampMs(lease.job_expires_at)) ||
            timestampMs(lease.job_expires_at) <= now) {
          throw new RunnerStartStaleLeaseError();
        }

        const transitioned = await client.query<{ id: string }>(
          [
            "UPDATE execution_jobs",
            "SET state = 'RUNNING',",
            "    state_version = state_version + 1,",
            "    started_at = COALESCE(started_at, now()),",
            "    updated_at = now()",
            "WHERE id = $1::uuid AND attempt_id = $2::uuid",
            "  AND state = 'CLAIMED' AND lease_owner = $3",
            "  AND lease_token = $4::uuid AND lease_expires_at > now()",
            "RETURNING id",
          ].join("\n"),
          [input.executionId, input.attemptId, input.runnerId, input.leaseToken],
        );
        if (transitioned.rows.length !== 1) throw new RunnerStartStaleLeaseError();

        const eventId = crypto.randomUUID();
        const insertedEvent = await client.query<InsertedEventRow>(
          [
            "INSERT INTO execution_evidence_events (",
            "  event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
            "  event_type, actor_kind, phase_status, safe_code, duration_ms",
            ")",
            "SELECT $1::uuid, job.id, attempt.id, attempt.tenant_id, attempt.actor_user_id,",
            "  'RUNNER_STARTED', 'RUNNER', 'STARTED', 'LEASE_FENCED_START', NULL",
            "FROM execution_jobs AS job",
            "INNER JOIN execution_attempts AS attempt ON attempt.id = job.attempt_id",
            "WHERE job.id = $2::uuid AND attempt.id = $3::uuid",
            "RETURNING event_id",
          ].join("\n"),
          [eventId, input.executionId, input.attemptId],
        );
        if (insertedEvent.rows.length !== 1) throw new RunnerStartNotFoundError();

        const insertedStart = await client.query<InsertedStartRow>(
          [
            "INSERT INTO runner_dispatch_starts (",
            "  dispatch_id, lease_token, execution_id, attempt_id,",
            "  runner_id, key_id, event_id",
            ")",
            "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7::uuid)",
            "RETURNING dispatch_id, execution_id, attempt_id, event_id, started_at",
          ].join("\n"),
          [
            input.dispatchId, input.leaseToken, input.executionId, input.attemptId,
            input.runnerId, input.keyId, eventId,
          ],
        );
        const row = insertedStart.rows[0];
        if (!row) throw new Error("runner_start_insert_returned_no_row");

        await client.query("COMMIT");
        return {
          dispatchId: row.dispatch_id,
          executionId: row.execution_id,
          attemptId: row.attempt_id,
          eventId: row.event_id,
          startedAt: iso(row.started_at),
          replayed: false,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof RunnerStartNotFoundError ||
          error instanceof RunnerStartUnauthorizedError ||
          error instanceof RunnerStartStaleLeaseError ||
          error instanceof RunnerStartNotAcceptedError ||
          error instanceof RunnerStartConflictError) {
        throw error;
      }
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private validate(input: RecordRunnerStartInput): void {
    if (!input || !isUuid(input.dispatchId) || !isUuid(input.executionId) ||
        !isUuid(input.attemptId) || !isUuid(input.leaseToken) ||
        !isUuid(input.runnerId) || !/^[A-Za-z0-9._:-]{1,128}$/.test(input.keyId)) {
      throw new Error("invalid_runner_start_input");
    }
  }

  private async withClient<T>(operation: (client: PgStartClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof RunnerStartNotFoundError ||
          error instanceof RunnerStartUnauthorizedError ||
          error instanceof RunnerStartStaleLeaseError ||
          error instanceof RunnerStartNotAcceptedError ||
          error instanceof RunnerStartConflictError) throw error;
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
