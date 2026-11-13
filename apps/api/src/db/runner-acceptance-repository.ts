import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface RecordRunnerAcceptanceInput {
  readonly dispatchId: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly runnerId: string;
  readonly keyId: string;
  readonly leaseToken: string;
  readonly acceptanceId: string;
  /** SHA-256 of the exact signed acceptance request body bytes. */
  readonly receiptSha256: string;
}

export interface RecordedRunnerAcceptance {
  readonly dispatchId: string;
  readonly acceptanceId: string;
  readonly eventId: string;
  readonly acceptedAt: string;
  readonly replayed: boolean;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}
interface PgAcceptanceClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}
type PgClientFactory = (connectionString: string) => PgAcceptanceClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-acceptance",
  }) as unknown as PgAcceptanceClient;

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
interface ExistingAcceptanceRow extends Record<string, unknown> {
  readonly acceptance_id: string;
  readonly runner_id: string;
  readonly receipt_sha256: string;
  readonly event_id: string;
  readonly accepted_at: Date | string;
}
interface InsertedEventRow extends Record<string, unknown> {
  readonly event_id: string;
  readonly created_at: Date | string;
}
interface InsertedAcceptanceRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly acceptance_id: string;
  readonly event_id: string;
  readonly accepted_at: Date | string;
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function iso(value: Date | string): string {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error("invalid_runner_acceptance_timestamp");
  return parsed.toISOString();
}

export class RunnerAcceptanceNotFoundError extends Error {
  constructor() { super("runner_acceptance_dispatch_not_found"); this.name = "RunnerAcceptanceNotFoundError"; }
}
export class RunnerAcceptanceUnauthorizedError extends Error {
  constructor() { super("runner_acceptance_machine_not_authorized"); this.name = "RunnerAcceptanceUnauthorizedError"; }
}
export class RunnerAcceptanceStaleLeaseError extends Error {
  constructor() { super("runner_acceptance_stale_lease"); this.name = "RunnerAcceptanceStaleLeaseError"; }
}
export class RunnerAcceptanceConflictError extends Error {
  constructor() { super("runner_acceptance_conflict"); this.name = "RunnerAcceptanceConflictError"; }
}

/**
 * Persists a signed runner acceptance receipt and its append-only evidence
 * event under the current dispatch/job fencing token.
 */
export class PostgresRunnerAcceptanceRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async record(input: RecordRunnerAcceptanceInput): Promise<RecordedRunnerAcceptance> {
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
        if (machineKey.rows.length !== 1) throw new RunnerAcceptanceUnauthorizedError();

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
        if (!lease) throw new RunnerAcceptanceNotFoundError();

        const existingResult = await client.query<ExistingAcceptanceRow>(
          [
            "SELECT acceptance_id, runner_id, receipt_sha256, event_id, accepted_at",
            "FROM runner_dispatch_acceptances",
            "WHERE dispatch_id = $1::uuid AND lease_token = $2::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [input.dispatchId, input.leaseToken],
        );
        const existing = existingResult.rows[0];
        if (existing) {
          if (existing.acceptance_id !== input.acceptanceId ||
              existing.runner_id !== input.runnerId ||
              existing.receipt_sha256.trim() !== input.receiptSha256) {
            throw new RunnerAcceptanceConflictError();
          }
          await client.query("COMMIT");
          return {
            dispatchId: input.dispatchId,
            acceptanceId: existing.acceptance_id,
            eventId: existing.event_id,
            acceptedAt: iso(existing.accepted_at),
            replayed: true,
          };
        }

        const now = Date.now();
        const dispatchExpiry = lease.dispatch_expires_at instanceof Date
          ? lease.dispatch_expires_at.getTime()
          : lease.dispatch_expires_at === null ? 0 : new Date(lease.dispatch_expires_at).getTime();
        const jobExpiry = lease.job_expires_at instanceof Date
          ? lease.job_expires_at.getTime()
          : lease.job_expires_at === null ? 0 : new Date(lease.job_expires_at).getTime();
        if (lease.delivery_state !== "PENDING" ||
            lease.dispatch_owner !== input.runnerId ||
            lease.dispatch_token !== input.leaseToken ||
            lease.job_state !== "CLAIMED" ||
            lease.job_owner !== input.runnerId ||
            lease.job_token !== input.leaseToken ||
            !Number.isFinite(dispatchExpiry) || dispatchExpiry <= now ||
            !Number.isFinite(jobExpiry) || jobExpiry <= now) {
          throw new RunnerAcceptanceStaleLeaseError();
        }

        const eventId = crypto.randomUUID();
        const event = await client.query<InsertedEventRow>(
          [
            "INSERT INTO execution_evidence_events (",
            "  event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
            "  event_type, actor_kind, phase_status, safe_code, duration_ms",
            ")",
            "SELECT $1::uuid, job.id, attempt.id, attempt.tenant_id, attempt.actor_user_id,",
            "  'RUNNER_ACCEPTED', 'RUNNER', 'SUCCEEDED', 'DURABLE_ACCEPTANCE', NULL",
            "FROM execution_jobs AS job",
            "INNER JOIN execution_attempts AS attempt ON attempt.id = job.attempt_id",
            "WHERE job.id = $2::uuid AND attempt.id = $3::uuid",
            "RETURNING event_id, created_at",
          ].join("\n"),
          [eventId, input.executionId, input.attemptId],
        );
        if (event.rows.length !== 1) throw new RunnerAcceptanceNotFoundError();

        const inserted = await client.query<InsertedAcceptanceRow>(
          [
            "INSERT INTO runner_dispatch_acceptances (",
            "  dispatch_id, lease_token, acceptance_id, event_id, execution_id,",
            "  attempt_id, runner_id, key_id, receipt_sha256",
            ")",
            "VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,",
            "  $6::uuid, $7::uuid, $8, $9)",
            "RETURNING dispatch_id, acceptance_id, event_id, accepted_at",
          ].join("\n"),
          [
            input.dispatchId, input.leaseToken, input.acceptanceId, eventId,
            input.executionId, input.attemptId, input.runnerId, input.keyId,
            input.receiptSha256,
          ],
        );
        const row = inserted.rows[0];
        if (!row) throw new Error("runner_acceptance_insert_returned_no_row");

        await client.query("COMMIT");
        return {
          dispatchId: row.dispatch_id,
          acceptanceId: row.acceptance_id,
          eventId: row.event_id,
          acceptedAt: iso(row.accepted_at),
          replayed: false,
        };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    }).catch((error: unknown) => {
      if (error instanceof RunnerAcceptanceNotFoundError ||
          error instanceof RunnerAcceptanceUnauthorizedError ||
          error instanceof RunnerAcceptanceStaleLeaseError ||
          error instanceof RunnerAcceptanceConflictError) {
        throw error;
      }
      if (error instanceof DatabaseUnavailableError) throw error;
      throw new DatabaseUnavailableError();
    });
  }

  private validate(input: RecordRunnerAcceptanceInput): void {
    if (!input || !isUuid(input.dispatchId) || !isUuid(input.executionId) ||
        !isUuid(input.attemptId) || !isUuid(input.runnerId) ||
        !isUuid(input.leaseToken) || !isUuid(input.acceptanceId) ||
        !/^[A-Za-z0-9._:-]{1,128}$/.test(input.keyId) ||
        !/^[0-9a-f]{64}$/.test(input.receiptSha256)) {
      throw new Error("invalid_runner_acceptance_input");
    }
  }

  private async withClient<T>(operation: (client: PgAcceptanceClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch (error) {
      if (error instanceof RunnerAcceptanceNotFoundError ||
          error instanceof RunnerAcceptanceUnauthorizedError ||
          error instanceof RunnerAcceptanceStaleLeaseError ||
          error instanceof RunnerAcceptanceConflictError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
