import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface RunnerDispatchLease {
  readonly id: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly protocolVersion: string;
  readonly correlationId: string;
  readonly deliveryAttempts: number;
  readonly leaseToken: string;
  readonly leaseExpiresAt: string;
}

interface QueryResult<T extends Record<string, unknown>> { readonly rows: T[]; }
interface PgDispatchClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResult<T>>;
  end(): Promise<void>;
}
type PgClientFactory = (connectionString: string) => PgDispatchClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-dispatcher",
  }) as unknown as PgDispatchClient;

interface ClaimedRow extends Record<string, unknown> {
  readonly id: string;
  readonly execution_id: string;
  readonly attempt_id: string;
  readonly protocol_version: string;
  readonly correlation_id: string;
  readonly delivery_attempts: number;
  readonly lease_token: string;
  readonly lease_expires_at: Date | string;
}
interface UpdatedRow extends Record<string, unknown> { readonly id: string; }

/** Database-only fenced leases for a future authenticated Linux-runner transport. */
export class PostgresRunnerDispatchLeaseRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async claimBatch(workerId: string, batchSize: number, leaseSeconds: number): Promise<RunnerDispatchLease[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateWorker(workerId);
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
      throw new Error("invalid_runner_dispatch_batch_size");
    }
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 3600) {
      throw new Error("invalid_runner_dispatch_lease_duration");
    }

    return this.withClient(async (client) => {
      const result = await client.query<ClaimedRow>(
        [
          "WITH candidates AS (",
          "  SELECT id FROM runner_dispatch_outbox",
          "  WHERE delivery_state = 'PENDING' AND available_at <= now()",
          "    AND (lease_expires_at IS NULL OR lease_expires_at <= now())",
          "  ORDER BY available_at, created_at, id",
          "  LIMIT $1 FOR UPDATE SKIP LOCKED",
          ")",
          "UPDATE runner_dispatch_outbox AS dispatch",
          "SET lease_owner = $2, lease_token = gen_random_uuid(),",
          "    lease_expires_at = now() + make_interval(secs => $3),",
          "    delivery_attempts = dispatch.delivery_attempts + 1",
          "FROM candidates WHERE dispatch.id = candidates.id",
          "RETURNING dispatch.id, dispatch.execution_id, dispatch.attempt_id,",
          "  dispatch.protocol_version, dispatch.correlation_id,",
          "  dispatch.delivery_attempts, dispatch.lease_token, dispatch.lease_expires_at",
        ].join("\n"),
        [batchSize, workerId, leaseSeconds],
      );
      return result.rows.map((row) => ({
        id: row.id,
        executionId: row.execution_id,
        attemptId: row.attempt_id,
        protocolVersion: row.protocol_version,
        correlationId: row.correlation_id,
        deliveryAttempts: row.delivery_attempts,
        leaseToken: row.lease_token,
        leaseExpiresAt: row.lease_expires_at instanceof Date
          ? row.lease_expires_at.toISOString()
          : new Date(row.lease_expires_at).toISOString(),
      }));
    });
  }

  /**
   * Claims at most one pending dispatch per student lane in this batch.
   * Lanes are served by least-recently-served order; each lane's oldest
   * eligible dispatch is selected first. Lane row locks serialize competing
   * fair schedulers and survive process restarts through the persisted cursor.
   */
  async claimFairBatch(
    workerId: string,
    batchSize: number,
    leaseSeconds: number,
  ): Promise<RunnerDispatchLease[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateWorker(workerId);
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
      throw new Error("invalid_runner_dispatch_batch_size");
    }
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 3600) {
      throw new Error("invalid_runner_dispatch_lease_duration");
    }

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        // Serialize the short scheduler transaction so competing pollers see
        // the latest committed lane cursor before choosing the next student.
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended('sky-high-runner-fair-scheduler', 0))",
        );
        const result = await client.query<ClaimedRow>(
          [
          "WITH candidate_lanes AS MATERIALIZED (",
          "  SELECT lane.tenant_id, lane.actor_user_id",
          "  FROM runner_dispatch_scheduler_lanes AS lane",
          "  WHERE EXISTS (",
          "    SELECT 1",
          "    FROM runner_dispatch_outbox AS pending",
          "    INNER JOIN execution_attempts AS owner_attempt",
          "      ON owner_attempt.id = pending.attempt_id",
          "    WHERE owner_attempt.tenant_id = lane.tenant_id",
          "      AND owner_attempt.actor_user_id = lane.actor_user_id",
          "      AND pending.delivery_state = 'PENDING'",
          "      AND pending.available_at <= now()",
          "      AND (pending.lease_expires_at IS NULL OR pending.lease_expires_at <= now())",
          "  )",
          "  ORDER BY lane.last_served_ticket, lane.tenant_id, lane.actor_user_id",
          "  LIMIT $1",
          "  FOR UPDATE OF lane SKIP LOCKED",
          "), candidate_dispatches AS (",
          "  SELECT DISTINCT ON (owner_attempt.tenant_id, owner_attempt.actor_user_id)",
          "    pending.id, owner_attempt.tenant_id, owner_attempt.actor_user_id",
          "  FROM candidate_lanes AS lane",
          "  INNER JOIN execution_attempts AS owner_attempt",
          "    ON owner_attempt.tenant_id = lane.tenant_id",
          "   AND owner_attempt.actor_user_id = lane.actor_user_id",
          "  INNER JOIN runner_dispatch_outbox AS pending",
          "    ON pending.attempt_id = owner_attempt.id",
          "  WHERE pending.delivery_state = 'PENDING'",
          "    AND pending.available_at <= now()",
          "    AND (pending.lease_expires_at IS NULL OR pending.lease_expires_at <= now())",
          "  ORDER BY owner_attempt.tenant_id, owner_attempt.actor_user_id,",
          "    pending.available_at, pending.created_at, pending.id",
          "), claimed AS (",
          "  UPDATE runner_dispatch_outbox AS dispatch",
          "  SET lease_owner = $2, lease_token = gen_random_uuid(),",
          "      lease_expires_at = now() + make_interval(secs => $3),",
          "      delivery_attempts = dispatch.delivery_attempts + 1",
          "  FROM candidate_dispatches AS candidate",
          "  WHERE dispatch.id = candidate.id",
          "  RETURNING dispatch.id, dispatch.execution_id, dispatch.attempt_id,",
          "    dispatch.protocol_version, dispatch.correlation_id,",
          "    dispatch.delivery_attempts, dispatch.lease_token, dispatch.lease_expires_at",
          "), served AS (",
          "  UPDATE runner_dispatch_scheduler_lanes AS lane",
          "  SET last_served_ticket = nextval('runner_dispatch_scheduler_ticket_seq'),",
          "      last_served_at = clock_timestamp(), updated_at = now()",
          "  FROM claimed",
          "  INNER JOIN execution_attempts AS owner_attempt ON owner_attempt.id = claimed.attempt_id",
          "  WHERE lane.tenant_id = owner_attempt.tenant_id",
          "    AND lane.actor_user_id = owner_attempt.actor_user_id",
          "  RETURNING lane.tenant_id",
          ")",
          "SELECT claimed.* FROM claimed",
          "CROSS JOIN (SELECT count(*) FROM served) AS scheduler_cursor_write",
        ].join("\n"),
          [batchSize, workerId, leaseSeconds],
        );

        await client.query("COMMIT");
        return result.rows.map((row) => ({
          id: row.id,
          executionId: row.execution_id,
          attemptId: row.attempt_id,
          protocolVersion: row.protocol_version,
          correlationId: row.correlation_id,
          deliveryAttempts: row.delivery_attempts,
          leaseToken: row.lease_token,
          leaseExpiresAt: row.lease_expires_at instanceof Date
            ? row.lease_expires_at.toISOString()
            : new Date(row.lease_expires_at).toISOString(),
        }));
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    });
  }

  /**
   * Claims fair dispatches for one authenticated runner. A transaction-scoped
   * advisory lock serializes polls from this runner. The active-lease count is
   * queried after acquiring the lock in a separate READ COMMITTED statement,
   * so concurrent polls cannot both spend the same remaining capacity.
   */
  async claimFairBatchForRunner(
    runnerId: string,
    requestedSlots: number,
    maxActiveLeases: number,
    leaseSeconds: number,
  ): Promise<RunnerDispatchLease[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runnerId)) {
      throw new Error("invalid_runner_machine_id");
    }
    if (!Number.isSafeInteger(requestedSlots) || requestedSlots < 1 || requestedSlots > 10 ||
        !Number.isSafeInteger(maxActiveLeases) || maxActiveLeases < 1 || maxActiveLeases > 10) {
      throw new Error("invalid_runner_dispatch_capacity");
    }
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 1 || leaseSeconds > 3600) {
      throw new Error("invalid_runner_dispatch_lease_duration");
    }

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        // The global scheduler lock protects cross-runner lane ordering;
        // the per-runner lock additionally protects this runner's capacity.
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended('sky-high-runner-fair-scheduler', 0))",
        );
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
          [runnerId],
        );
        const active = await client.query<{ active_count: number }>(
          [
            "SELECT count(*)::integer AS active_count",
            "FROM runner_dispatch_outbox",
            "WHERE lease_owner = $1",
            "  AND delivery_state = 'PENDING'",
            "  AND lease_expires_at > now()",
          ].join("\n"),
          [runnerId],
        );
        const activeCount = Number(active.rows[0]?.active_count ?? 0);
        const slotBudget = Math.min(requestedSlots, Math.max(maxActiveLeases - activeCount, 0));
        if (slotBudget === 0) {
          await client.query("COMMIT");
          return [];
        }

        const result = await client.query<ClaimedRow>(
          [
            "WITH candidate_lanes AS MATERIALIZED (",
          "  SELECT lane.tenant_id, lane.actor_user_id",
          "  FROM runner_dispatch_scheduler_lanes AS lane",
          "  WHERE EXISTS (",
          "    SELECT 1 FROM runner_dispatch_outbox AS pending",
          "    INNER JOIN execution_attempts AS owner_attempt ON owner_attempt.id = pending.attempt_id",
          "    INNER JOIN execution_jobs AS job ON job.id = pending.execution_id",
          "    WHERE owner_attempt.tenant_id = lane.tenant_id",
          "      AND owner_attempt.actor_user_id = lane.actor_user_id",
          "      AND pending.delivery_state = 'PENDING'",
          "      AND pending.available_at <= now()",
          "      AND (pending.lease_expires_at IS NULL OR pending.lease_expires_at <= now())",
          "      AND ((job.state = 'QUEUED' AND job.available_at <= now())",
          "        OR (job.state = 'CLAIMED' AND job.lease_expires_at <= now()))",
          "  )",
          "  ORDER BY lane.last_served_ticket, lane.tenant_id, lane.actor_user_id",
          "  LIMIT $1",
          "  FOR UPDATE OF lane SKIP LOCKED",
          "), candidate_dispatches AS MATERIALIZED (",
          "  SELECT candidate.dispatch_id, candidate.execution_id, candidate.attempt_id,",
          "    lane.tenant_id, lane.actor_user_id",
          "  FROM candidate_lanes AS lane",
          "  CROSS JOIN LATERAL (",
          "    SELECT pending.id AS dispatch_id, pending.execution_id, pending.attempt_id",
          "    FROM runner_dispatch_outbox AS pending",
          "    INNER JOIN execution_attempts AS owner_attempt ON owner_attempt.id = pending.attempt_id",
          "    INNER JOIN execution_jobs AS job ON job.id = pending.execution_id",
          "    WHERE owner_attempt.tenant_id = lane.tenant_id",
          "      AND owner_attempt.actor_user_id = lane.actor_user_id",
          "      AND pending.delivery_state = 'PENDING'",
          "      AND pending.available_at <= now()",
          "      AND (pending.lease_expires_at IS NULL OR pending.lease_expires_at <= now())",
          "      AND ((job.state = 'QUEUED' AND job.available_at <= now())",
          "        OR (job.state = 'CLAIMED' AND job.lease_expires_at <= now()))",
          "    ORDER BY pending.available_at, pending.created_at, pending.id",
          "    LIMIT 1",
          "    FOR UPDATE OF pending, job SKIP LOCKED",
          "  ) AS candidate",
          "), claimed AS (",
          "  UPDATE runner_dispatch_outbox AS dispatch",
          "  SET lease_owner = $2, lease_token = gen_random_uuid(),",
          "      lease_expires_at = now() + make_interval(secs => $3),",
          "      delivery_attempts = dispatch.delivery_attempts + 1",
          "  FROM candidate_dispatches AS candidate",
          "  WHERE dispatch.id = candidate.dispatch_id",
          "  RETURNING dispatch.id, dispatch.execution_id, dispatch.attempt_id,",
          "    dispatch.protocol_version, dispatch.correlation_id,",
          "    dispatch.delivery_attempts, dispatch.lease_token, dispatch.lease_expires_at",
          "), claimed_jobs AS (",
          "  UPDATE execution_jobs AS job",
          "  SET state = 'CLAIMED', state_version = job.state_version + 1,",
          "      lease_owner = $2, lease_token = claimed.lease_token,",
          "      lease_expires_at = claimed.lease_expires_at, updated_at = now()",
          "  FROM claimed",
          "  WHERE job.id = claimed.execution_id",
          "    AND job.attempt_id = claimed.attempt_id",
          "    AND ((job.state = 'QUEUED' AND job.available_at <= now())",
          "      OR (job.state = 'CLAIMED' AND job.lease_expires_at <= now()))",
          "  RETURNING job.id, job.attempt_id",
          "), claimed_events AS (",
          "  INSERT INTO execution_evidence_events (",
          "    event_id, execution_id, attempt_id, tenant_id, actor_user_id,",
          "    event_type, actor_kind, phase_status, safe_code, duration_ms",
          "  )",
          "  SELECT gen_random_uuid(), claimed_jobs.id, attempt.id, attempt.tenant_id,",
          "    attempt.actor_user_id, 'JOB_CLAIMED', 'RUNNER', NULL, NULL, NULL",
          "  FROM claimed_jobs",
          "  INNER JOIN execution_attempts AS attempt ON attempt.id = claimed_jobs.attempt_id",
          "  RETURNING sequence_id",
          "), served AS (",
          "  UPDATE runner_dispatch_scheduler_lanes AS lane",
          "  SET last_served_ticket = nextval('runner_dispatch_scheduler_ticket_seq'),",
          "      last_served_at = clock_timestamp(), updated_at = now()",
          "  FROM claimed_jobs",
          "  INNER JOIN execution_attempts AS owner_attempt ON owner_attempt.id = claimed_jobs.attempt_id",
          "  WHERE lane.tenant_id = owner_attempt.tenant_id",
          "    AND lane.actor_user_id = owner_attempt.actor_user_id",
          "  RETURNING lane.tenant_id",
          ")",
          "SELECT claimed.* FROM claimed",
          "INNER JOIN claimed_jobs ON claimed_jobs.id = claimed.execution_id",
          "CROSS JOIN (SELECT count(*) FROM claimed_events) AS evidence_write",
          "CROSS JOIN (SELECT count(*) FROM served) AS scheduler_cursor_write",
          ].join("\n"),
          [slotBudget, runnerId, leaseSeconds],
        );
        await client.query("COMMIT");
        return result.rows.map((row) => ({
          id: row.id,
          executionId: row.execution_id,
          attemptId: row.attempt_id,
          protocolVersion: row.protocol_version,
          correlationId: row.correlation_id,
          deliveryAttempts: row.delivery_attempts,
          leaseToken: row.lease_token,
          leaseExpiresAt: row.lease_expires_at instanceof Date
            ? row.lease_expires_at.toISOString()
            : new Date(row.lease_expires_at).toISOString(),
        }));
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    });
  }

  /** Mark delivered only after the runner transport returns an authenticated receipt. */
  async markDelivered(dispatchId: string, workerId: string, leaseToken: string): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(dispatchId, workerId, leaseToken);
    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE runner_dispatch_outbox",
          "SET delivery_state = 'DELIVERED', delivered_at = now(),",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now() RETURNING id",
        ].join("\n"),
        [dispatchId, workerId, leaseToken],
      );
      return result.rows.length === 1;
    });
  }

  async releaseForRetry(
    dispatchId: string, workerId: string, leaseToken: string, availableAt: Date,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(dispatchId, workerId, leaseToken);
    if (!(availableAt instanceof Date) || !Number.isFinite(availableAt.getTime())) {
      throw new Error("invalid_runner_dispatch_retry_time");
    }
    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE runner_dispatch_outbox",
          "SET available_at = $4::timestamptz,",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now() RETURNING id",
        ].join("\n"),
        [dispatchId, workerId, leaseToken, availableAt.toISOString()],
      );
      return result.rows.length === 1;
    });
  }

  async markDeadLetter(dispatchId: string, workerId: string, leaseToken: string): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(dispatchId, workerId, leaseToken);
    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE runner_dispatch_outbox",
          "SET delivery_state = 'DEAD_LETTER',",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now() RETURNING id",
        ].join("\n"),
        [dispatchId, workerId, leaseToken],
      );
      return result.rows.length === 1;
    });
  }

  private validateWorker(value: string): void {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) throw new Error("invalid_runner_dispatch_worker_id");
  }
  private validateLeaseIdentity(id: string, worker: string, token: string): void {
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error("invalid_runner_dispatch_id");
    this.validateWorker(worker);
    if (!/^[0-9a-f-]{36}$/i.test(token)) throw new Error("invalid_runner_dispatch_lease_token");
  }
  private async withClient<T>(operation: (client: PgDispatchClient) => Promise<T>): Promise<T> {
    const client = this.clientFactory(this.connectionString as string);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      return await operation(client);
    } catch {
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}
