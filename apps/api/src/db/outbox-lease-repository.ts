import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface OutboxLease {
  readonly id: string;
  readonly executionId: string;
  readonly eventType: string;
  readonly protocolVersion: string;
  readonly correlationId: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly deliveryAttempts: number;
  readonly leaseToken: string;
  readonly leaseExpiresAt: string;
}

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgOutboxClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgOutboxClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-outbox-publisher",
  }) as unknown as PgOutboxClient;

interface ClaimedOutboxRow extends Record<string, unknown> {
  readonly id: string;
  readonly execution_id: string;
  readonly event_type: string;
  readonly protocol_version: string;
  readonly correlation_id: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly delivery_attempts: number;
  readonly lease_token: string;
  readonly lease_expires_at: Date | string;
}

interface UpdatedRow extends Record<string, unknown> {
  readonly id: string;
}

/**
 * Database-only outbox lease primitives.
 *
 * Queue transport, retry/backoff, dead-letter thresholds and scheduling policy
 * are deliberately injected/owned by a future publisher, not decided here.
 */
export class PostgresOutboxLeaseRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async claimBatch(
    workerId: string,
    batchSize: number,
    leaseDurationSeconds: number,
  ): Promise<OutboxLease[]> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(workerId)) {
      throw new Error("invalid_outbox_worker_id");
    }
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 100) {
      throw new Error("invalid_outbox_batch_size");
    }
    if (!Number.isSafeInteger(leaseDurationSeconds) ||
        leaseDurationSeconds < 1 || leaseDurationSeconds > 3600) {
      throw new Error("invalid_outbox_lease_duration");
    }

    return this.withClient(async (client) => {
      const result = await client.query<ClaimedOutboxRow>(
        [
          "WITH candidates AS (",
          "  SELECT id",
          "  FROM execution_outbox",
          "  WHERE delivery_state = 'PENDING'",
          "    AND available_at <= now()",
          "    AND (lease_expires_at IS NULL OR lease_expires_at <= now())",
          "  ORDER BY available_at, created_at, id",
          "  LIMIT $1",
          "  FOR UPDATE SKIP LOCKED",
          ")",
          "UPDATE execution_outbox AS outbox",
          "SET lease_owner = $2,",
          "    lease_token = gen_random_uuid(),",
          "    lease_expires_at = now() + make_interval(secs => $3),",
          "    delivery_attempts = outbox.delivery_attempts + 1",
          "FROM candidates",
          "WHERE outbox.id = candidates.id",
          "RETURNING outbox.id, outbox.execution_id, outbox.event_type,",
          "  outbox.protocol_version, outbox.correlation_id, outbox.payload,",
          "  outbox.delivery_attempts, outbox.lease_token, outbox.lease_expires_at",
        ].join("\n"),
        [batchSize, workerId, leaseDurationSeconds],
      );

      return result.rows.map((row) => ({
        id: row.id,
        executionId: row.execution_id,
        eventType: row.event_type,
        protocolVersion: row.protocol_version,
        correlationId: row.correlation_id,
        payload: row.payload,
        deliveryAttempts: row.delivery_attempts,
        leaseToken: row.lease_token,
        leaseExpiresAt: row.lease_expires_at instanceof Date
          ? row.lease_expires_at.toISOString()
          : new Date(row.lease_expires_at).toISOString(),
      }));
    });
  }

  /**
   * Acknowledges only the currently active, unexpired lease.
   * A stale worker cannot acknowledge a row reclaimed by another publisher.
   */
  async markPublished(
    outboxId: string,
    workerId: string,
    leaseToken: string,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(outboxId, workerId, leaseToken);

    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE execution_outbox",
          "SET delivery_state = 'PUBLISHED',",
          "    published_at = now(),",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now()",
          "RETURNING id",
        ].join("\n"),
        [outboxId, workerId, leaseToken],
      );
      return result.rows.length === 1;
    });
  }

  /**
   * Permanently dead-letters a malformed/unsupported outbox event while the
   * caller still owns the active lease. Sink outages must not use this path.
   */
  async markDeadLetter(
    outboxId: string,
    workerId: string,
    leaseToken: string,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(outboxId, workerId, leaseToken);

    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE execution_outbox",
          "SET delivery_state = 'DEAD_LETTER',",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now()",
          "RETURNING id",
        ].join("\\n"),
        [outboxId, workerId, leaseToken],
      );
      return result.rows.length === 1;
    });
  }

  /**
   * Releases a failed delivery for a caller-selected retry time.
   * Retry delay and dead-letter policy remain outside this repository.
   */
  async releaseForRetry(
    outboxId: string,
    workerId: string,
    leaseToken: string,
    availableAt: Date,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(outboxId, workerId, leaseToken);
    if (!(availableAt instanceof Date) || !Number.isFinite(availableAt.getTime())) {
      throw new Error("invalid_outbox_retry_time");
    }

    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE execution_outbox",
          "SET available_at = $4::timestamptz,",
          "    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL",
          "WHERE id = $1::uuid AND delivery_state = 'PENDING'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now()",
          "RETURNING id",
        ].join("\n"),
        [outboxId, workerId, leaseToken, availableAt.toISOString()],
      );
      return result.rows.length === 1;
    });
  }

  private validateLeaseIdentity(
    outboxId: string,
    workerId: string,
    leaseToken: string,
  ): void {
    if (!/^[0-9a-f-]{36}$/i.test(outboxId)) throw new Error("invalid_outbox_id");
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(workerId)) {
      throw new Error("invalid_outbox_worker_id");
    }
    if (!/^[0-9a-f-]{36}$/i.test(leaseToken)) throw new Error("invalid_outbox_lease_token");
  }

  private async withClient<T>(operation: (client: PgOutboxClient) => Promise<T>): Promise<T> {
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
