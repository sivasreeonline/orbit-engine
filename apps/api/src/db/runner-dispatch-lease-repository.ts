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

export type RunnerDispatchReceiptResult =
  | { readonly status: "RECORDED" }
  | { readonly status: "DUPLICATE" };

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
interface DispatchLockRow extends Record<string, unknown> {
  readonly delivery_state: string;
  readonly lease_owner: string | null;
  readonly lease_token: string | null;
  readonly lease_expires_at: Date | string | null;
  readonly lease_active: boolean;
}
interface ReceiptRow extends Record<string, unknown> {
  readonly dispatch_id: string;
  readonly runner_id: string;
  readonly receipt_id: string;
  readonly receipt_hash: string;
}

/** Database-only fenced leases and durable acceptance receipts for a future runner agent. */
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
   * Persist the runner's durable acceptance receipt and mark the dispatch
   * delivered in one transaction. The runner must journal the execution
   * durably before submitting this receipt.
   */
  async recordReceipt(
    dispatchId: string,
    workerId: string,
    leaseToken: string,
    receiptId: string,
    receiptHash: string,
  ): Promise<RunnerDispatchReceiptResult> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateLeaseIdentity(dispatchId, workerId, leaseToken);
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(receiptId)) {
      throw new Error("invalid_runner_dispatch_receipt_id");
    }
    if (!/^[0-9a-f]{64}$/.test(receiptHash)) {
      throw new Error("invalid_runner_dispatch_receipt_hash");
    }

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        // Lock the dispatch row first. Concurrent replays then observe the
        // receipt committed by the first caller instead of misclassifying it
        // as a stale lease after waiting for that caller's transaction.
        const dispatch = await client.query<DispatchLockRow>(
          [
            "SELECT delivery_state, lease_owner, lease_token, lease_expires_at > now() AS lease_active",
            "FROM runner_dispatch_outbox WHERE id = $1::uuid",
            "FOR UPDATE",
          ].join("\n"),
          [dispatchId],
        );
        const current = dispatch.rows[0];
        if (!current) throw new StaleRunnerDispatchLeaseError();

        const existing = await client.query<ReceiptRow>(
          [
            "SELECT dispatch_id, runner_id, receipt_id, receipt_hash",
            "FROM runner_dispatch_receipts",
            "WHERE dispatch_id = $1::uuid",
          ].join("\n"),
          [dispatchId],
        );
        const prior = existing.rows[0];
        if (prior) {
          if (prior.runner_id === workerId &&
              prior.receipt_id === receiptId &&
              prior.receipt_hash === receiptHash) {
            await client.query("COMMIT");
            return { status: "DUPLICATE" };
          }
          throw new RunnerDispatchReceiptConflictError();
        }

        if (current.delivery_state !== "PENDING" ||
            current.lease_owner !== workerId ||
            current.lease_token !== leaseToken ||
            current.lease_active !== true) {
          throw new StaleRunnerDispatchLeaseError();
        }

        const reused = await client.query<ReceiptRow>(
          [
            "SELECT dispatch_id, runner_id, receipt_id, receipt_hash",
            "FROM runner_dispatch_receipts",
            "WHERE runner_id = $1 AND receipt_id = $2",
          ].join("\n"),
          [workerId, receiptId],
        );
        if (reused.rows.length > 0) throw new RunnerDispatchReceiptConflictError();

        await client.query(
          [
            "INSERT INTO runner_dispatch_receipts",
            "  (dispatch_id, runner_id, receipt_id, receipt_hash, accepted_at)",
            "VALUES ($1::uuid, $2, $3, $4, now())",
          ].join("\n"),
          [dispatchId, workerId, receiptId, receiptHash],
        );

        const delivered = await client.query<UpdatedRow>(
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
        if (delivered.rows.length !== 1) throw new StaleRunnerDispatchLeaseError();

        await client.query("COMMIT");
        return { status: "RECORDED" };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
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
    } catch (error) {
      if (error instanceof RunnerDispatchReceiptConflictError ||
          error instanceof StaleRunnerDispatchLeaseError) throw error;
      if (typeof error === "object" && error !== null &&
          "code" in error && error.code === "23505") {
        throw new RunnerDispatchReceiptConflictError();
      }
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }
}

export class RunnerDispatchReceiptConflictError extends Error {
  constructor() {
    super("runner_dispatch_receipt_conflict");
    this.name = "RunnerDispatchReceiptConflictError";
  }
}

export class StaleRunnerDispatchLeaseError extends Error {
  constructor() {
    super("stale_runner_dispatch_lease");
    this.name = "StaleRunnerDispatchLeaseError";
  }
}
