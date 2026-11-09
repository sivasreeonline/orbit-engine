import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface ExecutionJobLease {
  readonly executionId: string;
  readonly attemptId: string;
  readonly stateVersion: number;
  readonly retryCount: number;
  readonly leaseOwner: string;
  readonly leaseToken: string;
  readonly leaseExpiresAt: string;
}

export type ClaimExecutionJobResult =
  | { readonly status: "CLAIMED"; readonly lease: ExecutionJobLease }
  | { readonly status: "ALREADY_CLAIMED" }
  | { readonly status: "NOT_READY" }
  | { readonly status: "NOT_FOUND" }
  | { readonly status: "NOT_CLAIMABLE"; readonly state: string };

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgExecutionJobClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgExecutionJobClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-execution-job-consumer",
  }) as unknown as PgExecutionJobClient;

interface ClaimedJobRow extends Record<string, unknown> {
  readonly id: string;
  readonly attempt_id: string;
  readonly state_version: number;
  readonly retry_count: number;
  readonly lease_owner: string;
  readonly lease_token: string;
  readonly lease_expires_at: Date | string;
}

interface ExistingJobRow extends Record<string, unknown> {
  readonly state: string;
  readonly active_lease: boolean;
  readonly not_yet_available: boolean;
}

interface UpdatedRow extends Record<string, unknown> {
  readonly id: string;
}

export class PostgresExecutionJobRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async claim(
    executionId: string,
    workerId: string,
    leaseDurationSeconds: number,
  ): Promise<ClaimExecutionJobResult> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateExecutionId(executionId);
    this.validateWorkerId(workerId);
    if (!Number.isSafeInteger(leaseDurationSeconds) ||
        leaseDurationSeconds < 1 || leaseDurationSeconds > 3600) {
      throw new Error("invalid_execution_lease_duration");
    }

    return this.withClient(async (client) => {
      const claimed = await client.query<ClaimedJobRow>(
        [
          "UPDATE execution_jobs",
          "SET state = 'CLAIMED',",
          "    state_version = state_version + 1,",
          "    lease_owner = $2,",
          "    lease_token = gen_random_uuid(),",
          "    lease_expires_at = now() + make_interval(secs => $3),",
          "    updated_at = now()",
          "WHERE id = $1::uuid AND (",
          "  (state = 'QUEUED' AND available_at <= now())",
          "  OR (state = 'CLAIMED' AND lease_expires_at <= now())",
          ")",
          "RETURNING id, attempt_id, state_version, retry_count, lease_owner,",
          "  lease_token, lease_expires_at",
        ].join("\n"),
        [executionId, workerId, leaseDurationSeconds],
      );

      const row = claimed.rows[0];
      if (row) {
        return {
          status: "CLAIMED",
          lease: {
            executionId: row.id,
            attemptId: row.attempt_id,
            stateVersion: row.state_version,
            retryCount: row.retry_count,
            leaseOwner: row.lease_owner,
            leaseToken: row.lease_token,
            leaseExpiresAt: row.lease_expires_at instanceof Date
              ? row.lease_expires_at.toISOString()
              : new Date(row.lease_expires_at).toISOString(),
          },
        };
      }

      const existing = await client.query<ExistingJobRow>(
        [
          "SELECT state,",
          "  (state = 'CLAIMED' AND lease_expires_at > now()) AS active_lease,",
          "  (state = 'QUEUED' AND available_at > now()) AS not_yet_available",
          "FROM execution_jobs WHERE id = $1::uuid",
        ].join("\n"),
        [executionId],
      );
      const current = existing.rows[0];
      if (!current) return { status: "NOT_FOUND" };
      if (current.active_lease) return { status: "ALREADY_CLAIMED" };
      if (current.not_yet_available) return { status: "NOT_READY" };
      return { status: "NOT_CLAIMABLE", state: current.state };
    });
  }

  /**
   * Advances only the current, unexpired claim. The lease remains attached
   * while RUNNING so a later runner adapter can use the same fencing token.
   */
  async markRunning(
    executionId: string,
    workerId: string,
    leaseToken: string,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    this.validateExecutionId(executionId);
    this.validateWorkerId(workerId);
    if (!/^[0-9a-f-]{36}$/i.test(leaseToken)) {
      throw new Error("invalid_execution_lease_token");
    }

    return this.withClient(async (client) => {
      const result = await client.query<UpdatedRow>(
        [
          "UPDATE execution_jobs",
          "SET state = 'RUNNING',",
          "    state_version = state_version + 1,",
          "    started_at = COALESCE(started_at, now()),",
          "    updated_at = now()",
          "WHERE id = $1::uuid AND state = 'CLAIMED'",
          "  AND lease_owner = $2 AND lease_token = $3::uuid",
          "  AND lease_expires_at > now()",
          "RETURNING id",
        ].join("\n"),
        [executionId, workerId, leaseToken],
      );
      return result.rows.length === 1;
    });
  }

  private validateExecutionId(value: string): void {
    if (!/^[0-9a-f-]{36}$/i.test(value)) throw new Error("invalid_execution_id");
  }

  private validateWorkerId(value: string): void {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) {
      throw new Error("invalid_execution_worker_id");
    }
  }

  private async withClient<T>(operation: (client: PgExecutionJobClient) => Promise<T>): Promise<T> {
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
