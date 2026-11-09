import { Client } from "pg";
import type { RunnerPrincipal, RunnerScope } from "../auth/runner-authenticator";
import { DatabaseUnavailableError } from "./database-errors";

interface QueryResult<T extends Record<string, unknown>> {
  readonly rows: T[];
}

interface PgRunnerIdentityClient {
  connect(): Promise<void>;
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<QueryResult<T>>;
  end(): Promise<void>;
}

type PgClientFactory = (connectionString: string) => PgRunnerIdentityClient;

const defaultClientFactory: PgClientFactory = (connectionString) =>
  new Client({
    connectionString,
    connectionTimeoutMillis: 5_000,
    application_name: "sky-high-runner-identity-lookup",
  }) as unknown as PgRunnerIdentityClient;

interface RunnerIdentityRow extends Record<string, unknown> {
  readonly runner_id: string;
  readonly pool_id: string;
  readonly identity_subject: string;
  readonly scopes: string[];
}

const allowedScopes = new Set<RunnerScope>([
  "dispatch:claim",
  "dispatch:receipt",
  "dispatch:retry",
]);

export class InvalidRunnerIdentityLookupError extends Error {
  constructor() {
    super("invalid_runner_identity_lookup");
    this.name = "InvalidRunnerIdentityLookupError";
  }
}

export class RunnerIdentityRegistryIntegrityError extends Error {
  constructor() {
    super("runner_identity_registry_integrity_error");
    this.name = "RunnerIdentityRegistryIntegrityError";
  }
}

/**
 * Resolves an already-verified provider issuer/subject pair to trusted
 * server-managed runner identity, pool and scopes. This repository does not
 * validate credentials and must only be called after provider verification.
 */
export class PostgresRunnerIdentityRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async findActivePrincipal(
    issuer: string,
    subject: string,
  ): Promise<RunnerPrincipal | null> {
    this.validateLookup(issuer, subject);
    if (!this.connectionString) throw new DatabaseUnavailableError();

    const client = this.clientFactory(this.connectionString);
    try {
      await client.connect();
      await client.query("SET statement_timeout = '5s'");
      const result = await client.query<RunnerIdentityRow>(
        [
          "SELECT identity.runner_id, pool.id::text AS pool_id, identity.identity_subject, identity.scopes",
          "FROM runner_identities AS identity",
          "INNER JOIN runner_pools AS pool ON pool.id = identity.pool_id",
          "WHERE identity.identity_issuer = $1",
          "  AND identity.identity_subject = $2",
          "  AND identity.status = 'ACTIVE'",
          "  AND pool.status = 'ACTIVE'",
          "LIMIT 2",
        ].join("\n"),
        [issuer, subject],
      );

      if (result.rows.length === 0) return null;
      if (result.rows.length !== 1) throw new RunnerIdentityRegistryIntegrityError();

      const row = result.rows[0];
      if (!row || !Array.isArray(row.scopes) ||
          row.scopes.length === 0 ||
          row.scopes.some((scope) => typeof scope !== "string" || !allowedScopes.has(scope as RunnerScope))) {
        throw new RunnerIdentityRegistryIntegrityError();
      }

      return {
        runnerId: row.runner_id,
        poolId: row.pool_id,
        subject: row.identity_subject,
        scopes: [...row.scopes] as RunnerScope[],
      };
    } catch (error) {
      if (error instanceof RunnerIdentityRegistryIntegrityError) throw error;
      throw new DatabaseUnavailableError();
    } finally {
      await client.end().catch(() => undefined);
    }
  }

  private validateLookup(issuer: string, subject: string): void {
    if (typeof issuer !== "string" || issuer.length < 1 || issuer.length > 512 ||
        issuer !== issuer.trim() ||
        typeof subject !== "string" || subject.length < 1 || subject.length > 512 ||
        subject !== subject.trim()) {
      throw new InvalidRunnerIdentityLookupError();
    }
  }
}
