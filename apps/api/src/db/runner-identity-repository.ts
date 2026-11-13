import { Client } from "pg";
import { DatabaseUnavailableError } from "./database-errors";

export interface ActiveRunnerPublicKey {
  readonly keyId: string;
  readonly runnerId: string;
  readonly publicKey: Uint8Array;
}

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
    application_name: "sky-high-runner-identity",
  }) as unknown as PgRunnerIdentityClient;

interface ActiveKeyRow extends Record<string, unknown> {
  readonly key_id: string;
  readonly runner_id: string;
  readonly public_key: Uint8Array;
}

interface InsertedNonceRow extends Record<string, unknown> {
  readonly nonce: string;
}

/** Public-key lookup and one-time nonce persistence for machine authentication. */
export class PostgresRunnerIdentityRepository {
  constructor(
    private readonly connectionString: string | undefined,
    private readonly clientFactory: PgClientFactory = defaultClientFactory,
  ) {}

  async findActivePublicKey(
    keyId: string,
    now: Date,
  ): Promise<ActiveRunnerPublicKey | null> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId) ||
        !(now instanceof Date) || !Number.isFinite(now.getTime())) {
      throw new Error("invalid_runner_identity_lookup");
    }

    return this.withClient(async (client) => {
      const result = await client.query<ActiveKeyRow>(
        [
          "SELECT machine_key.key_id, machine_key.runner_id, machine_key.public_key",
          "FROM runner_machine_keys AS machine_key",
          "INNER JOIN runner_machines AS machine ON machine.id = machine_key.runner_id",
          "WHERE machine_key.key_id = $1",
          "  AND machine.status = 'ACTIVE'",
          "  AND machine_key.status = 'ACTIVE'",
          "  AND machine_key.revoked_at IS NULL",
          "  AND machine_key.valid_from <= $2::timestamptz",
          "  AND (machine_key.expires_at IS NULL OR machine_key.expires_at > $2::timestamptz)",
          "LIMIT 1",
        ].join("\n"),
        [keyId, now.toISOString()],
      );
      const row = result.rows[0];
      if (!row) return null;
      if (row.public_key.byteLength !== 32) throw new Error("invalid_runner_public_key_length");
      return {
        keyId: row.key_id,
        runnerId: row.runner_id,
        publicKey: new Uint8Array(row.public_key),
      };
    });
  }

  /**
   * Consumes a nonce once per key. Expired nonce rows for that key are removed
   * in the same transaction before insertion; timestamp freshness is checked
   * by the authenticator before this method is called.
   */
  async consumeNonce(
    keyId: string,
    nonce: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean> {
    if (!this.connectionString) throw new DatabaseUnavailableError();
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId) ||
        !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
        !(now instanceof Date) || !Number.isFinite(now.getTime()) ||
        !(expiresAt instanceof Date) || !Number.isFinite(expiresAt.getTime()) ||
        expiresAt.getTime() <= now.getTime()) {
      throw new Error("invalid_runner_request_nonce");
    }

    return this.withClient(async (client) => {
      await client.query("BEGIN");
      try {
        // Lock both identity rows while rechecking active state. A concurrent
        // revocation cannot race between signature lookup and nonce commit.
        const active = await client.query<{ key_id: string }>(
          [
            "SELECT machine_key.key_id",
            "FROM runner_machine_keys AS machine_key",
            "INNER JOIN runner_machines AS machine ON machine.id = machine_key.runner_id",
            "WHERE machine_key.key_id = $1",
            "  AND machine.status = 'ACTIVE'",
            "  AND machine_key.status = 'ACTIVE'",
            "  AND machine_key.revoked_at IS NULL",
            "  AND machine_key.valid_from <= $2::timestamptz",
            "  AND (machine_key.expires_at IS NULL OR machine_key.expires_at > $2::timestamptz)",
            "FOR UPDATE OF machine_key, machine",
          ].join("\n"),
          [keyId, now.toISOString()],
        );
        if (active.rows.length !== 1) {
          await client.query("COMMIT");
          return false;
        }

        await client.query(
          "DELETE FROM runner_request_nonces WHERE key_id = $1 AND expires_at <= $2::timestamptz",
          [keyId, now.toISOString()],
        );
        const inserted = await client.query<InsertedNonceRow>(
          [
            "INSERT INTO runner_request_nonces (key_id, nonce, received_at, expires_at)",
            "VALUES ($1, $2, $3::timestamptz, $4::timestamptz)",
            "ON CONFLICT (key_id, nonce) DO NOTHING",
            "RETURNING nonce",
          ].join("\n"),
          [keyId, nonce, now.toISOString(), expiresAt.toISOString()],
        );
        await client.query("COMMIT");
        return inserted.rows.length === 1;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      }
    });
  }

  private async withClient<T>(operation: (client: PgRunnerIdentityClient) => Promise<T>): Promise<T> {
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
