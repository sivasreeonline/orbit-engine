import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresRunnerIdentityRepository } from "./runner-identity-repository";

const databaseUrl = process.env.DATABASE_URL;
const testPublicKey = Buffer.from(
  "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "base64url",
);
const nonce = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";

describe.skipIf(!databaseUrl)("runner identity repository PostgreSQL integration", () => {
  it("loads only active, valid runner public keys", async () => {
    const runnerId = randomUUID();
    const keyId = `runner-key-${randomUUID()}`;
    const client = new Client({ connectionString: databaseUrl });
    const repository = new PostgresRunnerIdentityRepository(databaseUrl);
    try {
      await client.connect();
      await client.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `runner-${runnerId}`],
      );
      await client.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, testPublicKey],
      );

      const active = await repository.findActivePublicKey(keyId, new Date());
      expect(active).toEqual({
        keyId,
        runnerId,
        publicKey: new Uint8Array(testPublicKey),
      });

      await client.query(
        "UPDATE runner_machine_keys SET status = 'REVOKED', revoked_at = now() WHERE key_id = $1",
        [keyId],
      );
      await expect(repository.findActivePublicKey(keyId, new Date())).resolves.toBeNull();
    } finally {
      await client.query("DELETE FROM runner_machine_keys WHERE runner_id = $1", [runnerId]).catch(() => undefined);
      await client.query("DELETE FROM runner_machines WHERE id = $1", [runnerId]).catch(() => undefined);
      await client.end();
    }
  });

  it("allows exactly one concurrent consumer of the same nonce", async () => {
    const runnerId = randomUUID();
    const keyId = `runner-nonce-${randomUUID()}`;
    const setup = new Client({ connectionString: databaseUrl });
    const repository = new PostgresRunnerIdentityRepository(databaseUrl);
    try {
      await setup.connect();
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, testPublicKey],
      );

      const expiry = new Date(Date.now() + 5 * 60 * 1000);
      const results = await Promise.all([
        repository.consumeNonce(keyId, nonce, expiry),
        repository.consumeNonce(keyId, nonce, expiry),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(results.filter((value) => !value)).toHaveLength(1);
    } finally {
      await setup.query("DELETE FROM runner_request_nonces WHERE key_id = $1", [keyId]).catch(() => undefined);
      await setup.query("DELETE FROM runner_machine_keys WHERE key_id = $1", [keyId]).catch(() => undefined);
      await setup.query("DELETE FROM runner_machines WHERE id = $1", [runnerId]).catch(() => undefined);
      await setup.end();
    }
  });
});
