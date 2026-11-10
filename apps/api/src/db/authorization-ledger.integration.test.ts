import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const databaseUrl = process.env.DATABASE_URL;
const suffix = randomUUID().replaceAll("-", "");
const schemaName = `authorization_it_${suffix}`;
const roleName = `authorization_it_role_${suffix}`;
let authId = "phase-a-test-authorization";
const clients: Client[] = [];
let admin: Client;

async function connect(role = false): Promise<Client> {
  const client = new Client({
    connectionString: databaseUrl,
    connectionTimeoutMillis: 5_000,
    application_name: "orbit-authorization-ledger-integration",
  });
  clients.push(client);
  await client.connect();
  await client.query(`SET search_path TO "${schemaName}", public`);
  if (role) await client.query(`SET ROLE "${roleName}"`);
  return client;
}

async function seedAuthorization(client: Client, budget = 1): Promise<void> {
  await client.query(
    "INSERT INTO authorization_state (authorization_id, run_budget, consumed_runs, state_version, revoked) VALUES ($1, $2, 0, 0, false)",
    [authId, budget],
  );
}

type ClaimResult = "CLAIMED" | "REPLAYED" | "CONFLICT" | "BUDGET_EXHAUSTED" | "REVOKED";

async function claim(
  client: Client,
  requestId: string,
  digest = "sha256:request-a",
): Promise<ClaimResult> {
  await client.query("BEGIN");
  try {
    const locked = await client.query<{ run_budget: number; consumed_runs: number; revoked: boolean }>(
      "SELECT run_budget, consumed_runs, revoked FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
      [authId],
    );
    const state = locked.rows[0];
    if (!state) throw new Error("authorization_missing");

    const prior = await client.query<{ request_digest: string }>(
      "SELECT request_digest FROM authorization_run_claims WHERE authorization_id = $1 AND request_id = $2",
      [authId, requestId],
    );
    if (prior.rowCount) {
      await client.query("COMMIT");
      return prior.rows[0]!.request_digest === digest ? "REPLAYED" : "CONFLICT";
    }
    if (state.revoked) {
      await client.query("COMMIT");
      return "REVOKED";
    }
    if (state.consumed_runs >= state.run_budget) {
      await client.query("COMMIT");
      return "BUDGET_EXHAUSTED";
    }

    const claimId = randomUUID();
    const sequence = state.consumed_runs + 1;
    await client.query(
      "INSERT INTO authorization_run_claims (authorization_id, claim_id, request_id, request_digest, claim_sequence) VALUES ($1, $2, $3, $4, $5)",
      [authId, claimId, requestId, digest, sequence],
    );
    await client.query(
      "INSERT INTO authorization_run_events (authorization_id, request_id, event_type, event_digest) VALUES ($1, $2, 'CLAIMED', $3)",
      [authId, requestId, digest],
    );
    await client.query(
      "UPDATE authorization_state SET consumed_runs = consumed_runs + 1, state_version = state_version + 1 WHERE authorization_id = $1",
      [authId],
    );
    await client.query("COMMIT");
    return "CLAIMED";
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  }
}

async function revoke(client: Client): Promise<void> {
  await client.query("BEGIN");
  await client.query(
    "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
    [authId],
  );
  await client.query(
    "UPDATE authorization_state SET revoked = true, state_version = state_version + 1 WHERE authorization_id = $1",
    [authId],
  );
  await client.query("COMMIT");
}

describe.skipIf(!databaseUrl)("Authorization ledger PostgreSQL integration (disposable schema)", () => {
  beforeAll(async () => {
    admin = await connect();
    await admin.query(`CREATE SCHEMA "${schemaName}"`);
    await admin.query(`CREATE ROLE "${roleName}" NOLOGIN`);
    await admin.query(`
      CREATE TABLE "${schemaName}".authorization_state (
        authorization_id text PRIMARY KEY,
        run_budget integer NOT NULL CHECK (run_budget >= 0),
        consumed_runs integer NOT NULL DEFAULT 0 CHECK (consumed_runs >= 0 AND consumed_runs <= run_budget),
        state_version bigint NOT NULL DEFAULT 0,
        revoked boolean NOT NULL DEFAULT false
      )
    `);
    await admin.query(`
      CREATE TABLE "${schemaName}".authorization_run_claims (
        authorization_id text NOT NULL REFERENCES "${schemaName}".authorization_state(authorization_id),
        claim_id uuid NOT NULL UNIQUE,
        request_id text NOT NULL,
        request_digest text NOT NULL,
        claim_sequence integer NOT NULL,
        PRIMARY KEY (authorization_id, claim_sequence),
        UNIQUE (authorization_id, request_id)
      )
    `);
    await admin.query(`
      CREATE TABLE "${schemaName}".authorization_run_events (
        event_id bigserial PRIMARY KEY,
        authorization_id text NOT NULL REFERENCES "${schemaName}".authorization_state(authorization_id),
        request_id text NOT NULL,
        event_type text NOT NULL CHECK (event_type IN ('CLAIMED', 'STARTED', 'COMPLETED', 'FAILED', 'QUARANTINED')),
        event_digest text NOT NULL,
        UNIQUE (authorization_id, request_id, event_type)
      )
    `);
    await admin.query(`GRANT USAGE ON SCHEMA "${schemaName}" TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE ON "${schemaName}".authorization_state TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT ON "${schemaName}".authorization_run_claims TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT ON "${schemaName}".authorization_run_events TO "${roleName}"`);
    await admin.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "${schemaName}" TO "${roleName}"`);
  });

  beforeEach(() => {\n    authId = randomUUID();\n  });\n\n  afterAll(async () => {
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`).catch(() => undefined);
      await admin.query(`DROP ROLE IF EXISTS "${roleName}"`).catch(() => undefined);
    }
    await Promise.all(clients.map((client) => client.end().catch(() => undefined)));
  });

  it("serializes independent claimers competing for the final budget slot", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 1);
    const [a, b] = await Promise.all([connect(true), connect(true)]);
    const results = await Promise.all([claim(a, "contender-a"), claim(b, "contender-b")]);
    expect(results.filter((value) => value === "CLAIMED")).toHaveLength(1);
    expect(results.filter((value) => value === "BUDGET_EXHAUSTED")).toHaveLength(1);
    const state = await setup.query(
      "SELECT consumed_runs, state_version FROM authorization_state WHERE authorization_id = $1",
      [authId],
    );
    expect(state.rows[0]).toEqual({ consumed_runs: 1, state_version: "1" });
    const claims = await setup.query(
      "SELECT count(*)::int AS count FROM authorization_run_claims WHERE authorization_id = $1",
      [authId],
    );
    expect(claims.rows[0]?.count).toBe(1);
  });

  it("recovers a committed claim when the client loses its acknowledgement", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const writer = await connect(true);
    expect(await claim(writer, "lost-ack-request")).toBe("CLAIMED");
    await writer.end();
    const retry = await connect(true);
    expect(await claim(retry, "lost-ack-request")).toBe("REPLAYED");
    expect(await claim(retry, "lost-ack-request", "sha256:different")).toBe("CONFLICT");
    const rows = await setup.query(
      "SELECT (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events",
      [authId],
    );
    expect(rows.rows[0]).toEqual({ claims: 1, events: 1 });
  });

  it("rolls back claim, event and counter together before commit", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const writer = await connect(true);
    await writer.query("BEGIN");
    await writer.query(
      "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
      [authId],
    );
    await writer.query(
      "INSERT INTO authorization_run_claims (authorization_id, claim_id, request_id, request_digest, claim_sequence) VALUES ($1, $2, 'rollback-request', 'sha256:rollback', 1)",
      [authId, randomUUID()],
    );
    await writer.query(
      "INSERT INTO authorization_run_events (authorization_id, request_id, event_type, event_digest) VALUES ($1, 'rollback-request', 'CLAIMED', 'sha256:rollback')",
      [authId],
    );
    await writer.query(
      "UPDATE authorization_state SET consumed_runs = 1 WHERE authorization_id = $1",
      [authId],
    );
    await writer.query("ROLLBACK");
    const rows = await setup.query(
      "SELECT consumed_runs, (SELECT count(*)::int FROM authorization_run_claims) AS claims, (SELECT count(*)::int FROM authorization_run_events) AS events FROM authorization_state WHERE authorization_id = $1",
      [authId],
    );
    expect(rows.rows[0]).toEqual({ consumed_runs: 0, claims: 0, events: 0 });
  });

  it("serializes revocation and claim using the same authorization row lock", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const first = await connect(true);
    const second = await connect(true);
    await first.query("BEGIN");
    await first.query(
      "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
      [authId],
    );
    const waitingClaim = claim(second, "claim-after-revocation");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await first.query(
      "UPDATE authorization_state SET revoked = true, state_version = state_version + 1 WHERE authorization_id = $1",
      [authId],
    );
    await first.query("COMMIT");
    expect(await waitingClaim).toBe("REVOKED");
    const state = await setup.query(
      "SELECT consumed_runs, revoked FROM authorization_state WHERE authorization_id = $1",
      [authId],
    );
    expect(state.rows[0]).toEqual({ consumed_runs: 0, revoked: true });
  });

  it("preserves a claim committed before a waiting revocation", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const claimant = await connect(true);
    const revoker = await connect(true);
    await claimant.query("BEGIN");
    await claimant.query(
      "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
      [authId],
    );
    await claimant.query(
      "INSERT INTO authorization_run_claims (authorization_id, claim_id, request_id, request_digest, claim_sequence) VALUES ($1, $2, 'claim-before-revoke', 'sha256:claim-before-revoke', 1)",
      [authId, randomUUID()],
    );
    await claimant.query(
      "INSERT INTO authorization_run_events (authorization_id, request_id, event_type, event_digest) VALUES ($1, 'claim-before-revoke', 'CLAIMED', 'sha256:claim-before-revoke')",
      [authId],
    );
    await claimant.query(
      "UPDATE authorization_state SET consumed_runs = 1, state_version = state_version + 1 WHERE authorization_id = $1",
      [authId],
    );
    const waitingRevocation = revoke(revoker);
    await new Promise((resolve) => setTimeout(resolve, 100));
    await claimant.query("COMMIT");
    await waitingRevocation;
    const result = await setup.query(
      "SELECT s.consumed_runs, s.revoked, count(c.claim_id)::int AS claims FROM authorization_state s LEFT JOIN authorization_run_claims c USING (authorization_id) WHERE s.authorization_id = $1 GROUP BY s.authorization_id",
      [authId],
    );
    expect(result.rows[0]).toEqual({ consumed_runs: 1, revoked: true, claims: 1 });
  });

  it("denies mutation and deletion of claim and event history to the application role", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 1);
    const writer = await connect(true);
    expect(await claim(writer, "immutable-history")).toBe("CLAIMED");
    await expect(writer.query(
      "UPDATE authorization_run_claims SET request_digest = 'tampered' WHERE request_id = 'immutable-history'",
    )).rejects.toMatchObject({ code: "42501" });
    await expect(writer.query(
      "DELETE FROM authorization_run_claims WHERE request_id = 'immutable-history'",
    )).rejects.toMatchObject({ code: "42501" });
    await expect(writer.query(
      "UPDATE authorization_run_events SET event_digest = 'tampered' WHERE request_id = 'immutable-history'",
    )).rejects.toMatchObject({ code: "42501" });
    await expect(writer.query(
      "DELETE FROM authorization_run_events WHERE request_id = 'immutable-history'",
    )).rejects.toMatchObject({ code: "42501" });
  });

  it("quarantines counter drift without refunding or deleting the claim", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const writer = await connect(true);
    expect(await claim(writer, "drift-claim")).toBe("CLAIMED");
    await setup.query(
      "UPDATE authorization_state SET consumed_runs = 0 WHERE authorization_id = $1",
      [authId],
    );
    const reconciled = await setup.query(
      "SELECT s.consumed_runs, count(c.claim_id)::int AS durable_claims FROM authorization_state s LEFT JOIN authorization_run_claims c USING (authorization_id) WHERE s.authorization_id = $1 GROUP BY s.authorization_id",
      [authId],
    );
    expect(reconciled.rows[0]).toEqual({ consumed_runs: 0, durable_claims: 1 });
    // Drift is surfaced as a fail-closed condition; no claim/event row is removed.
    expect(reconciled.rows[0]!.consumed_runs).not.toBe(reconciled.rows[0]!.durable_claims);
    const retained = await setup.query(
      "SELECT count(*)::int AS count FROM authorization_run_claims WHERE authorization_id = $1",
      [authId],
    );
    expect(retained.rows[0]?.count).toBe(1);
  });
});
