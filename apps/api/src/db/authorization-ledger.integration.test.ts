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

async function appendRunEvent(
  client: Client,
  requestId: string,
  eventType: "CLAIMED" | "STARTED" | "COMPLETED" | "FAILED" | "QUARANTINED",
  requestDigest: string,
): Promise<void> {
  const prior = await client.query<{ event_sequence: number; event_digest: string }>(
    "SELECT event_sequence, event_digest FROM authorization_run_events WHERE authorization_id = $1 ORDER BY event_sequence DESC LIMIT 1",
    [authId],
  );
  const eventSequence = (prior.rows[0]?.event_sequence ?? 0) + 1;
  const previousDigest = prior.rows[0]?.event_digest ?? "0".repeat(64);
  await client.query(
    `INSERT INTO authorization_run_events
      (authorization_id, event_sequence, previous_event_digest, request_id, event_type, request_digest, event_digest)
     VALUES ($1, $2, $3, $4, $5, $6,
       encode(digest(convert_to(concat_ws('|', $1, $2::text, $4, $5, $6, $3), 'UTF8'), 'sha256'), 'hex'))`,
    [authId, eventSequence, previousDigest, requestId, eventType, requestDigest],
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
    await appendRunEvent(client, requestId, "CLAIMED", digest);
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
    await admin.query("CREATE EXTENSION IF NOT EXISTS pgcrypto");
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
        event_sequence integer NOT NULL,
        previous_event_digest text NOT NULL CHECK (length(previous_event_digest) = 64),
        request_id text NOT NULL,
        event_type text NOT NULL CHECK (event_type IN ('CLAIMED', 'STARTED', 'COMPLETED', 'FAILED', 'QUARANTINED')),
        request_digest text NOT NULL,
        event_digest text NOT NULL CHECK (length(event_digest) = 64),
        UNIQUE (authorization_id, event_sequence),
        UNIQUE (authorization_id, request_id, event_type)
      )
    `);
    await admin.query(`
      CREATE FUNCTION "${schemaName}".guard_run_event() RETURNS trigger
      LANGUAGE plpgsql AS $fn$
      DECLARE prior_sequence integer; prior_digest text;
      BEGIN
        IF TG_OP <> 'INSERT' THEN
          RAISE EXCEPTION 'run event history is append-only' USING ERRCODE = '55000';
        END IF;
        SELECT event_sequence, event_digest INTO prior_sequence, prior_digest
          FROM "${schemaName}".authorization_run_events
          WHERE authorization_id = NEW.authorization_id
          ORDER BY event_sequence DESC LIMIT 1;
        IF NOT FOUND THEN
          prior_sequence := 0;
          prior_digest := repeat('0', 64);
        END IF;
        IF NEW.event_sequence <> prior_sequence + 1 OR NEW.previous_event_digest <> prior_digest THEN
          RAISE EXCEPTION 'run event chain sequence or predecessor mismatch' USING ERRCODE = '23514';
        END IF;
        IF NEW.event_digest <> encode(digest(convert_to(concat_ws('|',
          NEW.authorization_id, NEW.event_sequence::text, NEW.request_id,
          NEW.event_type, NEW.request_digest, NEW.previous_event_digest), 'UTF8'), 'sha256'), 'hex') THEN
          RAISE EXCEPTION 'run event digest mismatch' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
      END;
      $fn$;
      CREATE TRIGGER authorization_run_event_guard
        BEFORE INSERT OR UPDATE OR DELETE ON "${schemaName}".authorization_run_events
        FOR EACH ROW EXECUTE FUNCTION "${schemaName}".guard_run_event();
    `);
    await admin.query(`
      CREATE FUNCTION "${schemaName}".assert_authorization_counter() RETURNS trigger
      LANGUAGE plpgsql AS $fn$
      DECLARE target_id text; recorded_count integer; actual_count integer;
      BEGIN
        target_id := COALESCE(NEW.authorization_id, OLD.authorization_id);
        SELECT consumed_runs INTO recorded_count FROM "${schemaName}".authorization_state
          WHERE authorization_id = target_id;
        SELECT count(*)::integer INTO actual_count FROM "${schemaName}".authorization_run_claims
          WHERE authorization_id = target_id;
        IF recorded_count IS DISTINCT FROM actual_count THEN
          RAISE EXCEPTION 'authorization consumed counter does not match immutable claims'
            USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
      END;
      $fn$;
      CREATE CONSTRAINT TRIGGER authorization_claim_counter_guard
        AFTER INSERT OR UPDATE OR DELETE ON "${schemaName}".authorization_run_claims
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        EXECUTE FUNCTION "${schemaName}".assert_authorization_counter();
      CREATE CONSTRAINT TRIGGER authorization_state_counter_guard
        AFTER UPDATE ON "${schemaName}".authorization_state
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        EXECUTE FUNCTION "${schemaName}".assert_authorization_counter();
    `);
    await admin.query(`GRANT USAGE ON SCHEMA "${schemaName}" TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE ON "${schemaName}".authorization_state TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT ON "${schemaName}".authorization_run_claims TO "${roleName}"`);
    await admin.query(`GRANT SELECT, INSERT ON "${schemaName}".authorization_run_events TO "${roleName}"`);
    await admin.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "${schemaName}" TO "${roleName}"`);
  });

  beforeEach(() => {
    authId = randomUUID();
  });

  afterAll(async () => {
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
    await appendRunEvent(writer, "rollback-request", "CLAIMED", "sha256:rollback");
    await writer.query(
      "UPDATE authorization_state SET consumed_runs = 1 WHERE authorization_id = $1",
      [authId],
    );
    await writer.query("ROLLBACK");
    const rows = await setup.query(
      "SELECT consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events FROM authorization_state WHERE authorization_id = $1",
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
    await appendRunEvent(claimant, "claim-before-revoke", "CLAIMED", "sha256:claim-before-revoke");
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

  it("rejects a counter drift transaction at commit and preserves the durable claim", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const writer = await connect(true);
    expect(await claim(writer, "drift-claim")).toBe("CLAIMED");
    await setup.query("BEGIN");
    await setup.query(
      "UPDATE authorization_state SET consumed_runs = 0 WHERE authorization_id = $1",
      [authId],
    );
    await expect(setup.query("COMMIT")).rejects.toMatchObject({ code: "23514" });
    await setup.query("ROLLBACK").catch(() => undefined);
    const reconciled = await setup.query(
      "SELECT s.consumed_runs, count(c.claim_id)::int AS durable_claims FROM authorization_state s LEFT JOIN authorization_run_claims c USING (authorization_id) WHERE s.authorization_id = $1 GROUP BY s.authorization_id",
      [authId],
    );
    expect(reconciled.rows[0]).toEqual({ consumed_runs: 1, durable_claims: 1 });
  });

  it("rejects a run event with a skipped sequence or forged predecessor", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const writer = await connect(true);
    expect(await claim(writer, "chain-root")).toBe("CLAIMED");
    await expect(writer.query(
      `INSERT INTO authorization_run_events
        (authorization_id, event_sequence, previous_event_digest, request_id, event_type, request_digest, event_digest)
       VALUES ($1, 3, repeat('0', 64), 'chain-gap', 'STARTED', 'sha256:gap', repeat('a', 64))`,
      [authId],
    )).rejects.toMatchObject({ code: "23514" });
    const events = await setup.query(
      "SELECT count(*)::int AS count FROM authorization_run_events WHERE authorization_id = $1",
      [authId],
    );
    expect(events.rows[0]?.count).toBe(1);
  });

  it("terminates a backend during an open claim transaction and rolls back every write", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 1);
    const writer = await connect(true);
    await writer.query("BEGIN");
    await writer.query(
      "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
      [authId],
    );
    await writer.query(
      "INSERT INTO authorization_run_claims (authorization_id, claim_id, request_id, request_digest, claim_sequence) VALUES ($1, $2, 'terminated-request', 'sha256:terminated', 1)",
      [authId, randomUUID()],
    );
    await appendRunEvent(writer, "terminated-request", "CLAIMED", "sha256:terminated");
    await writer.query(
      "UPDATE authorization_state SET consumed_runs = 1, state_version = state_version + 1 WHERE authorization_id = $1",
      [authId],
    );
    const backend = await writer.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
    const terminated = await admin.query<{ stopped: boolean }>(
      "SELECT pg_terminate_backend($1) AS stopped",
      [backend.rows[0]!.pid],
    );
    expect(terminated.rows[0]?.stopped).toBe(true);
    await expect(writer.query("COMMIT")).rejects.toBeDefined();
    await writer.end().catch(() => undefined);
    const state = await setup.query(
      "SELECT consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events FROM authorization_state WHERE authorization_id = $1",
      [authId],
    );
    expect(state.rows[0]).toEqual({ consumed_runs: 0, claims: 0, events: 0 });
  });

});
