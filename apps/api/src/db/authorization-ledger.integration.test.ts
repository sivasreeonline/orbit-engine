import { createHash, randomUUID } from "node:crypto";
import { connect as connectTcp, createServer, type Socket } from "node:net";
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

async function waitForLockWaiter(pid: number, description: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const result = await admin.query<{
      wait_event_type: string | null;
      blocking_pids: number[];
    }>(
      "SELECT wait_event_type, pg_blocking_pids(pid) AS blocking_pids FROM pg_stat_activity WHERE pid = $1",
      [pid],
    );
    const activity = result.rows[0];
    if (activity?.wait_event_type === "Lock" && activity.blocking_pids.length > 0) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for PostgreSQL lock state: ${description}`);
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
       encode(digest(convert_to(concat_ws('|', $1::text, $2::integer::text, $4::text, $5::text, $6::text, $3::text), 'UTF8'), 'sha256'), 'hex'))`,
    [authId, eventSequence, previousDigest, requestId, eventType, requestDigest],
  );
}


async function createCommitAckDroppingProxy(
  verifyCommitted: () => Promise<boolean>,
): Promise<{
  connectionString: string;
  dropped: Promise<void>;
  arm: () => void;
  close: () => Promise<void>;
}> {
  if (!databaseUrl) throw new Error("DATABASE_URL is required for the commit-ack proxy test");
  const target = new URL(databaseUrl);
  const sockets = new Set<Socket>();
  let settled = false;
  let armed = false;
  let handlingResponse = false;
  let resolveDropped!: () => void;
  let rejectDropped!: (error: Error) => void;
  const dropped = new Promise<void>((resolve, reject) => {
    resolveDropped = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    rejectDropped = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
  });
  void dropped.catch(() => undefined);

  const server = createServer((clientSocket) => {
    sockets.add(clientSocket);
    const upstream = connectTcp({
      host: target.hostname,
      port: Number(target.port || 5432),
    });
    sockets.add(upstream);

    clientSocket.on("data", (chunk) => {
      if (!upstream.destroyed) upstream.write(chunk);
    });

    upstream.on("data", (chunk) => {
      if (!armed || handlingResponse) {
        if (!clientSocket.destroyed) clientSocket.write(chunk);
        return;
      }

      // The test arms this only immediately before COMMIT, after every prior
      // query response has been consumed. Hold the next backend response until
      // an independent database session confirms the transaction is durable.
      handlingResponse = true;
      upstream.pause();
      void verifyCommitted()
        .then((committed) => {
          if (committed) {
            resolveDropped();
            clientSocket.destroy();
            upstream.destroy();
            return;
          }
          armed = false;
          if (!clientSocket.destroyed) clientSocket.write(chunk);
          if (!upstream.destroyed) upstream.resume();
        })
        .catch((error: Error) => {
          rejectDropped(error);
          armed = false;
          if (!clientSocket.destroyed) clientSocket.write(chunk);
          if (!upstream.destroyed) upstream.resume();
        })
        .finally(() => {
          handlingResponse = false;
        });
    });

    clientSocket.on("close", () => {
      sockets.delete(clientSocket);
      if (!upstream.destroyed) upstream.destroy();
    });
    upstream.on("close", () => sockets.delete(upstream));
    clientSocket.on("error", (error) => rejectDropped(error));
    upstream.on("error", (error) => {
      rejectDropped(error);
      clientSocket.destroy();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("Could not obtain the commit-ack proxy listening port");
  }
  const proxyUrl = new URL(databaseUrl);
  proxyUrl.hostname = "127.0.0.1";
  proxyUrl.port = String(address.port);
  proxyUrl.searchParams.set("sslmode", "disable");

  return {
    connectionString: proxyUrl.toString(),
    dropped,
    arm: () => {
      if (armed || settled) throw new Error("Commit-ack proxy can only be armed once");
      armed = true;
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
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

  it("serializes concurrent delivery of the same run ID and digest", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const [first, second] = await Promise.all([connect(true), connect(true)]);

    const outcomes = await Promise.all([
      claim(first, "concurrent-identical-request", "sha256:identical"),
      claim(second, "concurrent-identical-request", "sha256:identical"),
    ]);

    expect(outcomes.filter((value) => value === "CLAIMED")).toHaveLength(1);
    expect(outcomes.filter((value) => value === "REPLAYED")).toHaveLength(1);
    const persisted = await setup.query(
      "SELECT s.consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events FROM authorization_state s WHERE s.authorization_id = $1",
      [authId],
    );
    expect(persisted.rows[0]).toEqual({ consumed_runs: 1, claims: 1, events: 1 });
  });

  it("rejects concurrent reuse of one run ID with different request digests", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const [first, second] = await Promise.all([connect(true), connect(true)]);

    const outcomes = await Promise.all([
      claim(first, "concurrent-conflicting-request", "sha256:payload-a"),
      claim(second, "concurrent-conflicting-request", "sha256:payload-b"),
    ]);

    expect(outcomes.filter((value) => value === "CLAIMED")).toHaveLength(1);
    expect(outcomes.filter((value) => value === "CONFLICT")).toHaveLength(1);
    const persisted = await setup.query(
      "SELECT s.consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events FROM authorization_state s WHERE s.authorization_id = $1",
      [authId],
    );
    expect(persisted.rows[0]).toEqual({ consumed_runs: 1, claims: 1, events: 1 });
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


  it("recovers a committed claim after a TCP proxy drops the COMMIT acknowledgement", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 2);
    const requestId = "tcp-lost-ack-request";
    const requestDigest = "sha256:tcp-lost-ack";
    const proxy = await createCommitAckDroppingProxy(async () => {
      const durable = await setup.query(
        "SELECT s.consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1 AND request_id = $2) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1 AND request_id = $2) AS events FROM authorization_state s WHERE s.authorization_id = $1",
        [authId, requestId],
      );
      return durable.rows[0]?.consumed_runs === 1
        && durable.rows[0]?.claims === 1
        && durable.rows[0]?.events === 1;
    });
    const writer = new Client({
      connectionString: proxy.connectionString,
      connectionTimeoutMillis: 5_000,
      application_name: "orbit-authorization-commit-ack-fault-test",
    });
    let expectedDisconnectError: Error | undefined;
    // The proxy intentionally resets this client after the server-side commit.
    // Consume and assert pg's connection-level error event so Vitest does not
    // classify the expected fault as an unhandled exception.
    writer.on("error", (error: Error) => {
      expectedDisconnectError = error;
    });

    try {
      await writer.connect();
      await writer.query(`SET search_path TO "${schemaName}", public`);
      await writer.query(`SET ROLE "${roleName}"`);
      await writer.query("BEGIN");
      await writer.query(
        "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
        [authId],
      );
      await writer.query(
        "INSERT INTO authorization_run_claims (authorization_id, claim_id, request_id, request_digest, claim_sequence) VALUES ($1, $2, $3, $4, 1)",
        [authId, randomUUID(), requestId, requestDigest],
      );
      await appendRunEvent(writer, requestId, "CLAIMED", requestDigest);
      await writer.query(
        "UPDATE authorization_state SET consumed_runs = consumed_runs + 1, state_version = state_version + 1 WHERE authorization_id = $1",
        [authId],
      );

      proxy.arm();
      await expect(writer.query("COMMIT")).rejects.toBeDefined();
      await proxy.dropped;
    } finally {
      await writer.end().catch(() => undefined);
      await proxy.close();
    }

    expect(expectedDisconnectError).toBeDefined();
    expect(expectedDisconnectError?.message).toMatch(/terminated unexpectedly|connection terminated/i);

    const persisted = await setup.query(
      "SELECT s.consumed_runs, (SELECT count(*)::int FROM authorization_run_claims WHERE authorization_id = $1) AS claims, (SELECT count(*)::int FROM authorization_run_events WHERE authorization_id = $1) AS events FROM authorization_state s WHERE s.authorization_id = $1",
      [authId],
    );
    expect(persisted.rows[0]).toEqual({ consumed_runs: 1, claims: 1, events: 1 });

    const retry = await connect(true);
    expect(await claim(retry, requestId, requestDigest)).toBe("REPLAYED");
    expect(await claim(retry, requestId, "sha256:changed")).toBe("CONFLICT");
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
    const secondBackend = await second.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
    const waitingClaim = claim(second, "claim-after-revocation");
    await waitForLockWaiter(
      secondBackend.rows[0]!.pid,
      "claim blocked by the in-flight revocation transaction",
    );
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
    const revokerBackend = await revoker.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
    const waitingRevocation = revoke(revoker);
    await waitForLockWaiter(
      revokerBackend.rows[0]!.pid,
      "revocation blocked by the in-flight claim transaction",
    );
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


  it("independently recomputes the persisted event chain and detects altered rows", async () => {
    const setup = await connect();
    await seedAuthorization(setup, 3);
    const writer = await connect(true);
    expect(await claim(writer, "verify-chain-a")).toBe("CLAIMED");
    await appendRunEvent(writer, "verify-chain-a", "STARTED", "sha256:request-a");
    await appendRunEvent(writer, "verify-chain-a", "COMPLETED", "sha256:request-a");

    const persisted = await setup.query<{
      event_sequence: number;
      previous_event_digest: string;
      request_id: string;
      event_type: string;
      request_digest: string;
      event_digest: string;
    }>(
      "SELECT event_sequence, previous_event_digest, request_id, event_type, request_digest, event_digest FROM authorization_run_events WHERE authorization_id = $1 ORDER BY event_sequence",
      [authId],
    );

    const independentlyVerify = (rows: typeof persisted.rows): boolean => {
      let previous = "0".repeat(64);
      for (let index = 0; index < rows.length; index += 1) {
        const row = rows[index]!;
        if (row.event_sequence !== index + 1 || row.previous_event_digest !== previous) return false;
        const canonicalTuple = [
          authId,
          String(row.event_sequence),
          row.request_id,
          row.event_type,
          row.request_digest,
          row.previous_event_digest,
        ].join("|");
        const expected = createHash("sha256").update(canonicalTuple, "utf8").digest("hex");
        if (row.event_digest !== expected) return false;
        previous = expected;
      }
      return true;
    };

    expect(persisted.rows).toHaveLength(3);
    expect(independentlyVerify(persisted.rows)).toBe(true);
    const altered = persisted.rows.map((row) => ({ ...row }));
    altered[1]!.request_digest = "sha256:tampered";
    expect(independentlyVerify(altered)).toBe(false);
    const reordered = [...persisted.rows].reverse();
    expect(independentlyVerify(reordered)).toBe(false);
  });


  it("detects a PostgreSQL SERIALIZABLE write-skew conflict with SQLSTATE 40001", async () => {
    const setup = await connect();
    const firstId = randomUUID();
    const secondId = randomUUID();
    await setup.query(
      "INSERT INTO authorization_state (authorization_id, run_budget, consumed_runs, state_version, revoked) VALUES ($1, 1, 0, 0, false), ($2, 1, 0, 0, false)",
      [firstId, secondId],
    );
    const first = await connect(true);
    const second = await connect(true);

    try {
      await first.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      await second.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
      const ids = [firstId, secondId];
      const firstSnapshot = await first.query<{ active_count: number }>(
        "SELECT count(*)::int AS active_count FROM authorization_state WHERE authorization_id = ANY($1::text[]) AND revoked = false",
        [ids],
      );
      const secondSnapshot = await second.query<{ active_count: number }>(
        "SELECT count(*)::int AS active_count FROM authorization_state WHERE authorization_id = ANY($1::text[]) AND revoked = false",
        [ids],
      );
      expect(firstSnapshot.rows[0]?.active_count).toBe(2);
      expect(secondSnapshot.rows[0]?.active_count).toBe(2);

      const updates = await Promise.allSettled([
        first.query("UPDATE authorization_state SET revoked = true, state_version = state_version + 1 WHERE authorization_id = $1", [firstId]),
        second.query("UPDATE authorization_state SET revoked = true, state_version = state_version + 1 WHERE authorization_id = $1", [secondId]),
      ]);

      const finish = async (
        client: Client,
        update: PromiseSettledResult<unknown>,
      ): Promise<{ outcome: "COMMITTED" | "SERIALIZATION_ABORT"; code?: string }> => {
        if (update.status === "rejected") {
          await client.query("ROLLBACK").catch(() => undefined);
          const error = update.reason as { code?: string };
          if (error.code === "40001") return { outcome: "SERIALIZATION_ABORT", code: error.code };
          throw update.reason;
        }
        try {
          await client.query("COMMIT");
          return { outcome: "COMMITTED" };
        } catch (error) {
          await client.query("ROLLBACK").catch(() => undefined);
          const code = (error as { code?: string }).code;
          if (code === "40001") return { outcome: "SERIALIZATION_ABORT", code };
          throw error;
        }
      };

      const outcomes = await Promise.all([
        finish(first, updates[0]),
        finish(second, updates[1]),
      ]);
      expect(outcomes.filter((value) => value.outcome === "COMMITTED")).toHaveLength(1);
      expect(outcomes.filter((value) => value.code === "40001")).toHaveLength(1);
    } finally {
      await Promise.all([
        first.query("ROLLBACK").catch(() => undefined),
        second.query("ROLLBACK").catch(() => undefined),
      ]);
      await Promise.all([
        first.end().catch(() => undefined),
        second.end().catch(() => undefined),
      ]);
    }

    const remaining = await setup.query(
      "SELECT count(*)::int AS active_count FROM authorization_state WHERE authorization_id = ANY($1::text[]) AND revoked = false",
      [[firstId, secondId]],
    );
    expect(remaining.rows[0]?.active_count).toBe(1);
  });

  it("detects a real PostgreSQL deadlock using opposite row-lock order", async () => {
    const setup = await connect();
    const firstId = randomUUID();
    const secondId = randomUUID();
    await setup.query(
      "INSERT INTO authorization_state (authorization_id, run_budget, consumed_runs, state_version, revoked) VALUES ($1, 1, 0, 0, false), ($2, 1, 0, 0, false)",
      [firstId, secondId],
    );
    const first = await connect(true);
    const second = await connect(true);
    try {
      await first.query("BEGIN");
      await second.query("BEGIN");
      await first.query("SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE", [firstId]);
      await second.query("SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE", [secondId]);

      const firstBackend = await first.query<{ pid: number }>("SELECT pg_backend_pid() AS pid");
      const firstWaits = first.query(
        "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
        [secondId],
      );
      await waitForLockWaiter(
        firstBackend.rows[0]!.pid,
        "first deadlock participant blocked by the second participant",
      );
      const secondWaits = second.query(
        "SELECT authorization_id FROM authorization_state WHERE authorization_id = $1 FOR UPDATE",
        [firstId],
      );
      const outcomes = await Promise.allSettled([firstWaits, secondWaits]);
      const deadlockVictims = outcomes.filter(
        (outcome) => outcome.status === "rejected" && (outcome.reason as { code?: string }).code === "40P01",
      );
      const survivors = outcomes.filter((outcome) => outcome.status === "fulfilled");
      expect(deadlockVictims).toHaveLength(1);
      expect(survivors).toHaveLength(1);
    } finally {
      await Promise.all([
        first.query("ROLLBACK").catch(() => undefined),
        second.query("ROLLBACK").catch(() => undefined),
      ]);
      await Promise.all([first.end().catch(() => undefined), second.end().catch(() => undefined)]);
    }
    const rows = await setup.query(
      "SELECT count(*)::int AS count FROM authorization_state WHERE authorization_id = ANY($1::text[])",
      [[firstId, secondId]],
    );
    expect(rows.rows[0]?.count).toBe(2);
  });

});
