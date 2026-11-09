import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresRunnerIdentityRepository } from "./runner-identity-repository";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("runner identity registry PostgreSQL integration", () => {
  it("resolves active identities and denies suspended identities or disabled pools", async () => {
    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-runner-identity-integration-test",
    });
    const repository = new PostgresRunnerIdentityRepository(databaseUrl);

    const suffix = randomUUID();
    const issuer = `https://identity.integration.test/${suffix}`;
    const subject = `service-subject-${suffix}`;
    const runnerId = `runner-integration-${suffix}`;
    const poolKey = `integration-${suffix}`;

    try {
      await verifier.connect();
      const pool = await verifier.query<{ id: string }>(
        "INSERT INTO runner_pools (pool_key) VALUES ($1) RETURNING id",
        [poolKey],
      );
      const poolId = pool.rows[0]?.id;
      if (!poolId) throw new Error("runner_identity_integration_pool_missing");

      await verifier.query(
        [
          "INSERT INTO runner_identities",
          "  (runner_id, pool_id, identity_issuer, identity_subject, scopes)",
          "VALUES ($1, $2::uuid, $3, $4, $5::text[])",
        ].join("\n"),
        [runnerId, poolId, issuer, subject, ["dispatch:claim", "dispatch:receipt"]],
      );

      await expect(repository.findActivePrincipal(issuer, subject)).resolves.toEqual({
        runnerId,
        poolId,
        subject,
        scopes: ["dispatch:claim", "dispatch:receipt"],
      });

      await verifier.query(
        "UPDATE runner_identities SET status = 'SUSPENDED' WHERE runner_id = $1",
        [runnerId],
      );
      await expect(repository.findActivePrincipal(issuer, subject)).resolves.toBeNull();

      await verifier.query(
        "UPDATE runner_identities SET status = 'ACTIVE' WHERE runner_id = $1",
        [runnerId],
      );
      await verifier.query(
        "UPDATE runner_pools SET status = 'DISABLED' WHERE id = $1::uuid",
        [poolId],
      );
      await expect(repository.findActivePrincipal(issuer, subject)).resolves.toBeNull();
    } finally {
      await verifier.end();
    }
  }, 10_000);
});
