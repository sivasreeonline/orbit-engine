import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import { PostgresExecutionJobRepository } from "./execution-job-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";
const verifierConnections: Client[] = [];

afterAll(async () => {
  await Promise.all(verifierConnections.map((client) => client.end().catch(() => undefined)));
});

describe.skipIf(!databaseUrl)("PostgresExecutionJobRepository PostgreSQL integration", () => {
  it("allows one concurrent claimant, reclaims an expired lease and fences the old worker", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const jobs = new PostgresExecutionJobRepository(databaseUrl);
    const created = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: "job-claim-integration",
    }, `job-claim-${randomUUID()}`);

    const [first, second] = await Promise.all([
      jobs.claim(created.executionId, "consumer-a", 1),
      jobs.claim(created.executionId, "consumer-b", 1),
    ]);
    const claimed = [first, second].filter((result) => result.status === "CLAIMED");
    const duplicate = [first, second].filter((result) => result.status === "ALREADY_CLAIMED");
    expect(claimed).toHaveLength(1);
    expect(duplicate).toHaveLength(1);
    if (claimed[0]?.status !== "CLAIMED") throw new Error("expected_one_claim");
    expect(claimed[0].lease.stateVersion).toBe("2");

    await new Promise((resolve) => setTimeout(resolve, 1_150));
    const reclaimed = await jobs.claim(created.executionId, "consumer-c", 30);
    expect(reclaimed.status).toBe("CLAIMED");
    if (reclaimed.status !== "CLAIMED") throw new Error("expected_expired_lease_reclaim");
    expect(reclaimed.lease.leaseToken).not.toBe(claimed[0].lease.leaseToken);
    expect(reclaimed.lease.stateVersion).toBe("3");

    await expect(jobs.markRunning(
      created.executionId, claimed[0].lease.leaseOwner, claimed[0].lease.leaseToken,
    )).resolves.toBe(false);
    await expect(jobs.markRunning(
      created.executionId, "consumer-c", reclaimed.lease.leaseToken,
    )).resolves.toBe(true);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-execution-job-integration-test",
    });
    verifierConnections.push(verifier);
    await verifier.connect();
    const state = await verifier.query<{ state: string; state_version: string }>(
      "SELECT state, state_version FROM execution_jobs WHERE id = $1::uuid",
      [created.executionId],
    );
    expect(state.rows[0]).toEqual({ state: "RUNNING", state_version: "4" });
  }, 10_000);
});
