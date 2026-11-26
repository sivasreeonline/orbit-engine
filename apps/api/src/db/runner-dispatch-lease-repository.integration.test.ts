import { randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";
const actorId = "20000000-0000-4000-8000-000000000001";

describe.skipIf(!databaseUrl)("runner dispatch lease PostgreSQL integration", () => {
  it("coordinates competing dispatchers, reclaims expiry and rejects stale acknowledgement", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);

    // The disposable CI database also contains the SQL-acceptance and handoff
    // integration fixtures. Retire their pending intents so this test owns one row.
    const leftovers = await leases.claimBatch("integration-cleanup", 100, 60);
    await Promise.all(leftovers.map((lease) =>
      leases.markDeadLetter(lease.id, "integration-cleanup", lease.leaseToken),
    ));

    const created = await intake.create({
      principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `dispatch-lease-${randomUUID()}`,
    }, `dispatch-lease-${randomUUID()}`);
    await handoff.record({
      executionId: created.executionId,
      attemptId: created.attemptId,
      protocolVersion: "v1",
    });

    const [firstBatch, secondBatch] = await Promise.all([
      leases.claimBatch("dispatcher-a", 1, 1),
      leases.claimBatch("dispatcher-b", 1, 1),
    ]);
    expect(firstBatch.length + secondBatch.length).toBe(1);
    const original = firstBatch[0] ?? secondBatch[0];
    if (!original) throw new Error("expected_one_dispatch_lease");

    await new Promise((resolve) => setTimeout(resolve, 1_150));
    const reclaimed = await leases.claimBatch("dispatcher-c", 1, 30);
    expect(reclaimed).toHaveLength(1);
    expect(reclaimed[0]?.id).toBe(original.id);
    expect(reclaimed[0]?.leaseToken).not.toBe(original.leaseToken);

    const oldWorker = firstBatch.length ? "dispatcher-a" : "dispatcher-b";
    await expect(leases.markDelivered(original.id, oldWorker, original.leaseToken)).resolves.toBe(false);
    await expect(leases.markDelivered(
      reclaimed[0]!.id, "dispatcher-c", reclaimed[0]!.leaseToken,
    )).resolves.toBe(true);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-runner-dispatch-lease-integration-test",
    });
    try {
      await verifier.connect();
      const state = await verifier.query<{ delivery_state: string; lease_owner: string | null }>(
        "SELECT delivery_state, lease_owner FROM runner_dispatch_outbox WHERE id = $1::uuid",
        [original.id],
      );
      expect(state.rows[0]).toEqual({ delivery_state: "DELIVERED", lease_owner: null });
    } finally {
      await verifier.end();
    }
  }, 15_000);

  it("never leases a v2 dispatch intent to the current v1 runner", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, {
      policyRevision: "v2-v1-claim-gate-integration",
      runtimeImageDigests: {
        java: `sha256:${"c".repeat(64)}`,
        python: `sha256:${"d".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 1_000,
        memoryBytes: 268_435_456,
        wallTimeMillis: 60_000,
        processLimit: 32,
        outputBytes: 1_048_576,
        scratchBytes: 16_777_216,
        scratchInodes: 1_024,
      },
    } satisfies ExecutionProtocolV2Policy);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const runnerId = randomUUID();

    // Clear unrelated v1 fixtures so the claim attempt below is deterministic.
    const leftovers = await leases.claimBatch("v2-claim-gate-cleanup", 100, 60);
    await Promise.all(leftovers.map((lease) =>
      leases.markDeadLetter(lease.id, "v2-claim-gate-cleanup", lease.leaseToken),
    ));

    const created = await intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `v2-claim-gate-${randomUUID()}`,
    }, `v2-claim-gate-${randomUUID()}`);
    const intent = await handoff.record({
      executionId: created.executionId,
      attemptId: created.attemptId,
      protocolVersion: "v2",
    });
    expect(intent.status).toBe("RECORDED");

    const claimed = await leases.claimFairBatchForRunner(runnerId, 10, 2, 120);
    expect(claimed.some((lease) => lease.id === intent.dispatchId)).toBe(false);

    const verifier = new Client({
      connectionString: databaseUrl,
      connectionTimeoutMillis: 5_000,
      application_name: "sky-high-v2-v1-claim-gate-integration-test",
    });
    try {
      await verifier.connect();
      const persisted = await verifier.query<{
        protocol_version: string;
        delivery_state: string;
        lease_owner: string | null;
        lease_token: string | null;
      }>(
        "SELECT protocol_version, delivery_state, lease_owner, lease_token::text AS lease_token FROM runner_dispatch_outbox WHERE id = $1::uuid",
        [intent.dispatchId],
      );
      expect(persisted.rows[0]).toEqual({
        protocol_version: "v2",
        delivery_state: "PENDING",
        lease_owner: null,
        lease_token: null,
      });
    } finally {
      await verifier.end();
    }
  }, 15_000);


  it("counts a mixed v1 and v2 active-lease set against the shared two-slot runner cap", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const verifier = new Client({
      connectionString: databaseUrl,
      application_name: "sky-high-shared-runner-cap-integration",
    });
    const runnerId = randomUUID();
    const v2Policy = {
      policyRevision: "v2-shared-cap-integration",
      runtimeImageDigests: {
        java: `sha256:${"e".repeat(64)}`,
        python: `sha256:${"f".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 1_000,
        memoryBytes: 268_435_456,
        wallTimeMillis: 60_000,
        processLimit: 32,
        outputBytes: 1_048_576,
        scratchBytes: 16_777_216,
        scratchInodes: 1_024,
      },
    } satisfies ExecutionProtocolV2Policy;
    const v2Intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, v2Policy);

    // Retire unrelated v1 dispatch fixtures so this test owns the v1 lease.
    const leftovers = await leases.claimBatch("shared-cap-cleanup", 100, 60);
    await Promise.all(leftovers.map((lease) =>
      leases.markDeadLetter(lease.id, "shared-cap-cleanup", lease.leaseToken),
    ));

    const sourceCode = "public class Main { public static void main(String[] args) {} }";
    const v1Created = await intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode,
      correlationId: `shared-cap-v1-${randomUUID()}`,
    }, `shared-cap-v1-${randomUUID()}`);
    const v2ActiveCreated = await v2Intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode,
      correlationId: `shared-cap-v2-active-${randomUUID()}`,
    }, `shared-cap-v2-active-${randomUUID()}`);
    const v2PendingCreated = await v2Intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode,
      correlationId: `shared-cap-v2-pending-${randomUUID()}`,
    }, `shared-cap-v2-pending-${randomUUID()}`);

    await handoff.record({
      executionId: v1Created.executionId,
      attemptId: v1Created.attemptId,
      protocolVersion: "v1",
    });
    const v2ActiveIntent = await handoff.record({
      executionId: v2ActiveCreated.executionId,
      attemptId: v2ActiveCreated.attemptId,
      protocolVersion: "v2",
    });
    const v2PendingIntent = await handoff.record({
      executionId: v2PendingCreated.executionId,
      attemptId: v2PendingCreated.attemptId,
      protocolVersion: "v2",
    });
    await verifier.connect();
    await verifier.query(
      "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
      [runnerId, `shared-cap-runner-${runnerId}`],
    );
    await verifier.query(
      "INSERT INTO runner_machine_protocol_capabilities (runner_id, protocol_version, qualification_reference) VALUES ($1, 'v2', $2)",
      [runnerId, `integration-qualification-${randomUUID()}`],
    );
    expect(v2ActiveIntent.status).toBe("RECORDED");
    expect(v2PendingIntent.status).toBe("RECORDED");

    try {
      const liveV1 = await leases.claimBatch("shared-cap-v1-fixture", 1, 120);
      expect(liveV1).toHaveLength(1);

      // Model one already-active lease of each protocol under the same runner.
      // The second v2 intent remains eligible but must not exceed the shared cap.
      await verifier.query(
        "UPDATE runner_dispatch_outbox SET lease_owner=$2, lease_token=gen_random_uuid(), lease_expires_at=now()+interval '120 seconds' WHERE id=$1::uuid",
        [liveV1[0]!.id, runnerId],
      );
      await verifier.query(
        "UPDATE runner_dispatch_outbox SET lease_owner=$2, lease_token=gen_random_uuid(), lease_expires_at=now()+interval '120 seconds' WHERE id=$1::uuid",
        [v2ActiveIntent.dispatchId, runnerId],
      );

      const activeByProtocol = await verifier.query<{
        protocol_version: string;
        active_count: number;
      }>(
        [
          "SELECT protocol_version, count(*)::integer AS active_count",
          "FROM runner_dispatch_outbox",
          "WHERE lease_owner=$1 AND delivery_state='PENDING' AND lease_expires_at > now()",
          "GROUP BY protocol_version ORDER BY protocol_version",
        ].join("\n"),
        [runnerId],
      );
      expect(activeByProtocol.rows).toEqual([
        { protocol_version: "v1", active_count: 1 },
        { protocol_version: "v2", active_count: 1 },
      ]);

      const v2Claim = await leases.claimFairBatchForRunnerV2(runnerId, 2, 2, 120);
      expect(v2Claim).toEqual([]);

      const pendingState = await verifier.query<{
        protocol_version: string;
        delivery_state: string;
        lease_owner: string | null;
        lease_token: string | null;
      }>(
        "SELECT protocol_version, delivery_state, lease_owner, lease_token::text AS lease_token FROM runner_dispatch_outbox WHERE id = $1::uuid",
        [v2PendingIntent.dispatchId],
      );
      expect(pendingState.rows[0]).toEqual({
        protocol_version: "v2",
        delivery_state: "PENDING",
        lease_owner: null,
        lease_token: null,
      });
    } finally {
      await verifier.query("DELETE FROM runner_machine_protocol_capabilities WHERE runner_id=$1", [runnerId]).catch(() => undefined);
      await verifier.query("DELETE FROM runner_machines WHERE id=$1", [runnerId]).catch(() => undefined);
      await verifier.end();
    }
  }, 15_000);

  it("rejects a v2 claim in PostgreSQL when the authenticated runner has no active qualification", async () => {
    const v2Policy = {
      policyRevision: "v2-unqualified-claim-integration",
      runtimeImageDigests: {
        java: `sha256:${"a".repeat(64)}`,
        python: `sha256:${"b".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 1_000,
        memoryBytes: 268_435_456,
        wallTimeMillis: 60_000,
        processLimit: 32,
        outputBytes: 1_048_576,
        scratchBytes: 16_777_216,
        scratchInodes: 1_024,
      },
    } satisfies ExecutionProtocolV2Policy;
    const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, v2Policy);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const leases = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
    const verifier = new Client({ connectionString: databaseUrl });
    const runnerId = randomUUID();
    await verifier.connect();
    await verifier.query(
      "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
      [runnerId, `unqualified-runner-${runnerId}`],
    );
    const created = await intake.create({
      principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
      action: "RUN",
      problemSlug: "two-sum",
      language: "java",
      runtimeVersion: "25",
      sourceCode: "public class Main { public static void main(String[] args) {} }",
      correlationId: `v2-unqualified-${randomUUID()}`,
    }, `v2-unqualified-${randomUUID()}`);
    const intent = await handoff.record({
      executionId: created.executionId,
      attemptId: created.attemptId,
      protocolVersion: "v2",
    });
    expect(intent.status).toBe("RECORDED");

    await expect(leases.claimFairBatchForRunnerV2(runnerId, 1, 2, 120))
      .rejects.toThrow("runner_protocol_not_qualified");

    try {
      const persisted = await verifier.query<{ lease_owner: string | null; lease_token: string | null }>(
        "SELECT lease_owner, lease_token::text AS lease_token FROM runner_dispatch_outbox WHERE id = $1::uuid",
        [intent.dispatchId],
      );
      expect(persisted.rows[0]).toEqual({ lease_owner: null, lease_token: null });
    } finally {
      await verifier.query("DELETE FROM runner_machine_protocol_capabilities WHERE runner_id=$1", [runnerId]).catch(() => undefined);
      await verifier.query("DELETE FROM runner_machines WHERE id=$1", [runnerId]).catch(() => undefined);
      await verifier.end();
    }
  }, 15_000);


  it("serializes v2 claims ahead of a concurrent qualification revocation", async () => {
    const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, {
      policyRevision: "v2-revocation-race-integration",
      runtimeImageDigests: {
        java: `sha256:${"1".repeat(64)}`,
        python: `sha256:${"2".repeat(64)}`,
      },
      limits: {
        cpuQuotaMillis: 1_000,
        memoryBytes: 268_435_456,
        wallTimeMillis: 60_000,
        processLimit: 32,
        outputBytes: 1_048_576,
        scratchBytes: 16_777_216,
        scratchInodes: 1_024,
      },
    } satisfies ExecutionProtocolV2Policy);
    const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
    const runnerId = randomUUID();
    const claimClient = new Client({ connectionString: databaseUrl });
    const revoker = new Client({ connectionString: databaseUrl });
    let signalQualificationRead!: () => void;
    let releaseQualification!: () => void;
    const qualificationRead = new Promise<void>((resolve) => {
      signalQualificationRead = resolve;
    });
    const qualificationGate = new Promise<void>((resolve) => {
      releaseQualification = resolve;
    });
    const interceptedClient = new Proxy(claimClient, {
      get(target, property) {
        if (property === "query") {
          return async (...args: [string, unknown[]?]) => {
            const result = await target.query(args[0], args[1]);
            if (args[0].includes("FROM runner_machine_protocol_capabilities")
              && args[0].includes("FOR SHARE")) {
              signalQualificationRead();
              await qualificationGate;
            }
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const leases = new PostgresRunnerDispatchLeaseRepository(
      databaseUrl,
      (() => interceptedClient as never),
    );

    try {
      await revoker.connect();
      await revoker.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `revocation-race-runner-${runnerId}`],
      );
      await revoker.query(
        "INSERT INTO runner_machine_protocol_capabilities (runner_id, protocol_version, qualification_reference) VALUES ($1, 'v2', $2)",
        [runnerId, `revocation-race-${randomUUID()}`],
      );
      const created = await intake.create({
        principal: { tenantId, userId: randomUUID(), roles: ["STUDENT"] },
        action: "RUN",
        problemSlug: "two-sum",
        language: "java",
        runtimeVersion: "25",
        sourceCode: "public class Main { public static void main(String[] args) {} }",
        correlationId: `v2-revocation-race-${randomUUID()}`,
      }, `v2-revocation-race-${randomUUID()}`);
      const intent = await handoff.record({
        executionId: created.executionId,
        attemptId: created.attemptId,
        protocolVersion: "v2",
      });
      expect(intent.status).toBe("RECORDED");

      const claimPromise = leases.claimFairBatchForRunnerV2(runnerId, 10, 10, 120);
      await qualificationRead;

      await revoker.query("BEGIN");
      await revoker.query("SET LOCAL lock_timeout = '100ms'");
      let revocationError: { code?: string } | undefined;
      try {
        await revoker.query(
          "UPDATE runner_machine_protocol_capabilities SET status='REVOKED', revoked_at=now() WHERE runner_id=$1 AND protocol_version='v2'",
          [runnerId],
        );
      } catch (error) {
        revocationError = error as { code?: string };
      }
      expect(revocationError?.code).toBe("55P03");
      await revoker.query("ROLLBACK");

      // The claim still owns its FOR SHARE lock. Once it commits, revocation
      // can proceed; it cannot retroactively invalidate the issued lease.
      releaseQualification();
      const claimed = await claimPromise;
      expect(claimed.some((lease) => lease.id === intent.dispatchId)).toBe(true);

      await revoker.query(
        "UPDATE runner_machine_protocol_capabilities SET status='REVOKED', revoked_at=now() WHERE runner_id=$1 AND protocol_version='v2'",
        [runnerId],
      );
      const capability = await revoker.query<{ status: string; revoked_at: Date | null }>(
        "SELECT status, revoked_at FROM runner_machine_protocol_capabilities WHERE runner_id=$1 AND protocol_version='v2'",
        [runnerId],
      );
      expect(capability.rows[0]?.status).toBe("REVOKED");
      expect(capability.rows[0]?.revoked_at).not.toBeNull();
    } finally {
      releaseQualification();
      await claimClient.end().catch(() => undefined);
      await revoker.query("ROLLBACK").catch(() => undefined);
      await revoker.query("DELETE FROM runner_machine_protocol_capabilities WHERE runner_id=$1", [runnerId]).catch(() => undefined);
      await revoker.query("DELETE FROM runner_machines WHERE id=$1", [runnerId]).catch(() => undefined);
      await revoker.end().catch(() => undefined);
    }
  }, 15_000);

});
