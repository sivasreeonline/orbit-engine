import { createHash, randomBytes, randomUUID } from "node:crypto";
import { Client } from "pg";
import { describe, expect, it } from "vitest";
import { PostgresExecutionIntakeRepository } from "./execution-intake-repository";
import type { ExecutionProtocolV2Policy } from "../security/execution-protocol-v2-policy";
import { PostgresRunnerDispatchHandoffRepository } from "./runner-dispatch-handoff-repository";
import { PostgresRunnerDispatchLeaseRepository } from "./runner-dispatch-lease-repository";
import { PostgresRunnerAcceptanceRepository } from "./runner-acceptance-repository";
import { PostgresRunnerStartRepository } from "./runner-start-repository";
import {
  PostgresRunnerArtifactRepository,
  RunnerArtifactNotStartedError,
  RunnerArtifactStaleLeaseError,
} from "./runner-artifact-repository";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = "30000000-0000-4000-8000-000000000001";

function canonicalTestBundleSha256(cases: readonly {
  testCaseId: string;
  sequence: number;
  visibility: "PUBLIC" | "HIDDEN";
  input: string;
  expectedOutput: string;
}[]): string {
  const chunks: Buffer[] = [];
  const appendU32 = (value: number) => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value);
    chunks.push(buffer);
  };
  const appendField = (value: string) => {
    const bytes = Buffer.from(value, "utf8");
    appendU32(bytes.length);
    chunks.push(bytes);
  };

  appendField("SKYHIGH-TEST-BUNDLE-V1");
  appendU32(cases.length);
  for (const testCase of cases) {
    appendField(testCase.testCaseId);
    appendU32(testCase.sequence);
    chunks.push(Buffer.from([testCase.visibility === "PUBLIC" ? 1 : 2]));
    appendField(testCase.input);
    appendField(testCase.expectedOutput);
  }
  return createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}

async function createClaimedDispatch(
  runnerId: string,
  actorId: string,
  action: "RUN" | "SUBMIT",
) {
  const intake = new PostgresExecutionIntakeRepository(databaseUrl);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const dispatches = new PostgresRunnerDispatchLeaseRepository(databaseUrl);
  const sourceCode = `public class Main { public static void main(String[] args) { System.out.println("${randomUUID()}"); } }\n`;
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action,
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode,
    correlationId: `runner-artifact-${randomUUID()}`,
  }, `runner-artifact-${randomUUID()}`);
  await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v1",
  });
  const claimed = await dispatches.claimFairBatchForRunner(runnerId, 1, 2, 120);
  const dispatch = claimed.find((item) => item.executionId === created.executionId);
  if (!dispatch) throw new Error("RUNNER_ARTIFACT_DISPATCH_NOT_CLAIMED");
  return { created, dispatch, sourceCode };
}


async function createV2Dispatch(
  runnerId: string,
  actorId: string,
  action: "RUN" | "SUBMIT",
) {
  const policy: ExecutionProtocolV2Policy = {
    policyRevision: "postgres-artifact-v2-integration",
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
  };
  const intake = new PostgresExecutionIntakeRepository(databaseUrl, undefined, policy);
  const handoff = new PostgresRunnerDispatchHandoffRepository(databaseUrl);
  const sourceCode = `public class Main { public static void main(String[] args) { System.out.println("v2-${randomUUID()}"); } }\n`;
  const created = await intake.create({
    principal: { tenantId, userId: actorId, roles: ["STUDENT"] },
    action,
    problemSlug: "two-sum",
    language: "java",
    runtimeVersion: "25",
    sourceCode,
    correlationId: `runner-artifact-v2-${randomUUID()}`,
  }, `runner-artifact-v2-${randomUUID()}`);
  const handoffResult = await handoff.record({
    executionId: created.executionId,
    attemptId: created.attemptId,
    protocolVersion: "v2",
  });
  const leaseToken = randomUUID();
  // Test-only lease fixture: production claim SQL intentionally remains v1-only.
  const setup = new Client({ connectionString: databaseUrl });
  await setup.connect();
  try {
    await setup.query(
      "UPDATE runner_dispatch_outbox SET lease_owner = $2, lease_token = $3::uuid, lease_expires_at = now() + interval '2 minutes' WHERE id = $1::uuid",
      [handoffResult.dispatchId, runnerId, leaseToken],
    );
    await setup.query(
      "UPDATE execution_jobs SET state = 'CLAIMED', lease_owner = $2, lease_token = $3::uuid, lease_expires_at = now() + interval '2 minutes' WHERE id = $1::uuid",
      [created.executionId, runnerId, leaseToken],
    );
  } finally {
    await setup.end();
  }
  return {
    created,
    sourceCode,
    dispatch: {
      id: handoffResult.dispatchId,
      executionId: created.executionId,
      attemptId: created.attemptId,
      leaseToken,
    },
  };
}

async function acceptAndStart(
  runnerId: string,
  keyId: string,
  created: Awaited<ReturnType<typeof createClaimedDispatch>>["created"],
  dispatch: { readonly id: string; readonly executionId: string; readonly attemptId: string; readonly leaseToken: string },
) {
  const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
  const start = new PostgresRunnerStartRepository(databaseUrl);
  await acceptance.record({
    acceptanceId: randomUUID(),
    dispatchId: dispatch.id,
    executionId: dispatch.executionId,
    attemptId: dispatch.attemptId,
    runnerId,
    keyId,
    leaseToken: dispatch.leaseToken,
    receiptSha256: "f".repeat(64),
  });
  await start.start({
    dispatchId: dispatch.id,
    executionId: created.executionId,
    attemptId: created.attemptId,
    leaseToken: dispatch.leaseToken,
    runnerId,
    keyId,
  });
}

describe.skipIf(!databaseUrl)("runner private artifact PostgreSQL integration", () => {
  it("returns public-only fixtures for RUN and the full immutable bundle for SUBMIT", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-artifact-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const artifacts = new PostgresRunnerArtifactRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `artifact-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const run = await createClaimedDispatch(runnerId, actorId, "RUN");
      await acceptAndStart(runnerId, keyId, run.created, run.dispatch);
      const runArtifact = await artifacts.fetch({
        dispatchId: run.dispatch.id,
        executionId: run.created.executionId,
        attemptId: run.created.attemptId,
        leaseToken: run.dispatch.leaseToken,
        runnerId,
        keyId,
      });
      expect(runArtifact.action).toBe("RUN");
      expect(runArtifact.testCases).toHaveLength(2);
      expect(runArtifact.testCases.every((testCase) => testCase.visibility === "PUBLIC")).toBe(true);
      expect(runArtifact.testBundleId).toContain("-run-");
      expect(runArtifact.testBundleSha256).toBe(
        canonicalTestBundleSha256(runArtifact.testCases),
      );

      const submit = await createClaimedDispatch(runnerId, randomUUID(), "SUBMIT");
      await acceptAndStart(runnerId, keyId, submit.created, submit.dispatch);
      const submitArtifact = await artifacts.fetch({
        dispatchId: submit.dispatch.id,
        executionId: submit.created.executionId,
        attemptId: submit.created.attemptId,
        leaseToken: submit.dispatch.leaseToken,
        runnerId,
        keyId,
      });
      expect(submitArtifact.action).toBe("SUBMIT");
      expect(submitArtifact.testCases).toHaveLength(4);
      expect(submitArtifact.testCases.some((testCase) => testCase.visibility === "HIDDEN")).toBe(true);
      expect(submitArtifact.testBundleId).toContain("-submit-");

      expect(runArtifact.sourceCode).toBe(run.sourceCode);
      expect(runArtifact.sourceSha256).toBe(
        createHash("sha256").update(run.sourceCode, "utf8").digest("hex"),
      );
      expect(submitArtifact.sourceCode).toBe(submit.sourceCode);
      expect(submitArtifact.testBundleSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(submitArtifact.testBundleSha256).toBe(
        canonicalTestBundleSha256(submitArtifact.testCases),
      );
      expect(submitArtifact.problemVersionId).toBe("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1");
    } finally {
      await setup.end();
    }
  }, 25_000);


  it("delivers the exact persisted v2 request bytes from PostgreSQL after authenticated start", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-artifact-v2-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const artifacts = new PostgresRunnerArtifactRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `artifact-v2-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );

      const v2 = await createV2Dispatch(runnerId, actorId, "SUBMIT");
      await acceptAndStart(runnerId, keyId, v2.created, v2.dispatch);
      const artifact = await artifacts.fetch({
        dispatchId: v2.dispatch.id,
        executionId: v2.created.executionId,
        attemptId: v2.created.attemptId,
        leaseToken: v2.dispatch.leaseToken,
        runnerId,
        keyId,
      });

      expect(artifact.action).toBe("SUBMIT");
      expect(artifact.testCases).toHaveLength(4);
      expect(artifact.testCases.some((testCase) => testCase.visibility === "HIDDEN")).toBe(true);
      expect(artifact.protocolRequest).toBeDefined();
      expect(artifact.protocolRequest?.requestSha256).toMatch(/^[0-9a-f]{64}$/);

      const persisted = await setup.query<{
        request_bytes: Buffer;
        request_sha256: string;
        correlation_id: string;
      }>(
        "SELECT request_bytes, request_sha256, correlation_id::text AS correlation_id FROM execution_protocol_requests WHERE execution_id = $1::uuid",
        [v2.created.executionId],
      );
      expect(persisted.rows).toHaveLength(1);
      const exactBytes = persisted.rows[0]!.request_bytes;
      const exactSha256 = createHash("sha256").update(exactBytes).digest("hex");
      expect(exactSha256).toBe(persisted.rows[0]!.request_sha256.trim());
      expect(artifact.protocolRequest?.requestSha256).toBe(exactSha256);
      expect(Buffer.from(artifact.protocolRequest!.requestBytesBase64, "base64")).toEqual(exactBytes);

      const requestDocument = JSON.parse(exactBytes.toString("utf8")) as Record<string, unknown>;
      expect(requestDocument).toMatchObject({
        protocolVersion: "v2",
        executionId: v2.created.executionId,
        attemptId: v2.created.attemptId,
        correlationId: persisted.rows[0]!.correlation_id,
        action: "SUBMIT",
        language: "java",
        sourceSha256: artifact.sourceSha256,
        testBundleId: artifact.testBundleId,
        comparisonPolicy: "EXACT_BYTES",
      });
      expect(artifact.sourceCode).toBe(v2.sourceCode);
    } finally {
      await setup.end();
    }
  }, 25_000);

  it("requires the durable start receipt and an active unexpired lease", async () => {
    const runnerId = randomUUID();
    const actorId = randomUUID();
    const keyId = `runner-artifact-guard-${runnerId}`;
    const setup = new Client({ connectionString: databaseUrl });
    const artifacts = new PostgresRunnerArtifactRepository(databaseUrl);

    await setup.connect();
    try {
      await setup.query(
        "INSERT INTO runner_machines (id, machine_name) VALUES ($1, $2)",
        [runnerId, `artifact-guard-runner-${runnerId}`],
      );
      await setup.query(
        "INSERT INTO runner_machine_keys (key_id, runner_id, public_key) VALUES ($1, $2, $3)",
        [keyId, runnerId, randomBytes(32)],
      );
      const { created, dispatch } = await createClaimedDispatch(runnerId, actorId, "SUBMIT");
      const acceptance = new PostgresRunnerAcceptanceRepository(databaseUrl);
      await acceptance.record({
        acceptanceId: randomUUID(),
        dispatchId: dispatch.id,
        executionId: dispatch.executionId,
        attemptId: dispatch.attemptId,
        runnerId,
        keyId,
        leaseToken: dispatch.leaseToken,
        receiptSha256: "e".repeat(64),
      });
      const input = {
        dispatchId: dispatch.id,
        executionId: created.executionId,
        attemptId: created.attemptId,
        leaseToken: dispatch.leaseToken,
        runnerId,
        keyId,
      };
      await expect(artifacts.fetch(input)).rejects.toBeInstanceOf(RunnerArtifactNotStartedError);

      const start = new PostgresRunnerStartRepository(databaseUrl);
      await start.start({ ...input });
      await setup.query(
        "UPDATE runner_dispatch_outbox SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [dispatch.id],
      );
      await setup.query(
        "UPDATE execution_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
        [created.executionId],
      );
      await expect(artifacts.fetch(input)).rejects.toBeInstanceOf(RunnerArtifactStaleLeaseError);
    } finally {
      await setup.end();
    }
  }, 20_000);
});
