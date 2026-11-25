import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canonicalTestBundleIdentity } from "./canonical-test-bundle";
import {
  PostgresRunnerArtifactRepository,
  RunnerArtifactIntegrityError,
} from "./runner-artifact-repository";

const executionId = "20000000-0000-4000-8000-000000000001";
const attemptId = "30000000-0000-4000-8000-000000000001";
const problemVersionId = "40000000-0000-4000-8000-000000000001";
const sourceArtifactId = "50000000-0000-4000-8000-000000000001";
const runnerId = "60000000-0000-4000-8000-000000000001";
const leaseToken = "70000000-0000-4000-8000-000000000001";
const correlationId = "10000000-0000-4000-8000-000000000001";
const keyId = "runner-v2-artifact-test";
const connectionString = "postgres://test";

function makeFixture() {
  const now = Date.now();
  const deadlineAt = new Date(now + 60_000).toISOString();
  const sourceCode = "public class Main { public static void main(String[] args) {} }\n";
  const sourceBytes = new TextEncoder().encode(sourceCode);
  const sourceSha256 = createHash("sha256").update(sourceBytes).digest("hex");
  const testCases = [{
    testCaseId: "80000000-0000-4000-8000-000000000001",
    sequence: 1,
    visibility: "PUBLIC" as const,
    input: "1\n",
    expectedOutput: "1\n",
  }];
  return { now, deadlineAt, sourceCode, sourceBytes, sourceSha256, testCases };
}

async function makeClient(fixture: ReturnType<typeof makeFixture>, options: {
  protocolVersion?: string;
  requestProtocolVersion?: string | null;
  requestAttemptId?: string | null;
  requestCorrelationId?: string | null;
  requestDeadlineAt?: string | null;
  corruptDigest?: boolean;
} = {}) {
  const bundle = await canonicalTestBundleIdentity(problemVersionId, "RUN", fixture.testCases);
  const requestDocument = {
    protocolVersion: "v2",
    correlationId,
    executionId,
    attemptId,
    problemVersionId,
    action: "RUN",
    language: "java",
    runtimeVersion: "25",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    sourceArtifactId,
    sourceSha256: fixture.sourceSha256,
    testBundleId: bundle.testBundleId,
    comparisonPolicy: "EXACT_BYTES",
    deadlineAt: fixture.deadlineAt,
    cancellationRef: "cxl_" + "b".repeat(32),
    limits: {
      cpuQuotaMillis: 1000, memoryBytes: 134217728, wallTimeMillis: 5000,
      processLimit: 16, outputBytes: 65536, scratchBytes: 1048576, scratchInodes: 128,
    },
  };
  const requestBytes = new TextEncoder().encode(JSON.stringify(requestDocument));
  const requestSha256 = createHash("sha256").update(requestBytes).digest("hex");
  const artifactRow = {
    dispatch_id: "90000000-0000-4000-8000-000000000001",
    dispatch_protocol_version: options.protocolVersion ?? "v2",
    dispatch_correlation_id: correlationId,
    execution_id: executionId,
    attempt_id: attemptId,
    delivery_state: "PENDING",
    dispatch_owner: runnerId,
    dispatch_token: leaseToken,
    dispatch_expires_at: new Date(fixture.now + 30_000),
    job_state: "RUNNING",
    job_owner: runnerId,
    job_token: leaseToken,
    job_expires_at: new Date(fixture.now + 30_000),
    attempt_tenant_id: "a0000000-0000-4000-8000-000000000001",
    attempt_actor_user_id: "b0000000-0000-4000-8000-000000000001",
    action: "RUN",
    language: "java",
    runtime_version: "25",
    problem_version_id: problemVersionId,
    problem_slug: "two-sum",
    problem_title: "Two Sum",
    source_snapshot_id: sourceArtifactId,
    attempt_source_sha256: fixture.sourceSha256,
    snapshot_sha256: fixture.sourceSha256,
    snapshot_byte_length: fixture.sourceBytes.byteLength,
    storage_kind: "DATABASE",
    source_bytes: fixture.sourceBytes,
    acceptance_id: "c0000000-0000-4000-8000-000000000001",
    accepted_runner_id: runnerId,
    accepted_key_id: keyId,
    start_event_id: "d0000000-0000-4000-8000-000000000001",
    started_runner_id: runnerId,
    started_key_id: keyId,
    request_protocol_version: options.requestProtocolVersion === undefined ? "v2" : options.requestProtocolVersion,
    request_attempt_id: options.requestAttemptId === undefined ? attemptId : options.requestAttemptId,
    request_correlation_id: options.requestCorrelationId === undefined ? correlationId : options.requestCorrelationId,
    request_deadline_at: options.requestDeadlineAt === undefined ? fixture.deadlineAt : options.requestDeadlineAt,
    request_sha256: options.corruptDigest ? "0".repeat(64) : requestSha256,
    request_bytes: requestBytes,
  };
  const calls: string[] = [];
  const client = {
    connect: vi.fn(async () => undefined),
    end: vi.fn(async () => undefined),
    query: vi.fn(async (sql: string) => {
      calls.push(sql);
      if (sql.includes("FROM runner_machine_keys")) return { rows: [{ key_id: keyId }] };
      if (sql.includes("FROM runner_dispatch_outbox AS dispatch")) return { rows: [artifactRow] };
      if (sql.includes("FROM problem_test_cases")) return {
        rows: fixture.testCases.map((item) => ({
          id: item.testCaseId,
          sequence: item.sequence,
          visibility: item.visibility,
          input_data: new TextEncoder().encode(item.input),
          expected_output: new TextEncoder().encode(item.expectedOutput),
        })),
      };
      if (sql.includes("SELECT job.id AS execution_id")) return { rows: [{ execution_id: executionId }] };
      return { rows: [] };
    }),
  };
  const repository = new PostgresRunnerArtifactRepository(connectionString, () => client as never);
  return { repository, client, calls, requestBytes, requestSha256, bundle };
}

describe("runner artifact protocol v2 request delivery", () => {
  it("returns the exact immutable request bytes and digest after runner authorization and lease checks", async () => {
    const fixture = makeFixture();
    const fake = await makeClient(fixture);
    const artifact = await fake.repository.fetch({
      dispatchId: "90000000-0000-4000-8000-000000000001",
      executionId,
      attemptId,
      leaseToken,
      runnerId,
      keyId,
    });
    expect(artifact.protocolRequest?.requestSha256).toBe(fake.requestSha256);
    expect(new Uint8Array(Buffer.from(artifact.protocolRequest?.requestBytesBase64 ?? "", "base64")))
      .toEqual(fake.requestBytes);
    expect(artifact.testBundleId).toBe(fake.bundle.testBundleId);
    expect(fake.client.query).toHaveBeenCalled();
    expect(fake.client.end).toHaveBeenCalledOnce();
  });

  it.each([
    ["missing request", { requestProtocolVersion: null }],
    ["mismatched attempt", { requestAttemptId: "e0000000-0000-4000-8000-000000000001" }],
    ["mismatched correlation", { requestCorrelationId: "f0000000-0000-4000-8000-000000000001" }],
    ["expired deadline", { requestDeadlineAt: new Date(Date.now() - 1000).toISOString() }],
    ["corrupted digest", { corruptDigest: true }],
  ])("fails closed for %s", async (_name, options) => {
    const fixture = makeFixture();
    const fake = await makeClient(fixture, options);
    await expect(fake.repository.fetch({
      dispatchId: "90000000-0000-4000-8000-000000000001",
      executionId,
      attemptId,
      leaseToken,
      runnerId,
      keyId,
    })).rejects.toBeInstanceOf(RunnerArtifactIntegrityError);
    expect(fake.calls.some((sql) => sql.includes("SELECT job.id AS execution_id"))).toBe(false);
    expect(fake.client.end).toHaveBeenCalledOnce();
  });
});
