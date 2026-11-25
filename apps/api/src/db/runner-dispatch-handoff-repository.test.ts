import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  InvalidRunnerDispatchEnvelopeError,
  PostgresRunnerDispatchHandoffRepository,
} from "./runner-dispatch-handoff-repository";

interface Call {
  readonly text: string;
  readonly values: unknown[] | undefined;
}

function fakeClient(options: {
  readonly authoritative?: Record<string, unknown>[];
  readonly inserted?: Record<string, unknown>[];
  readonly existing?: Record<string, unknown>[];
  readonly failInsert?: boolean;
} = {}) {
  const calls: Call[] = [];
  let ended = false;
  const client = {
    async connect() {},
    async query<T extends Record<string, unknown>>(text: string, values?: unknown[]) {
      calls.push({ text, values });
      if (text.includes("FROM execution_jobs AS ej")) {
        return { rows: (options.authoritative ?? [{
          attempt_id: attemptId,
          job_state: "QUEUED",
          outbox_attempt_id: attemptId,
          outbox_protocol_version: "v1", outbox_payload_protocol_version: "v1",
          correlation_id: "corr-1",
          request_attempt_id: null, request_protocol_version: null,
          request_correlation_id: null, request_deadline_at: null,
          request_deadline_valid: null, request_sha256: null, request_bytes: null,
        }]) as unknown as T[] };
      }
      if (text.includes("INSERT INTO runner_dispatch_outbox")) {
        if (options.failInsert) throw new Error("simulated_insert_failure");
        return { rows: (options.inserted ?? [{
          id: dispatchId,
          attempt_id: attemptId,
          protocol_version: String(values?.[2] ?? "v1"),
          correlation_id: "corr-1",
        }]) as unknown as T[] };
      }
      if (text.includes("FROM runner_dispatch_outbox")) {
        return { rows: (options.existing ?? [{
          id: dispatchId,
          attempt_id: attemptId,
          protocol_version: "v1",
          correlation_id: "corr-1",
        }]) as unknown as T[] };
      }
      return { rows: [] as T[] };
    },
    async end() { ended = true; },
  };
  return { client, calls, ended: () => ended };
}

const connection = "postgres://test-user:test-password@localhost/test";
const executionId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const attemptId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
const dispatchId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
const envelope = { executionId, attemptId, protocolVersion: "v1" } as const;

describe("PostgresRunnerDispatchHandoffRepository", () => {
  it("validates persisted v2 request bytes and records a v2 intent", async () => {
    const deadlineAt = new Date(Date.now() + 60_000).toISOString();
    const correlationId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
    const document = {
      protocolVersion: "v2", correlationId, executionId, attemptId,
      problemVersionId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      action: "RUN", language: "java", runtimeVersion: "25",
      runtimeImageDigest: "sha256:" + "a".repeat(64),
      sourceArtifactId: "source-snapshot-1", sourceSha256: "b".repeat(64),
      testBundleId: "two-sum-run-" + "c".repeat(16), comparisonPolicy: "EXACT_BYTES",
      deadlineAt, cancellationRef: "cxl_" + "d".repeat(32),
      limits: { cpuQuotaMillis: 1000, memoryBytes: 134217728, wallTimeMillis: 5000,
        processLimit: 16, outputBytes: 65536, scratchBytes: 1048576, scratchInodes: 128 },
    };
    const requestBytes = new TextEncoder().encode(JSON.stringify(document));
    const requestSha = createHash("sha256").update(requestBytes).digest("hex");
    const fake = fakeClient({ authoritative: [{
      attempt_id: attemptId, job_state: "QUEUED", outbox_attempt_id: attemptId,
      outbox_protocol_version: "v2", outbox_payload_protocol_version: "v2", correlation_id: correlationId,
      request_attempt_id: attemptId, request_protocol_version: "v2",
      request_correlation_id: correlationId, request_deadline_at: deadlineAt,
      request_deadline_valid: true, request_sha256: requestSha, request_bytes: requestBytes,
    }], existing: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);
    await expect(repository.record({ executionId, attemptId, protocolVersion: "v2" }))
      .resolves.toEqual({ status: "RECORDED", dispatchId });
    expect(fake.calls.find((call) => call.text.includes("INSERT INTO runner_dispatch_outbox"))?.values)
      .toEqual([executionId, attemptId, "v2", correlationId]);
  });

  it("rejects a v2 request whose persisted digest does not match its bytes", async () => {
    const deadlineAt = new Date(Date.now() + 60_000).toISOString();
    const correlationId = "cccccccc-cccc-4ccc-8ccc-ccccccccccc1";
    const bytes = new TextEncoder().encode(JSON.stringify({ protocolVersion: "v2" }));
    const fake = fakeClient({ authoritative: [{
      attempt_id: attemptId, job_state: "QUEUED", outbox_attempt_id: attemptId,
      outbox_protocol_version: "v2", outbox_payload_protocol_version: "v2", correlation_id: correlationId,
      request_attempt_id: attemptId, request_protocol_version: "v2",
      request_correlation_id: correlationId, request_deadline_at: deadlineAt,
      request_deadline_valid: true, request_sha256: "0".repeat(64), request_bytes: bytes,
    }], existing: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);
    await expect(repository.record({ executionId, attemptId, protocolVersion: "v3" } as never))
      .rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO runner_dispatch_outbox"))).toBe(false);
  });

  it("validates authoritative job/outbox identity and commits one durable intent", async () => {
    const fake = fakeClient({ existing: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record(envelope)).resolves.toEqual({
      status: "RECORDED",
      dispatchId,
    });

    expect(fake.calls.some((call) => call.text === "BEGIN")).toBe(true);
    expect(fake.calls.find((call) => call.text.includes("FROM execution_jobs AS ej"))?.text)
      .toContain("FOR UPDATE OF ej");
    expect(fake.calls.find((call) => call.text.includes("INSERT INTO runner_dispatch_outbox"))?.values)
      .toEqual([executionId, attemptId, "v1", "corr-1"]);
    expect(fake.calls.at(-1)?.text).toBe("COMMIT");
    expect(fake.ended()).toBe(true);
  });

  it("returns the existing intent for a duplicate delivery", async () => {
    const fake = fakeClient({ authoritative: [{
      attempt_id: attemptId, job_state: "RUNNING", outbox_attempt_id: attemptId,
      outbox_protocol_version: "v1", outbox_payload_protocol_version: "v1", correlation_id: "corr-1",
    }], inserted: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record(envelope)).resolves.toEqual({
      status: "DUPLICATE",
      dispatchId,
    });
    expect(fake.calls.at(-1)?.text).toBe("COMMIT");
  });

  it("rolls back when the authoritative job, attempt or outbox do not match", async () => {
    const fake = fakeClient({ authoritative: [{
      attempt_id: attemptId,
      job_state: "RUNNING",
      outbox_attempt_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
      outbox_protocol_version: "v1", outbox_payload_protocol_version: "v1",
      correlation_id: "corr-1",
    }], existing: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record(envelope)).rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    expect(fake.calls.at(-1)?.text).toBe("ROLLBACK");
    expect(fake.calls.some((call) => call.text.includes("INSERT INTO runner_dispatch_outbox"))).toBe(false);
  });

  it("rejects a first-time handoff when the job is no longer queued", async () => {
    const fake = fakeClient({ authoritative: [{
      attempt_id: attemptId, job_state: "RUNNING", outbox_attempt_id: attemptId,
      outbox_protocol_version: "v1", outbox_payload_protocol_version: "v1", correlation_id: "corr-1",
    }], existing: [] });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);
    await expect(repository.record(envelope)).rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    expect(fake.calls.at(-1)?.text).toBe("ROLLBACK");
  });

  it("rolls back a failed intent insert so the queue message can be retried", async () => {
    const fake = fakeClient({ existing: [], failInsert: true });
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record(envelope)).rejects.toThrow("database_unavailable");
    expect(fake.calls.at(-1)?.text).toBe("ROLLBACK");
  });

  it("rejects malformed, unsupported-version and extended envelopes before connecting", async () => {
    const fake = fakeClient();
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record({ ...envelope, protocolVersion: "v3" } as never))
      .rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    await expect(repository.record({ ...envelope, sourceCode: "must-not-cross" } as never))
      .rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    await expect(repository.record({ ...envelope, executionId: "bad" }))
      .rejects.toBeInstanceOf(InvalidRunnerDispatchEnvelopeError);
    expect(fake.calls).toHaveLength(0);
    expect(fake.ended()).toBe(false);
  });

  it("fails closed without database configuration", async () => {
    const repository = new PostgresRunnerDispatchHandoffRepository(undefined);
    await expect(repository.record(envelope)).rejects.toThrow("database_unavailable");
  });
});
