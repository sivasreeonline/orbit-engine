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
          outbox_protocol_version: "v1",
          correlation_id: "corr-1",
        }]) as unknown as T[] };
      }
      if (text.includes("INSERT INTO runner_dispatch_outbox")) {
        if (options.failInsert) throw new Error("simulated_insert_failure");
        return { rows: (options.inserted ?? [{
          id: dispatchId,
          attempt_id: attemptId,
          protocol_version: "v1",
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
  it("validates authoritative job/outbox identity and commits one durable intent", async () => {
    const fake = fakeClient();
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
      outbox_protocol_version: "v1", correlation_id: "corr-1",
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
      outbox_protocol_version: "v1",
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
      outbox_protocol_version: "v1", correlation_id: "corr-1",
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

  it("rejects malformed, unknown-version and extended envelopes before connecting", async () => {
    const fake = fakeClient();
    const repository = new PostgresRunnerDispatchHandoffRepository(connection, () => fake.client);

    await expect(repository.record({ ...envelope, protocolVersion: "v2" }))
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
