import { describe, expect, it, vi } from "vitest";
import type { ExecutionRequestedEnvelope } from "../db/runner-dispatch-handoff-repository";
import { consumeRunnerDispatchBatch } from "./runner-dispatch-queue-consumer";

const envelope: ExecutionRequestedEnvelope = {
  executionId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
  attemptId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
  protocolVersion: "v1",
};

function makeMessage(body: unknown) {
  const events: string[] = [];
  return {
    body,
    events,
    ack: vi.fn(() => { events.push("ack"); }),
    retry: vi.fn(() => { events.push("retry"); }),
  };
}

describe("consumeRunnerDispatchBatch", () => {
  it("acknowledges only after the durable handoff resolves", async () => {
    const message = makeMessage(envelope);
    const record = vi.fn(async () => {
      expect(message.events).toEqual([]);
      return { status: "RECORDED" as const, dispatchId: "dispatch-1" };
    });

    const summary = await consumeRunnerDispatchBatch(
      { messages: [message] },
      { record },
    );

    expect(summary).toEqual({ received: 1, acknowledged: 1, retried: 0 });
    expect(record).toHaveBeenCalledWith(envelope);
    expect(message.ack).toHaveBeenCalledOnce();
    expect(message.retry).not.toHaveBeenCalled();
    expect(message.events).toEqual(["ack"]);
  });

  it("acknowledges an exact duplicate because the durable intent already exists", async () => {
    const message = makeMessage(envelope);
    const record = vi.fn(async () => ({
      status: "DUPLICATE" as const,
      dispatchId: "dispatch-existing",
    }));

    const summary = await consumeRunnerDispatchBatch(
      { messages: [message] },
      { record },
    );

    expect(summary).toEqual({ received: 1, acknowledged: 1, retried: 0 });
    expect(message.ack).toHaveBeenCalledOnce();
  });

  it("retries when the durable handoff fails and does not acknowledge", async () => {
    const message = makeMessage(envelope);
    const record = vi.fn(async () => {
      throw new Error("private database failure");
    });

    const summary = await consumeRunnerDispatchBatch(
      { messages: [message] },
      { record },
    );

    expect(summary).toEqual({ received: 1, acknowledged: 0, retried: 1 });
    expect(message.ack).not.toHaveBeenCalled();
    expect(message.retry).toHaveBeenCalledOnce();
  });

  it("retries malformed or extended messages without passing them to persistence", async () => {
    const malformed = makeMessage({ ...envelope, sourceCode: "must-not-cross" });
    const unknownVersion = makeMessage({ ...envelope, protocolVersion: "v2" });
    const record = vi.fn(async () => ({
      status: "RECORDED" as const,
      dispatchId: "dispatch-1",
    }));

    const summary = await consumeRunnerDispatchBatch(
      { messages: [malformed, unknownVersion] },
      { record },
    );

    expect(summary).toEqual({ received: 2, acknowledged: 0, retried: 2 });
    expect(record).not.toHaveBeenCalled();
    expect(malformed.retry).toHaveBeenCalledOnce();
    expect(unknownVersion.retry).toHaveBeenCalledOnce();
  });
});
