import { describe, expect, it, vi } from "vitest";
import { PostgresLocalDispatchSink } from "./postgres-local-dispatch-sink";

const envelope = {
  executionId: "10000000-0000-4000-8000-000000000001",
  attemptId: "20000000-0000-4000-8000-000000000001",
  protocolVersion: "v1" as const,
};

describe("PostgresLocalDispatchSink", () => {
  it("resolves only after the durable handoff repository records the intent", async () => {
    const record = vi.fn().mockResolvedValue({
      status: "RECORDED",
      dispatchId: "30000000-0000-4000-8000-000000000001",
    });
    const sink = new PostgresLocalDispatchSink({ record });

    await expect(sink.accept(envelope)).resolves.toBeUndefined();
    expect(record).toHaveBeenCalledWith(envelope);
  });

  it("treats an exact durable duplicate as accepted", async () => {
    const record = vi.fn().mockResolvedValue({
      status: "DUPLICATE",
      dispatchId: "30000000-0000-4000-8000-000000000001",
    });
    const sink = new PostgresLocalDispatchSink({ record });

    await expect(sink.accept(envelope)).resolves.toBeUndefined();
  });

  it("propagates persistence failures so the intake outbox is not acknowledged", async () => {
    const record = vi.fn().mockRejectedValue(new Error("database_unavailable"));
    const sink = new PostgresLocalDispatchSink({ record });

    await expect(sink.accept(envelope)).rejects.toThrow("database_unavailable");
  });
});
