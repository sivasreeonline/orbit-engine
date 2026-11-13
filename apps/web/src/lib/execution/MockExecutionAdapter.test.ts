import { describe, expect, it } from "vitest";
import { MockExecutionAdapter } from "./MockExecutionAdapter";

const adapter = new MockExecutionAdapter();

const request = {
  problemId: "SH-ARR-001",
  problemVersion: "1",
  language: "java" as const,
  runtimeVersion: "25",
  action: "RUN" as const,
  sourceCode: "public class Main {}",
};

describe("MockExecutionAdapter", () => {
  it("clearly reports that Run did not execute source code", async () => {
    const result = await adapter.execute(request);

    expect(result.mode).toBe("MOCK");
    expect(result.state).toBe("NOT_CONNECTED");
    expect(result.action).toBe("RUN");
    expect(result.message).toMatch(/not executed/i);
    expect(result).not.toHaveProperty("verdict");
    expect(result).not.toHaveProperty("score");
  });

  it("does not claim an official Submit verdict", async () => {
    const result = await adapter.execute({
      ...request,
      action: "SUBMIT",
    });

    expect(result.action).toBe("SUBMIT");
    expect(result.state).toBe("NOT_CONNECTED");
    expect(result.message).toMatch(/no verdict or score/i);
    expect(result).not.toHaveProperty("testResults");
  });

  it("does not return or persist the submitted source", async () => {
    const result = await adapter.execute(request);

    expect(JSON.stringify(result)).not.toContain(request.sourceCode);
  });
});
