import { describe, expect, it } from "vitest";
import { canonicalTestBundleBytes, canonicalTestBundleIdentity } from "./canonical-test-bundle";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const cases = [{
  testCaseId: "case-1",
  sequence: 1,
  visibility: "PUBLIC" as const,
  input: "1 2",
  expectedOutput: "3\n",
}];

describe("canonicalTestBundleBytes", () => {
  it("encodes the version marker, count and case fields deterministically", () => {
    const encoded = canonicalTestBundleBytes(cases);
    expect(hex(encoded)).toBe(
      "00000016534b59484947482d544553542d42554e444c452d5631" +
      "00000001" +
      "00000006636173652d31" +
      "00000001" +
      "01" +
      "00000003312032" +
      "00000002330a",
    );
    expect(canonicalTestBundleBytes(cases)).toEqual(encoded);
  });

  it("changes the canonical bytes when visibility or expected output changes", () => {
    const hidden = [{ ...cases[0]!, visibility: "HIDDEN" as const }];
    const changedOutput = [{ ...cases[0]!, expectedOutput: "3" }];
    expect(canonicalTestBundleBytes(hidden)).not.toEqual(canonicalTestBundleBytes(cases));
    expect(canonicalTestBundleBytes(changedOutput)).not.toEqual(canonicalTestBundleBytes(cases));
  });

  it("derives one stable digest and action-scoped bundle identity", async () => {
    const problemVersionId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
    const run = await canonicalTestBundleIdentity(problemVersionId, "RUN", cases);
    const repeated = await canonicalTestBundleIdentity(problemVersionId, "RUN", cases);
    const submit = await canonicalTestBundleIdentity(problemVersionId, "SUBMIT", cases);

    expect(repeated).toEqual(run);
    expect(run.testBundleSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(run.testBundleId).toBe(
      `${problemVersionId}-run-${run.testBundleSha256.slice(0, 16)}`,
    );
    expect(submit.testBundleSha256).toBe(run.testBundleSha256);
    expect(submit.testBundleId).not.toBe(run.testBundleId);
  });

  it("rejects invalid sequence numbers", () => {
    expect(() => canonicalTestBundleBytes([{ ...cases[0]!, sequence: 0 }]))
      .toThrow("runner_artifact_test_sequence_invalid");
  });
});
