import { describe, expect, it } from "vitest";
import { canonicalTestBundleBytes } from "./canonical-test-bundle";

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

  it("rejects invalid sequence numbers", () => {
    expect(() => canonicalTestBundleBytes([{ ...cases[0]!, sequence: 0 }]))
      .toThrow("runner_artifact_test_sequence_invalid");
  });
});
