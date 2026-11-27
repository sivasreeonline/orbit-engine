// Copyright 2026 Sky High Coding Judge
// Result V2 TypeScript canonicalization tests.
//
// These tests consume the same shared fixtures as the Go tests in
// services/execution-runner/internal/protocol/result_v2_test.go, ensuring
// byte-for-byte JSON and SHA-256 parity between TypeScript and Go.
//
// Expected digest values are independently fixed in test/fixtures/result-v2/digests.json
// and are NOT generated from the implementation under test.

import {
  CanonicalResultV2,
  canonicalResultV2Bytes,
  canonicalResultV2Digest,
  canonicalResultV2Json,
  validateResultV2,
} from "./execution-protocol-v2-result";
import { describe, expect, it } from "vitest";

import * as path from "path";
import { fileURLToPath } from "url";

const FIXTURE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../test/fixtures/result-v2",
);

interface DigestFixture {
  filename: string;
  expectedCanonicalJson: string;
  expectedSha256: string;
}

interface DigestManifest {
  fixtures: DigestFixture[];
}

function loadManifest(): DigestManifest {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require(FIXTURE_DIR + "/digests.json");
}

function loadFixtureRawText(filename: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs");
  return fs.readFileSync(FIXTURE_DIR + "/" + filename, "utf8");
}

function loadFixture(filename: string): Record<string, unknown> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require(FIXTURE_DIR + "/" + filename) as Record<string, unknown>;
}

// Extract int64 field values as raw strings from the fixture text, before
// JSON.parse can lose precision on values beyond JavaScript's safe integer
// range. This preserves full signed int64 range for cross-language parity.
function extractInt64Field(rawText: string, field: string): string {
  const needle = `"${field}":`;
  const index = rawText.indexOf(needle);
  if (index === -1) {
    throw new Error(`field ${field} not found in fixture text`);
  }
  const start = index + needle.length;
  let end = start;
  while (end < rawText.length) {
    const ch = rawText[end]!;
    if (ch >= "0" && ch <= "9") {
      end++;
    } else {
      break;
    }
  }
  return rawText.slice(start, end);
}

function bigintField(obj: Record<string, unknown>, field: string): bigint {
  const value = obj[field];
  if (typeof value === "string") {
    return BigInt(value);
  }
  if (typeof value === "number") {
    return BigInt(value);
  }
  throw new Error(`field ${field}: expected number or string, got ${typeof value}`);
}

// optionalBigintField handles nullable int64 from raw fixture text, converting
// exact integer tokens to BigInt. Returns null for null values.
function optionalBigintField(
  rawText: string,
  field: string,
): bigint | null {
  const needle = `"${field}":`;
  const index = rawText.indexOf(needle);
  if (index === -1) return null;
  const start = index + needle.length;
  const rest = rawText.slice(start);
  if (rest.startsWith("null")) return null;
  const numStr = extractInt64Field(rawText, field);
  return BigInt(numStr);
}

function fixtureToResult(
  obj: Record<string, unknown>,
  rawText: string,
): CanonicalResultV2 {
  return {
    format: obj.format as string,
    executionId: obj.executionId as string,
    attemptId: obj.attemptId as string,
    dispatchId: obj.dispatchId as string,
    runnerId: obj.runnerId as string,
    keyId: obj.keyId as string,
    requestSha256: obj.requestSha256 as string,
    policyRevision: obj.policyRevision as string,
    runtimeImageDigest: obj.runtimeImageDigest as string,
    infrastructureStatus: obj.infrastructureStatus as string,
    infrastructureErrorCode:
      (obj.infrastructureErrorCode as string | null) ?? null,
    compilationStatus: obj.compilationStatus as string,
    verdict: obj.verdict as string,
    cleanupStatus: obj.cleanupStatus as string,
    testsTotal: BigInt(extractInt64Field(rawText, "testsTotal")),
    testsPassed: BigInt(extractInt64Field(rawText, "testsPassed")),
    elapsedMs: BigInt(extractInt64Field(rawText, "elapsedMs")),
    peakMemoryBytes: optionalBigintField(rawText, "peakMemoryBytes"),
    runnerVersion: obj.runnerVersion as string,
    startedAt: obj.startedAt as string,
    completedAt: obj.completedAt as string,
  };
}

const manifest: DigestManifest = loadManifest();

const FIXTURE_FILES = ["base.json", "populated.json", "no-fraction.json"];

for (const fixtureFile of FIXTURE_FILES) {
  const fixture = manifest.fixtures.find((f) => f.filename === fixtureFile);
  if (!fixture) {
    throw new Error(`manifest missing entry for ${fixtureFile}`);
  }
  const parsed = loadFixture(fixtureFile);
  const rawText = loadFixtureRawText(fixtureFile);

  describe(`Result V2 TypeScript canonicalization — ${fixtureFile}`, () => {
    it("produces byte-for-byte identical canonical JSON", () => {
      const result = fixtureToResult(parsed, rawText);
      const json = canonicalResultV2Json(result);
      expect(json).toBe(fixture.expectedCanonicalJson);
    });

    it("produces deterministic canonical JSON across repeated calls", () => {
      const result = fixtureToResult(parsed, rawText);
      const first = canonicalResultV2Json(result);
      for (let i = 0; i < 5; i++) {
        expect(canonicalResultV2Json(result)).toBe(first);
      }
    });

    it("produces byte-for-byte identical canonical bytes", () => {
      const result = fixtureToResult(parsed, rawText);
      const bytes = canonicalResultV2Bytes(result);
      const text = new TextDecoder().decode(bytes);
      expect(text).toBe(fixture.expectedCanonicalJson);
    });

    it("produces the expected SHA-256 digest", async () => {
      const result = fixtureToResult(parsed, rawText);
      const digest = await canonicalResultV2Digest(result);
      expect(digest).toBe(fixture.expectedSha256);
      expect(digest.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(digest)).toBe(true);
    });

    it("produces deterministic SHA-256 digest across repeated calls", async () => {
      const result = fixtureToResult(parsed, rawText);
      const first = await canonicalResultV2Digest(result);
      for (let i = 0; i < 5; i++) {
        expect(await canonicalResultV2Digest(result)).toBe(first);
      }
    });

    it("produces a different digest when canonical JSON changes by one byte", async () => {
      const result = fixtureToResult(parsed, rawText);
      const originalDigest = await canonicalResultV2Digest(result);
      const modified = {
        ...result,
        runnerVersion: result.runnerVersion + "x",
      };
      const modifiedDigest = await canonicalResultV2Digest(modified);
      expect(modifiedDigest).not.toBe(originalDigest);
    });
  });
}

describe("Result V2 BigInt and int64 boundary tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("serializes zero as exact JSON number 0", () => {
    const result = { ...baseResult, testsTotal: 0n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"testsTotal":0');
  });

  it("serializes positive one as exact JSON number 1", () => {
    const result = { ...baseResult, testsPassed: 1n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"testsPassed":1');
  });

  it("serializes negative one as exact JSON number -1", () => {
    const result = { ...baseResult, elapsedMs: -1n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"elapsedMs":-1');
  });

  it("serializes 9007199254740993n (beyond JS safe integer) exactly", () => {
    const result = { ...baseResult, testsTotal: 9007199254740993n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"testsTotal":9007199254740993');
  });

  it("serializes int64 max exactly", () => {
    const result = { ...baseResult, testsTotal: 9223372036854775807n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"testsTotal":9223372036854775807');
  });

  it("serializes int64 min exactly", () => {
    const result = { ...baseResult, testsTotal: -9223372036854775808n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"testsTotal":-9223372036854775808');
  });

  it("rejects int64 max plus one", () => {
    const result = { ...baseResult, testsTotal: 9223372036854775808n };
    expect(() => validateResultV2(result)).toThrow();
    expect(() => canonicalResultV2Json(result)).toThrow();
  });

  it("rejects int64 min minus one", () => {
    const result = { ...baseResult, testsTotal: -9223372036854775809n };
    expect(() => validateResultV2(result)).toThrow();
    expect(() => canonicalResultV2Json(result)).toThrow();
  });

  it("rejects JavaScript number where bigint is expected", () => {
    const result = { ...baseResult, testsTotal: 3 as unknown as bigint };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("does not produce exponent notation for large values", () => {
    const result = { ...baseResult, testsTotal: 9007199254740993n };
    const json = canonicalResultV2Json(result);
    expect(json).not.toMatch(/e\+\d+/);
    expect(json).toContain('"testsTotal":9007199254740993');
  });
});

describe("Result V2 nullability tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("emits null for infrastructureErrorCode", () => {
    const json = canonicalResultV2Json(baseResult);
    expect(json).toContain('"infrastructureErrorCode":null');
  });

  it("emits null for peakMemoryBytes", () => {
    const json = canonicalResultV2Json(baseResult);
    expect(json).toContain('"peakMemoryBytes":null');
  });

  it("emits value when infrastructureErrorCode is populated", () => {
    const result = { ...baseResult, infrastructureErrorCode: "E_INFRA_TIMEOUT" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"infrastructureErrorCode":"E_INFRA_TIMEOUT"');
  });

  it("emits value when peakMemoryBytes is populated", () => {
    const result = { ...baseResult, peakMemoryBytes: 134217728n };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"peakMemoryBytes":134217728');
  });
});

describe("Result V2 field-order tests", () => {
  const expectedOrder = [
    "format",
    "executionId",
    "attemptId",
    "dispatchId",
    "runnerId",
    "keyId",
    "requestSha256",
    "policyRevision",
    "runtimeImageDigest",
    "infrastructureStatus",
    "infrastructureErrorCode",
    "compilationStatus",
    "verdict",
    "cleanupStatus",
    "testsTotal",
    "testsPassed",
    "elapsedMs",
    "peakMemoryBytes",
    "runnerVersion",
    "startedAt",
    "completedAt",
  ];

  it("emits fields in exact Go struct declaration order", () => {
    const result: CanonicalResultV2 = {
      format: "SKYHIGH-RUNNER-RESULT-V2",
      executionId: "exec_123",
      attemptId: "attempt_123",
      dispatchId: "dispatch_123",
      runnerId: "runner_01",
      keyId: "key_2026_01",
      requestSha256: "a".repeat(64),
      policyRevision: "policy_rev_7",
      runtimeImageDigest: "sha256:" + "a".repeat(64),
      infrastructureStatus: "OK",
      infrastructureErrorCode: null,
      compilationStatus: "SUCCEEDED",
      verdict: "ACCEPTED",
      cleanupStatus: "CLEANED",
      testsTotal: 3n,
      testsPassed: 3n,
      elapsedMs: 1234n,
      peakMemoryBytes: null,
      runnerVersion: "0.1.0",
      startedAt: "2026-11-26T13:40:10.123Z",
      completedAt: "2026-11-26T13:40:11.987Z",
    };
    const json = canonicalResultV2Json(result);

    let previous = -1;
    for (const field of expectedOrder) {
      const needle = `"${field}":`;
      const index = json.indexOf(needle);
      expect(index).toBeGreaterThanOrEqual(0);
      expect(json.indexOf(needle, index + 1)).toBe(-1);
      expect(index).toBeGreaterThan(previous);
      previous = index;
    }

    expect(json.startsWith('{"format":')).toBe(true);
    expect(json.endsWith("}")).toBe(true);
  });
});

describe("Result V2 timestamp tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("normalizes no-fraction timestamp to .000Z", () => {
    const result = { ...baseResult, startedAt: "2026-11-26T13:40:10Z", completedAt: "2026-11-26T13:40:11Z" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.000Z"');
    expect(json).toContain('"completedAt":"2026-11-26T13:40:11.000Z"');
  });

  it("preserves three fractional digits", () => {
    const result = { ...baseResult };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.123Z"');
    expect(json).toContain('"completedAt":"2026-11-26T13:40:11.987Z"');
  });

  it("truncates six fractional digits", () => {
    const result = {
      ...baseResult,
      startedAt: "2026-11-26T13:40:10.123456Z",
      completedAt: "2026-11-26T13:40:11.987654Z",
    };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.123Z"');
    expect(json).toContain('"completedAt":"2026-11-26T13:40:11.987Z"');
  });

  it("truncates nine fractional digits", () => {
    const result = {
      ...baseResult,
      startedAt: "2026-11-26T13:40:10.123999999Z",
      completedAt: "2026-11-26T13:40:11.987999999Z",
    };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.123Z"');
    expect(json).toContain('"completedAt":"2026-11-26T13:40:11.987Z"');
  });

  it("normalizes offset +02:00 to UTC", () => {
    const result = {
      ...baseResult,
      startedAt: "2026-11-26T15:40:10.123456789+02:00",
      completedAt: "2026-11-26T15:40:11.987654321+02:00",
    };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.123Z"');
    expect(json).toContain('"completedAt":"2026-11-26T13:40:11.987Z"');
  });

  it("normalizes offset -05:30 to UTC with day boundary", () => {
    const result = {
      ...baseResult,
      startedAt: "2026-11-26T05:30:30.987654321-05:30",
      completedAt: "2026-11-26T05:30:31.123456789-05:30",
    };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T11:00:30.987Z"');
    expect(json).toContain('"completedAt":"2026-11-26T11:00:31.123Z"');
  });

  it("truncates rather than rounds", () => {
    const result = {
      ...baseResult,
      startedAt: "2026-11-26T13:40:10.123999Z",
    };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"startedAt":"2026-11-26T13:40:10.123Z"');
    expect(json).not.toContain('"startedAt":"2026-11-26T13:40:10.124Z"');
  });

  it("rejects invalid calendar date", () => {
    const result = { ...baseResult, startedAt: "2026-13-26T13:40:10Z" };
    expect(() => validateResultV2(result)).toThrow();
    expect(() => canonicalResultV2Json(result)).toThrow();
  });

  it("rejects invalid clock values", () => {
    const result = { ...baseResult, startedAt: "2026-11-26T25:40:10Z" };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects missing timezone", () => {
    const result = { ...baseResult, startedAt: "2026-11-26T13:40:10" };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects malformed RFC3339 text", () => {
    const result = { ...baseResult, completedAt: "not-a-timestamp" };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects empty timestamp", () => {
    const result = { ...baseResult, startedAt: "" };
    expect(() => validateResultV2(result)).toThrow();
  });
});

describe("Result V2 string escaping tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("escapes double quotes", () => {
    const result = { ...baseResult, runnerVersion: 'say "hello"' };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"say \\"hello\\""');
  });

  it("escapes backslashes", () => {
    const result = { ...baseResult, runnerVersion: "path\\to\\runner" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"path\\\\to\\\\runner"');
  });

  it("escapes control characters", () => {
    const result = { ...baseResult, runnerVersion: "line1\nline2" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"line1\\nline2"');
  });

  it("escapes < > &", () => {
    const result = { ...baseResult, runnerVersion: "a<b&c>d" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"a\\u003cb\\u0026c\\u003ed"');
  });

  it("escapes U+2028 and U+2029", () => {
    const result = { ...baseResult, runnerVersion: "a b c" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"a\\u2028b\\u2029c"');
  });

  it("preserves ordinary Unicode", () => {
    const result = { ...baseResult, runnerVersion: "café" };
    const json = canonicalResultV2Json(result);
    expect(json).toContain('"runnerVersion":"café"');
  });

  it("rejects unpaired high surrogate", () => {
    const result = { ...baseResult, runnerVersion: "a\uD800b" };
    expect(() => canonicalResultV2Json(result)).toThrow();
  });

  it("rejects unpaired low surrogate", () => {
    const result = { ...baseResult, runnerVersion: "a\uDC00b" };
    expect(() => canonicalResultV2Json(result)).toThrow();
  });
});

describe("Result V2 digest tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("produces lowercase hexadecimal output", async () => {
    const digest = await canonicalResultV2Digest(baseResult);
    expect(/^[0-9a-f]{64}$/.test(digest)).toBe(true);
  });

  it("produces exactly 64 hex characters", async () => {
    const digest = await canonicalResultV2Digest(baseResult);
    expect(digest.length).toBe(64);
  });

  it("produces same digest for repeated calls", async () => {
    const first = await canonicalResultV2Digest(baseResult);
    for (let i = 0; i < 5; i++) {
      expect(await canonicalResultV2Digest(baseResult)).toBe(first);
    }
  });
});

describe("Result V2 invalid input tests", () => {
  const baseResult: CanonicalResultV2 = {
    format: "SKYHIGH-RUNNER-RESULT-V2",
    executionId: "exec_123",
    attemptId: "attempt_123",
    dispatchId: "dispatch_123",
    runnerId: "runner_01",
    keyId: "key_2026_01",
    requestSha256: "a".repeat(64),
    policyRevision: "policy_rev_7",
    runtimeImageDigest: "sha256:" + "a".repeat(64),
    infrastructureStatus: "OK",
    infrastructureErrorCode: null,
    compilationStatus: "SUCCEEDED",
    verdict: "ACCEPTED",
    cleanupStatus: "CLEANED",
    testsTotal: 3n,
    testsPassed: 3n,
    elapsedMs: 1234n,
    peakMemoryBytes: null,
    runnerVersion: "0.1.0",
    startedAt: "2026-11-26T13:40:10.123Z",
    completedAt: "2026-11-26T13:40:11.987Z",
  };

  it("rejects incorrect format", () => {
    const result = { ...baseResult, format: "SKYHIGH-RUNNER-RESULT-V1" };
    expect(() => validateResultV2(result)).toThrow();
    expect(() => canonicalResultV2Json(result)).toThrow();
  });

  it("rejects empty required strings", () => {
    const result = { ...baseResult, executionId: "" };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects invalid timestamps", () => {
    const result = { ...baseResult, startedAt: "not-a-timestamp" };
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects missing required properties", () => {
    const result = { ...baseResult };
    delete (result as Record<string, unknown>).keyId;
    expect(() => validateResultV2(result)).toThrow();
  });

  it("rejects invalid Unicode (unpaired surrogate)", () => {
    const result = {
      ...baseResult,
      runnerVersion: "a" + String.fromCharCode(0xD800) + "b",
    };
    expect(() => canonicalResultV2Json(result)).toThrow();
  });
});
