export interface CanonicalTestBundleCase {
  readonly testCaseId: string;
  readonly sequence: number;
  readonly visibility: "PUBLIC" | "HIDDEN";
  readonly input: string;
  readonly expectedOutput: string;
}

export class TestBundleEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TestBundleEncodingError";
  }
}

function appendLengthPrefixed(target: number[], value: Uint8Array): void {
  const length = value.byteLength;
  if (!Number.isSafeInteger(length) || length < 0 || length > 0xffffffff) {
    throw new TestBundleEncodingError("runner_artifact_bundle_field_too_large");
  }
  target.push(
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  );
  for (const byte of value) target.push(byte);
}

/**
 * Cross-language canonical format:
 * length-prefixed magic "SKYHIGH-TEST-BUNDLE-V1" (no NUL terminator),\n * u32 case count, then per case:
 * length-prefixed UTF-8 testCaseId, u32 sequence, one visibility byte
 * (1=PUBLIC, 2=HIDDEN), length-prefixed UTF-8 input and expected output.
 * All integers are unsigned big-endian.
 */
export function canonicalTestBundleBytes(
  testCases: readonly CanonicalTestBundleCase[],
): Uint8Array {
  if (testCases.length > 0xffffffff) {
    throw new TestBundleEncodingError("runner_artifact_test_case_count_invalid");
  }
  const target: number[] = [];
  appendLengthPrefixed(target, new TextEncoder().encode("SKYHIGH-TEST-BUNDLE-V1"));
  target.push(
    (testCases.length >>> 24) & 0xff,
    (testCases.length >>> 16) & 0xff,
    (testCases.length >>> 8) & 0xff,
    testCases.length & 0xff,
  );
  for (const testCase of testCases) {
    appendLengthPrefixed(target, new TextEncoder().encode(testCase.testCaseId));
    const sequence = testCase.sequence;
    if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > 0xffffffff) {
      throw new TestBundleEncodingError("runner_artifact_test_sequence_invalid");
    }
    target.push(
      (sequence >>> 24) & 0xff,
      (sequence >>> 16) & 0xff,
      (sequence >>> 8) & 0xff,
      sequence & 0xff,
    );
    target.push(testCase.visibility === "PUBLIC" ? 1 : 2);
    appendLengthPrefixed(target, new TextEncoder().encode(testCase.input));
    appendLengthPrefixed(target, new TextEncoder().encode(testCase.expectedOutput));
  }
  return Uint8Array.from(target);
}


export interface CanonicalTestBundleIdentity {
  readonly testBundleId: string;
  readonly testBundleSha256: string;
}

export async function canonicalTestBundleIdentity(
  problemVersionId: string,
  action: "RUN" | "SUBMIT",
  testCases: readonly CanonicalTestBundleCase[],
): Promise<CanonicalTestBundleIdentity> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(problemVersionId)) {
    throw new TestBundleEncodingError("runner_artifact_problem_version_id_invalid");
  }
  const bytes = canonicalTestBundleBytes(testCases);
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
  const testBundleSha256 = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return {
    testBundleId: `${problemVersionId}-${action.toLowerCase()}-${testBundleSha256.slice(0, 16)}`,
    testBundleSha256,
  };
}
