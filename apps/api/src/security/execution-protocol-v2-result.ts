// Copyright 2026 Sky High Coding Judge
// Result V2 canonicalization for TypeScript, byte-compatible with the Go
// implementation in services/execution-runner/internal/protocol/result_v2.go.
//
// This module produces canonical JSON and SHA-256 digests that are
// byte-for-byte identical to the Go CanonicalResultV2Digest implementation.
// It uses bigint for all Go int64 fields to preserve the full signed int64
// range, and the Web Crypto API (crypto.subtle) for SHA-256, compatible with
// Cloudflare Workers.

export interface CanonicalResultV2 {
  readonly format: string;
  readonly executionId: string;
  readonly attemptId: string;
  readonly dispatchId: string;
  readonly runnerId: string;
  readonly keyId: string;
  readonly requestSha256: string;
  readonly policyRevision: string;
  readonly runtimeImageDigest: string;
  readonly infrastructureStatus: string;
  readonly infrastructureErrorCode: string | null;
  readonly compilationStatus: string;
  readonly verdict: string;
  readonly cleanupStatus: string;
  readonly testsTotal: bigint;
  readonly testsPassed: bigint;
  readonly elapsedMs: bigint;
  readonly peakMemoryBytes: bigint | null;
  readonly runnerVersion: string;
  readonly startedAt: string;
  readonly completedAt: string;
}

const REQUIRED_FORMAT = "SKYHIGH-RUNNER-RESULT-V2";
const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;

const REQUIRED_STRING_FIELDS: readonly string[] = [
  "format",
  "executionId",
  "attemptId",
  "dispatchId",
  "runnerId",
  "keyId",
  "requestSha256",
  "policyRevision",
  "runtimeImageDigest",
];

const INT64_BIGINT_FIELDS: readonly string[] = [
  "testsTotal",
  "testsPassed",
  "elapsedMs",
  "peakMemoryBytes",
];

// RFC3339: YYYY-MM-DDTHH:MM:SS[.fraction][Z|±HH:MM]
// Fractional seconds may have any number of digits; we truncate to 3.
const RFC3339_REGEX = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/;

const DAYS_IN_MONTH = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function daysInMonth(year: number, month: number): number {
  const days = DAYS_IN_MONTH[month];
  if (days === undefined) throw new Error(`invalid month: ${month}`);
  if (month === 2 && isLeapYear(year)) return 29;
  return days;
}

// Escape a JSON string value, matching Go's encoding/json default behavior:
// escapes ", \, control characters, and HTML-sensitive characters
// (< > & as escaped; U+2028 U+2029 as escaped).
function escapeJsonString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i);
    // Reject unpaired UTF-16 surrogates: they represent invalid Unicode.
    if (ch >= 0xd800 && ch <= 0xdbff) {
      // High surrogate must be followed by a low surrogate.
      if (i + 1 >= value.length) {
        throw new Error("invalid UTF-16: unpaired high surrogate");
      }
      const next = value.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error("invalid UTF-16: high surrogate not followed by low surrogate");
      }
      // Valid surrogate pair: emit both characters escaped.
      const codePoint = 0x10000 + ((ch - 0xd800) << 10) + (next - 0xdc00);
      out += "\\u" + codePoint.toString(16).padStart(4, "0");
      i++; // skip the low surrogate
      continue;
    }
    if (ch >= 0xdc00 && ch <= 0xdfff) {
      throw new Error("invalid UTF-16: unpaired low surrogate");
    }
    switch (ch) {
      case 0x22: // "
        out += '\\"';
        break;
      case 0x5c: // \
        out += '\\\\';
        break;
      case 0x08: // backspace
        out += '\\b';
        break;
      case 0x0c: // form feed
        out += '\\f';
        break;
      case 0x0a: // newline
        out += '\\n';
        break;
      case 0x0d: // carriage return
        out += '\\r';
        break;
      case 0x09: // tab
        out += '\\t';
        break;
      case 0x3c: // <
        out += '\\u003c';
        break;
      case 0x3e: // >
        out += '\\u003e';
        break;
      case 0x26: // &
        out += '\\u0026';
        break;
      default:
        if (ch < 0x20) {
          out += '\\u' + ch.toString(16).padStart(4, '0');
        } else if (ch === 0x2028 || ch === 0x2029) {
          out += '\\u' + ch.toString(16).padStart(4, '0');
        } else {
          out += value[i];
        }
    }
  }
  out += '"';
  return out;
}

function serializeBigInt(value: bigint): string {
  return value.toString(10);
}

function validateBigIntField(name: string, value: bigint | null | undefined): void {
  if (value === null || value === undefined) return;
  if (typeof value !== "bigint") {
    throw new Error(`field ${name}: expected bigint, got ${typeof value}`);
  }
  if (value < INT64_MIN || value > INT64_MAX) {
    throw new Error(`field ${name}: int64 value out of range`);
  }
}

function validateTimestampFormat(ts: string): void {
  // normalizeTimestamp performs full semantic validation; call it here so
  // validateResultV2 catches invalid timestamps without serializing.
  normalizeTimestamp(ts);
}

// Normalize an RFC3339 timestamp to UTC with millisecond precision, truncating
// rather than rounding. Does not use JavaScript Date for fractional-second
// extraction; fractional digits are parsed directly from the string.
function normalizeTimestamp(ts: string): string {
  const match = RFC3339_REGEX.exec(ts);
  if (!match) {
    throw new Error(`invalid timestamp: ${ts}`);
  }

  const year = parseInt(match[1]!, 10);
  const month = parseInt(match[2]!, 10);
  const day = parseInt(match[3]!, 10);
  const hour = parseInt(match[4]!, 10);
  const minute = parseInt(match[5]!, 10);
  const second = parseInt(match[6]!, 10);
  const fraction = match[7] ?? "";
  const tz = match[8] ?? "";

  // Validate ranges
  if (month < 1 || month > 12) throw new Error(`invalid month in timestamp: ${ts}`);
  if (day < 1 || day > daysInMonth(year, month)) throw new Error(`invalid day in timestamp: ${ts}`);
  if (hour > 23) throw new Error(`invalid hour in timestamp: ${ts}`);
  if (minute > 59) throw new Error(`invalid minute in timestamp: ${ts}`);
  if (second > 59) throw new Error(`invalid second in timestamp: ${ts}`);

  // Validate timezone offset range
  if (tz !== "Z") {
    const sign = tz[0] === "+" ? 1 : -1;
    const tzHour = parseInt(tz.slice(1, 3), 10);
    const tzMinute = parseInt(tz.slice(4, 6), 10);
    if (tzHour > 23 || tzMinute > 59) {
      throw new Error(`invalid timezone offset in timestamp: ${ts}`);
    }
  }

  // Truncate fractional seconds to exactly 3 digits
  let msFraction: string;
  if (fraction.length === 0) {
    msFraction = "000";
  } else {
    msFraction = fraction.padEnd(3, "0").slice(0, 3);
  }

  // Compute timezone offset in minutes
  let tzOffsetMinutes = 0;
  if (tz !== "Z") {
    const sign = tz[0] === "+" ? 1 : -1;
    const tzHour = parseInt(tz.slice(1, 3), 10);
    const tzMinute = parseInt(tz.slice(4, 6), 10);
    if (tzHour > 23 || tzMinute > 59) {
      throw new Error(`invalid timezone offset in timestamp: ${ts}`);
    }
    tzOffsetMinutes = sign * (tzHour * 60 + tzMinute);
  }

  // Convert local time to UTC minutes, handling day carry/borrow
  let utcTotalMinutes = hour * 60 + minute - tzOffsetMinutes;
  let dayOffset = 0;
  while (utcTotalMinutes < 0) {
    utcTotalMinutes += 24 * 60;
    dayOffset -= 1;
  }
  while (utcTotalMinutes >= 24 * 60) {
    utcTotalMinutes -= 24 * 60;
    dayOffset += 1;
  }
  const utcHour = Math.floor(utcTotalMinutes / 60);
  const utcMinute = utcTotalMinutes % 60;

  // Use Date.UTC to handle month/year boundary rollover from dayOffset
  const ms = parseInt(msFraction, 10);
  const date = new Date(Date.UTC(year, month - 1, day + dayOffset, utcHour, utcMinute, second, ms));

  const y = String(date.getUTCFullYear()).padStart(4, '0');
  const mo = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  const h = String(date.getUTCHours()).padStart(2, '0');
  const mi = String(date.getUTCMinutes()).padStart(2, '0');
  const s = String(date.getUTCSeconds()).padStart(2, '0');

  return `${y}-${mo}-${d}T${h}:${mi}:${s}.${msFraction}Z`;
}

export function validateResultV2(result: CanonicalResultV2): void {
  if (result.format !== REQUIRED_FORMAT) {
    throw new Error(`invalid format: ${result.format}`);
  }

  const requiredStrings: Record<string, string> = {
    format: result.format,
    executionId: result.executionId,
    attemptId: result.attemptId,
    dispatchId: result.dispatchId,
    runnerId: result.runnerId,
    keyId: result.keyId,
    requestSha256: result.requestSha256,
    policyRevision: result.policyRevision,
    runtimeImageDigest: result.runtimeImageDigest,
  };

  for (const [field, value] of Object.entries(requiredStrings)) {
    if (typeof value !== "string" || value === "") {
      throw new Error(`missing required field: ${field}`);
    }
  }

  validateBigIntField("testsTotal", result.testsTotal);
  validateBigIntField("testsPassed", result.testsPassed);
  validateBigIntField("elapsedMs", result.elapsedMs);
  if (result.peakMemoryBytes !== null) {
    validateBigIntField("peakMemoryBytes", result.peakMemoryBytes);
  }

  validateTimestampFormat(result.startedAt);
  validateTimestampFormat(result.completedAt);
}

export function canonicalResultV2Json(result: CanonicalResultV2): string {
  validateResultV2(result);

  const startedAt = normalizeTimestamp(result.startedAt);
  const completedAt = normalizeTimestamp(result.completedAt);

  const parts: string[] = [];
  parts.push(`"format":${escapeJsonString(result.format)}`);
  parts.push(`"executionId":${escapeJsonString(result.executionId)}`);
  parts.push(`"attemptId":${escapeJsonString(result.attemptId)}`);
  parts.push(`"dispatchId":${escapeJsonString(result.dispatchId)}`);
  parts.push(`"runnerId":${escapeJsonString(result.runnerId)}`);
  parts.push(`"keyId":${escapeJsonString(result.keyId)}`);
  parts.push(`"requestSha256":${escapeJsonString(result.requestSha256)}`);
  parts.push(`"policyRevision":${escapeJsonString(result.policyRevision)}`);
  parts.push(`"runtimeImageDigest":${escapeJsonString(result.runtimeImageDigest)}`);
  parts.push(`"infrastructureStatus":${escapeJsonString(result.infrastructureStatus)}`);
  if (result.infrastructureErrorCode === null) {
    parts.push('"infrastructureErrorCode":null');
  } else {
    parts.push(`"infrastructureErrorCode":${escapeJsonString(result.infrastructureErrorCode)}`);
  }
  parts.push(`"compilationStatus":${escapeJsonString(result.compilationStatus)}`);
  parts.push(`"verdict":${escapeJsonString(result.verdict)}`);
  parts.push(`"cleanupStatus":${escapeJsonString(result.cleanupStatus)}`);
  parts.push(`"testsTotal":${serializeBigInt(result.testsTotal)}`);
  parts.push(`"testsPassed":${serializeBigInt(result.testsPassed)}`);
  parts.push(`"elapsedMs":${serializeBigInt(result.elapsedMs)}`);
  if (result.peakMemoryBytes === null) {
    parts.push('"peakMemoryBytes":null');
  } else {
    parts.push(`"peakMemoryBytes":${serializeBigInt(result.peakMemoryBytes)}`);
  }
  parts.push(`"runnerVersion":${escapeJsonString(result.runnerVersion)}`);
  parts.push(`"startedAt":${escapeJsonString(startedAt)}`);
  parts.push(`"completedAt":${escapeJsonString(completedAt)}`);

  return "{" + parts.join(",") + "}";
}

export function canonicalResultV2Bytes(result: CanonicalResultV2): Uint8Array {
  const json = canonicalResultV2Json(result);
  return new TextEncoder().encode(json);
}

export async function canonicalResultV2Digest(result: CanonicalResultV2): Promise<string> {
  const bytes = canonicalResultV2Bytes(result);
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
