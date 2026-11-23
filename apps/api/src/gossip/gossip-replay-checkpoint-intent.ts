import canonicalize from "canonicalize";

const DIGEST = /^[0-9a-f]{64}$/;
const MAX_SNAPSHOT_BYTES = 512 * 1024;

export interface ReplayCheckpointScope {
  readonly trustDomainId: string;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
}

export interface ReplayCheckpointPredecessor {
  readonly generation: number;
  readonly digest: string;
}

/**
 * Durable, restart-safe description of one proposed replay-state transition.
 * Store this record before making the gateway RPC. Retries must use the exact
 * canonicalCheckpointBody string and operationId from this record.
 */
export interface ReplayCheckpointIntent {
  readonly version: 1;
  readonly baseStateVersion: number;
  readonly scope: ReplayCheckpointScope;
  readonly expectedPredecessor: ReplayCheckpointPredecessor;
  readonly operationId: string;
  readonly snapshotDigest: string;
  readonly canonicalSnapshotBase64Url: string;
  readonly canonicalCheckpointBody: string;
}

export interface CreateReplayCheckpointIntentInput {
  readonly baseStateVersion: number;
  /** Existing four-part relationship scope: domain|witness|authority|host. */
  readonly scope: string;
  readonly expectedPredecessor: ReplayCheckpointPredecessor;
  readonly nextState: Record<string, unknown>;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function parseScope(value: string): ReplayCheckpointScope {
  const parts = value.split("|");
  if (parts.length !== 4 || parts.some((part) => part.length === 0 || part.trim() !== part)) {
    throw new TypeError("replay checkpoint scope must contain four non-empty canonical parts");
  }
  return {
    trustDomainId: parts[0]!,
    witnessId: parts[1]!,
    authorityId: parts[2]!,
    hostId: parts[3]!,
  };
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\\+/g, "-").replace(/\\//g, "_");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalJson(value: unknown): string {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("value is not canonical JSON");
  return serialized;
}

/** Build one deterministic checkpoint intent without performing I/O. */
export async function createReplayCheckpointIntent(
  input: CreateReplayCheckpointIntentInput,
): Promise<ReplayCheckpointIntent> {
  if (!Number.isSafeInteger(input.baseStateVersion) || input.baseStateVersion < 0) {
    throw new TypeError("base replay-state version is invalid");
  }
  if (
    !Number.isSafeInteger(input.expectedPredecessor?.generation) ||
    input.expectedPredecessor.generation < 0 ||
    !DIGEST.test(input.expectedPredecessor.digest)
  ) {
    throw new TypeError("witness predecessor is invalid");
  }
  if (!isPlainRecord(input.nextState)) {
    throw new TypeError("next replay state must be a plain JSON object");
  }

  const scope = parseScope(input.scope);
  const canonicalSnapshot = canonicalJson(input.nextState);
  const snapshotBytes = new TextEncoder().encode(canonicalSnapshot);
  if (snapshotBytes.length === 0 || snapshotBytes.length > MAX_SNAPSHOT_BYTES) {
    throw new RangeError("canonical replay snapshot exceeds the 512 KiB limit");
  }

  const snapshotDigest = await sha256Hex(snapshotBytes);
  const operationId = `fence-monitor-replay-${snapshotDigest}`;
  const canonicalSnapshotBase64Url = encodeBase64Url(snapshotBytes);
  const body = {
    version: 1,
    scope,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    expectedPredecessor: input.expectedPredecessor,
    snapshotDigest,
    canonicalSnapshotBase64Url,
  };

  return {
    version: 1,
    baseStateVersion: input.baseStateVersion,
    scope,
    expectedPredecessor: input.expectedPredecessor,
    operationId,
    snapshotDigest,
    canonicalSnapshotBase64Url,
    canonicalCheckpointBody: canonicalJson(body),
  };
}

/** Validate the persisted intent before any retry or gateway call. */
export async function validateReplayCheckpointIntent(
  intent: ReplayCheckpointIntent,
): Promise<boolean> {
  if (
    !isPlainRecord(intent) ||
    intent.version !== 1 ||
    !Number.isSafeInteger(intent.baseStateVersion) ||
    intent.baseStateVersion < 0 ||
    !isPlainRecord(intent.scope) ||
    !isPlainRecord(intent.expectedPredecessor) ||
    !DIGEST.test(intent.snapshotDigest) ||
    intent.operationId !== `fence-monitor-replay-${intent.snapshotDigest}` ||
    typeof intent.canonicalSnapshotBase64Url !== "string" ||
    !/^[A-Za-z0-9_-]+$/.test(intent.canonicalSnapshotBase64Url) ||
    typeof intent.canonicalCheckpointBody !== "string"
  ) return false;

  try {
    const expectedScope = parseScope([
      intent.scope.trustDomainId,
      intent.scope.witnessId,
      intent.scope.authorityId,
      intent.scope.hostId,
    ].join("|"));
    const expectedPredecessor = intent.expectedPredecessor as unknown as ReplayCheckpointPredecessor;
    if (
      !Number.isSafeInteger(expectedPredecessor.generation) ||
      expectedPredecessor.generation < 0 ||
      !DIGEST.test(expectedPredecessor.digest)
    ) return false;

    const encoded = intent.canonicalSnapshotBase64Url;
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (encoded.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (encodeBase64Url(bytes) !== encoded || bytes.length > MAX_SNAPSHOT_BYTES) return false;
    const snapshotText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const snapshot = JSON.parse(snapshotText) as unknown;
    if (!isPlainRecord(snapshot) || canonicalJson(snapshot) !== snapshotText) return false;
    if (await sha256Hex(bytes) !== intent.snapshotDigest) return false;

    const expectedBody = canonicalJson({
      version: 1,
      scope: expectedScope,
      operationId: intent.operationId,
      phase: "MONITOR_GOSSIP_REPLAY_V1",
      expectedPredecessor,
      snapshotDigest: intent.snapshotDigest,
      canonicalSnapshotBase64Url: encoded,
    });
    return expectedBody === intent.canonicalCheckpointBody;
  } catch {
    return false;
  }
}
