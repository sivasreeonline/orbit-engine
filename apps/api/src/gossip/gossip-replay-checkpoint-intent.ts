import canonicalize from "canonicalize";

const DIGEST = /^[0-9a-f]{64}$/;
const MAX_SNAPSHOT_BYTES = 512 * 1024;
const MAX_IDENTIFIER_LENGTH = 256;

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

/** Durable, restart-safe description of one proposed replay-state transition. */
export interface ReplayCheckpointIntent {
  readonly version: 1;
  readonly baseStateVersion: number;
  readonly scope: ReplayCheckpointScope;
  readonly senderId: string;
  readonly recipientId: string;
  readonly messageDigest: string;
  readonly expectedPredecessor: ReplayCheckpointPredecessor;
  readonly operationId: string;
  readonly snapshotDigest: string;
  readonly snapshotByteLength: number;
  readonly canonicalSnapshotBase64Url: string;
  readonly canonicalCheckpointBody: string;
}

export interface CreateReplayCheckpointIntentInput {
  readonly baseStateVersion: number;
  /** Existing four-part relationship scope: domain|witness|authority|host. */
  readonly scope: string;
  readonly senderId: string;
  readonly recipientId: string;
  /** Digest of the exact already-verified gossip message that caused this transition. */
  readonly messageDigest: string;
  readonly expectedPredecessor: ReplayCheckpointPredecessor;
  readonly nextState: Record<string, unknown>;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_IDENTIFIER_LENGTH &&
    value.trim() === value;
}

function parseScope(value: string): ReplayCheckpointScope {
  const parts = value.split("|");
  if (parts.length !== 4 || parts.some((part) =>
    part.length === 0 || part.length > MAX_IDENTIFIER_LENGTH || part.trim() !== part
  )) {
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
  return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalJson(value: unknown): string {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("value is not canonical JSON");
  return serialized;
}

/** Scope and predecessor are part of idempotency identity, not just snapshot bytes. */
export async function deriveReplayCheckpointOperationId(input: {
  readonly scope: ReplayCheckpointScope;
  readonly expectedPredecessor: ReplayCheckpointPredecessor;
  readonly snapshotDigest: string;
}): Promise<string> {
  const identityDigest = await sha256Hex(new TextEncoder().encode(canonicalJson({
    scope: input.scope,
    expectedPredecessor: input.expectedPredecessor,
    snapshotDigest: input.snapshotDigest,
  })));
  return `fence-monitor-replay-${identityDigest}`;
}

/** Build one deterministic, message-bound checkpoint intent without performing I/O. */
export async function createReplayCheckpointIntent(
  input: CreateReplayCheckpointIntentInput,
): Promise<ReplayCheckpointIntent> {
  if (!Number.isSafeInteger(input.baseStateVersion) || input.baseStateVersion < 0) {
    throw new TypeError("base replay-state version is invalid");
  }
  if (
    !validIdentifier(input.senderId) ||
    !validIdentifier(input.recipientId) ||
    input.senderId === input.recipientId ||
    !DIGEST.test(input.messageDigest)
  ) throw new TypeError("replay message identity or digest is invalid");
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
  const operationId = await deriveReplayCheckpointOperationId({
    scope,
    expectedPredecessor: input.expectedPredecessor,
    snapshotDigest,
  });
  const canonicalSnapshotBase64Url = encodeBase64Url(snapshotBytes);
  const body = {
    version: 1,
    scope,
    senderId: input.senderId,
    recipientId: input.recipientId,
    messageDigest: input.messageDigest,
    baseStateVersion: input.baseStateVersion,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    expectedPredecessor: input.expectedPredecessor,
    snapshotDigest,
    snapshotByteLength: snapshotBytes.length,
    canonicalSnapshotBase64Url,
  };

  return {
    version: 1,
    baseStateVersion: input.baseStateVersion,
    scope,
    senderId: input.senderId,
    recipientId: input.recipientId,
    messageDigest: input.messageDigest,
    expectedPredecessor: input.expectedPredecessor,
    operationId,
    snapshotDigest,
    snapshotByteLength: snapshotBytes.length,
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
    !hasExactKeys(intent, [
      "version",
      "baseStateVersion",
      "scope",
      "senderId",
      "recipientId",
      "messageDigest",
      "expectedPredecessor",
      "operationId",
      "snapshotDigest",
      "snapshotByteLength",
      "canonicalSnapshotBase64Url",
      "canonicalCheckpointBody",
    ]) ||
    !hasExactKeys(intent.scope, ["trustDomainId", "witnessId", "authorityId", "hostId"]) ||
    !Object.values(intent.scope).every(validIdentifier) ||
    !validIdentifier(intent.senderId) ||
    !validIdentifier(intent.recipientId) ||
    intent.senderId === intent.recipientId ||
    !DIGEST.test(intent.messageDigest) ||
    !isPlainRecord(intent.expectedPredecessor) ||
    !hasExactKeys(intent.expectedPredecessor, ["generation", "digest"]) ||
    !Number.isSafeInteger(intent.expectedPredecessor.generation) ||
    intent.expectedPredecessor.generation < 0 ||
    !DIGEST.test(intent.expectedPredecessor.digest) ||
    !DIGEST.test(intent.snapshotDigest) ||
    !Number.isSafeInteger(intent.snapshotByteLength) ||
    intent.snapshotByteLength < 1 ||
    intent.snapshotByteLength > MAX_SNAPSHOT_BYTES ||
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

    const encoded = intent.canonicalSnapshotBase64Url;
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (encoded.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (
      encodeBase64Url(bytes) !== encoded ||
      bytes.length !== intent.snapshotByteLength ||
      bytes.length > MAX_SNAPSHOT_BYTES
    ) return false;
    const snapshotText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const snapshot = JSON.parse(snapshotText) as unknown;
    if (!isPlainRecord(snapshot) || canonicalJson(snapshot) !== snapshotText) return false;
    if (await sha256Hex(bytes) !== intent.snapshotDigest) return false;

    if (intent.operationId !== await deriveReplayCheckpointOperationId({
      scope: expectedScope,
      expectedPredecessor,
      snapshotDigest: intent.snapshotDigest,
    })) return false;

    const expectedBody = canonicalJson({
      version: 1,
      scope: expectedScope,
      senderId: intent.senderId,
      recipientId: intent.recipientId,
      messageDigest: intent.messageDigest,
      baseStateVersion: intent.baseStateVersion,
      operationId: intent.operationId,
      phase: "MONITOR_GOSSIP_REPLAY_V1",
      expectedPredecessor,
      snapshotDigest: intent.snapshotDigest,
      snapshotByteLength: intent.snapshotByteLength,
      canonicalSnapshotBase64Url: encoded,
    });
    return expectedBody === intent.canonicalCheckpointBody;
  } catch {
    return false;
  }
}
