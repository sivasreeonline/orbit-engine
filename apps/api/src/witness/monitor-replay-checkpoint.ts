import canonicalize from "canonicalize";
import type { GossipReplaySnapshot } from "../gossip/gossip-replay-state-do";
import type { WitnessCheckpointBody } from "./witness-profile-verifier";

const PROFILE = "sky-high-fence-witness-v1";
const REPLAY_PHASE = "MONITOR_GOSSIP_REPLAY_V1";
const ZERO_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

export interface MonitorReplayTrustScope {
  readonly trustDomainId: string;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
  readonly senderId: string;
  readonly recipientId: string;
  readonly replayScope: string;
}

export interface MonitorReplayProviderCheckpoint {
  readonly scope: {
    readonly trustDomainId: string;
    readonly witnessId: string;
    readonly authorityId: string;
    readonly hostId: string;
    readonly senderId: string;
    readonly recipientId: string;
    readonly replayScope: string;
  };
  readonly generation: number;
  readonly operationId: string;
  readonly phase: typeof REPLAY_PHASE;
  /** Digest of the cryptographic checkpoint artifact body. */
  readonly checkpointDigest: string;
  readonly previousDigest: string;
  /** Digest of the complete canonical Durable Object replay snapshot. */
  readonly snapshotDigest: string;
}

export interface MonitorReplayCheckpointArtifact {
  readonly canonicalSnapshotBytes: Uint8Array;
  readonly snapshotDigest: string;
  readonly operationId: string;
  readonly checkpointBody: WitnessCheckpointBody;
  readonly checkpointDigest: string;
  readonly providerCheckpoint: MonitorReplayProviderCheckpoint;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validNonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}

function canonicalBytes(value: unknown): Uint8Array {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("value is not RFC 8785 canonicalizable JSON");
  return encoder.encode(serialized);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validateSnapshot(
  snapshot: GossipReplaySnapshot,
  scope: MonitorReplayTrustScope,
): void {
  if (
    !isRecord(snapshot) ||
    !hasExactKeys(snapshot, [
      "version",
      "senderId",
      "recipientId",
      "scope",
      "highestSequence",
      "seenBySequence",
      "seenByMessageId",
      "outstandingRequests",
      "consumedNonces",
      "missingSequences",
    ])
  ) throw new TypeError("monitor replay snapshot has an unexpected shape");

  if (
    snapshot.version !== 1 ||
    snapshot.senderId !== scope.senderId ||
    snapshot.recipientId !== scope.recipientId ||
    snapshot.scope !== scope.replayScope ||
    snapshot.senderId === snapshot.recipientId ||
    !validNonEmpty(snapshot.senderId) ||
    !validNonEmpty(snapshot.recipientId) ||
    !validNonEmpty(snapshot.scope) ||
    !Number.isSafeInteger(snapshot.highestSequence) ||
    snapshot.highestSequence < 0 ||
    !isRecord(snapshot.seenBySequence) ||
    !isRecord(snapshot.seenByMessageId) ||
    !isRecord(snapshot.outstandingRequests) ||
    !Array.isArray(snapshot.consumedNonces) ||
    !snapshot.consumedNonces.every(validNonEmpty) ||
    new Set(snapshot.consumedNonces).size !== snapshot.consumedNonces.length ||
    !Array.isArray(snapshot.missingSequences) ||
    !snapshot.missingSequences.every((value: unknown) =>
      Number.isSafeInteger(value) && (value as number) >= 1
    ) ||
    new Set(snapshot.missingSequences).size !== snapshot.missingSequences.length
  ) throw new TypeError("monitor replay snapshot fields or relationship binding are invalid");

  for (const [sequence, entry] of Object.entries(snapshot.seenBySequence)) {
    if (
      !/^[1-9][0-9]*$/.test(sequence) ||
      Number(sequence) > snapshot.highestSequence ||
      !isRecord(entry) ||
      !hasExactKeys(entry, ["messageId", "digest"]) ||
      !validNonEmpty(entry.messageId) ||
      typeof entry.digest !== "string" ||
      !DIGEST.test(entry.digest)
    ) throw new TypeError("seenBySequence entry is malformed");
  }
  for (const [messageId, entry] of Object.entries(snapshot.seenByMessageId)) {
    if (
      !validNonEmpty(messageId) ||
      !isRecord(entry) ||
      !hasExactKeys(entry, ["sequence", "digest"]) ||
      !Number.isSafeInteger(entry.sequence) ||
      (entry.sequence as number) < 1 ||
      typeof entry.digest !== "string" ||
      !DIGEST.test(entry.digest)
    ) throw new TypeError("seenByMessageId entry is malformed");
  }
  for (const [requestId, request] of Object.entries(snapshot.outstandingRequests)) {
    if (
      !validNonEmpty(requestId) ||
      !isRecord(request) ||
      !hasExactKeys(request, ["nonce", "expiresAt"]) ||
      !validNonEmpty(request.nonce) ||
      !Number.isSafeInteger(request.expiresAt) ||
      (request.expiresAt as number) < 0
    ) throw new TypeError("outstanding request entry is malformed");
    if (!snapshot.seenByMessageId[requestId]) {
      throw new TypeError("outstanding request is not bound to a seen replay message");
    }
    if (snapshot.consumedNonces.includes(request.nonce)) {
      throw new TypeError("outstanding request nonce is already consumed");
    }
  }

  for (const [sequence, entry] of Object.entries(snapshot.seenBySequence)) {
    const reverse = snapshot.seenByMessageId[entry.messageId];
    if (
      !reverse ||
      reverse.sequence !== Number(sequence) ||
      reverse.digest !== entry.digest
    ) throw new TypeError("replay sequence and message indexes disagree");
    if (Number(sequence) > snapshot.highestSequence) {
      throw new TypeError("seen sequence exceeds the replay high-water");
    }
  }
  for (const [messageId, entry] of Object.entries(snapshot.seenByMessageId)) {
    const forward = snapshot.seenBySequence[String(entry.sequence)];
    if (
      !forward ||
      forward.messageId !== messageId ||
      forward.digest !== entry.digest
    ) throw new TypeError("replay message and sequence indexes disagree");
  }
  for (const missing of snapshot.missingSequences) {
    if (
      missing > snapshot.highestSequence ||
      Object.hasOwn(snapshot.seenBySequence, String(missing))
    ) throw new TypeError("missing sequence conflicts with replay high-water or seen messages");
  }
}

export function canonicalReplaySnapshotBytes(
  snapshot: GossipReplaySnapshot,
  scope: MonitorReplayTrustScope,
): Uint8Array {
  validateSnapshot(snapshot, scope);
  const normalized = {
    version: snapshot.version,
    senderId: snapshot.senderId,
    recipientId: snapshot.recipientId,
    scope: snapshot.scope,
    highestSequence: snapshot.highestSequence,
    seenBySequence: snapshot.seenBySequence,
    seenByMessageId: snapshot.seenByMessageId,
    outstandingRequests: snapshot.outstandingRequests,
    consumedNonces: [...snapshot.consumedNonces].sort(),
    missingSequences: [...snapshot.missingSequences].sort((left, right) => left - right),
  };
  return canonicalBytes(normalized);
}

/**
 * Maps the complete replay snapshot to the existing signed witness checkpoint
 * artifact. The provider checkpoint digest is the artifact-body digest; the
 * full replay snapshot digest is separately bound by authorityStateDigest.
 */
export async function buildMonitorReplayCheckpointArtifact(
  snapshot: GossipReplaySnapshot,
  scope: MonitorReplayTrustScope,
  generation: number,
  previousCheckpointDigest: string,
): Promise<MonitorReplayCheckpointArtifact> {
  if (
    !Number.isSafeInteger(generation) ||
    generation < 1 ||
    !DIGEST.test(previousCheckpointDigest) ||
    !validNonEmpty(scope.trustDomainId) ||
    !validNonEmpty(scope.witnessId) ||
    !validNonEmpty(scope.authorityId) ||
    !validNonEmpty(scope.hostId)
  ) throw new TypeError("monitor replay checkpoint generation or trust scope is invalid");

  const canonicalSnapshotBytes = canonicalReplaySnapshotBytes(snapshot, scope);
  const snapshotDigest = await digestHex(canonicalSnapshotBytes);
  const operationId = `fence-monitor-replay-${snapshotDigest}`;
  const operationDescriptor = {
    phase: REPLAY_PHASE,
    operationId,
    generation,
    previousCheckpointDigest,
    snapshotDigest,
    senderId: snapshot.senderId,
    recipientId: snapshot.recipientId,
    replayScope: snapshot.scope,
  };
  const responseDigest = await digestHex(canonicalBytes(operationDescriptor));
  const checkpointBody: WitnessCheckpointBody = {
    profile: PROFILE,
    schemaVersion: 1,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    generation,
    phase: "ACCEPTED",
    operationId,
    previousCheckpointDigest,
    authorityStateDigest: snapshotDigest,
    responseDigest,
    epoch: snapshot.highestSequence,
    recordVersion: snapshot.version,
  };
  const checkpointDigest = await digestHex(canonicalBytes(checkpointBody));
  const providerCheckpoint: MonitorReplayProviderCheckpoint = {
    scope: {
      trustDomainId: scope.trustDomainId,
      witnessId: scope.witnessId,
      authorityId: scope.authorityId,
      hostId: scope.hostId,
      senderId: scope.senderId,
      recipientId: scope.recipientId,
      replayScope: scope.replayScope,
    },
    generation,
    operationId,
    phase: REPLAY_PHASE,
    checkpointDigest,
    previousDigest: previousCheckpointDigest,
    snapshotDigest,
  };
  return {
    canonicalSnapshotBytes,
    snapshotDigest,
    operationId,
    checkpointBody,
    checkpointDigest,
    providerCheckpoint,
  };
}

export const MONITOR_REPLAY_ZERO_DIGEST = ZERO_DIGEST;
