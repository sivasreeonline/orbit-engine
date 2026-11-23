import canonicalize from "canonicalize";
import {
  validateReplayCheckpointIntent,
  type ReplayCheckpointIntent,
} from "./gossip-replay-checkpoint-intent";

const DIGEST = /^[0-9a-f]{64}$/;

import type { VerifiedGossipMessage } from "./gossip-replay-state-do";

export type ReplayTransitionMessage = VerifiedGossipMessage;

export interface PendingReplayIntent {
  readonly version: 1;
  readonly intent: ReplayCheckpointIntent;
  readonly message: ReplayTransitionMessage;
  readonly proposedState: Record<string, unknown>;
  readonly transitionDigest: string;
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function canonicalBytes(value: unknown): Uint8Array {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new TypeError("transition is not canonical JSON");
  return new TextEncoder().encode(serialized);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Wrap the exact proposed state and triggering message alongside the durable
 * checkpoint intent. This record is persisted before any gateway call.
 */
export async function createPendingReplayIntent(
  intent: ReplayCheckpointIntent,
  message: ReplayTransitionMessage,
  proposedState: Record<string, unknown>,
): Promise<PendingReplayIntent> {
  if (!(await validateReplayCheckpointIntent(intent))) {
    throw new TypeError("checkpoint intent is invalid");
  }
  if (!plainRecord(proposedState)) throw new TypeError("proposed replay state is malformed");
  if (canonicalize(proposedState) !== new TextDecoder().decode(
    Uint8Array.from(atob(intent.canonicalSnapshotBase64Url
      .replace(/-/g, "+").replace(/_/g, "/")
      + "=".repeat((4 - intent.canonicalSnapshotBase64Url.length % 4) % 4)),
      (character) => character.charCodeAt(0)),
  )) {
    throw new TypeError("proposed replay state differs from checkpoint snapshot");
  }
  if (
    !message || typeof message !== "object" ||
    typeof message.messageId !== "string" || message.messageId.length === 0 ||
    typeof message.senderId !== "string" || message.senderId.length === 0 ||
    typeof message.recipientId !== "string" || message.recipientId.length === 0 ||
    typeof message.scope !== "string" || message.scope.length === 0 ||
    !Number.isSafeInteger(message.sequence) || message.sequence < 1 ||
    !DIGEST.test(message.canonicalDigest) ||
    typeof message.messageType !== "string" || message.messageType.length === 0 ||
    !Number.isSafeInteger(message.issuedAt) || message.issuedAt < 0 ||
    !Number.isSafeInteger(message.expiresAt) || message.expiresAt < 0
  ) throw new TypeError("transition message identity is malformed");

  const transition = {
    baseStateVersion: intent.baseStateVersion,
    message,
    proposedState,
    operationId: intent.operationId,
    snapshotDigest: intent.snapshotDigest,
  };
  return {
    version: 1,
    intent,
    message,
    proposedState,
    transitionDigest: await sha256Hex(canonicalBytes(transition)),
  };
}

/** Revalidate all persisted bytes before retry or finalization after restart. */
export async function validatePendingReplayIntent(
  pending: PendingReplayIntent,
): Promise<boolean> {
  if (
    !plainRecord(pending) ||
    pending.version !== 1 ||
    !plainRecord(pending.proposedState) ||
    !plainRecord(pending.message) ||
    !DIGEST.test(pending.transitionDigest) ||
    !(await validateReplayCheckpointIntent(pending.intent))
  ) return false;
  try {
    const rebuilt = await createPendingReplayIntent(
      pending.intent,
      pending.message as unknown as ReplayTransitionMessage,
      pending.proposedState,
    );
    return rebuilt.transitionDigest === pending.transitionDigest &&
      rebuilt.intent.canonicalCheckpointBody === pending.intent.canonicalCheckpointBody;
  } catch {
    return false;
  }
}
