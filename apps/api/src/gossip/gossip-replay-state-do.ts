import { DurableObject } from "cloudflare:workers";

const MAX_TTL_SECONDS = 300;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_SEQUENCE_GAP = 64;
const REORDER_WINDOW = 64;
const RETAINED_SEQUENCE_WINDOW = 128;
const DIGEST = /^[0-9a-f]{64}$/;

export type GossipMessageType =
  | "HEAD_ADVERTISEMENT"
  | "EQUIVOCATION_ALERT"
  | "CONSISTENCY_PROOF_REQUEST"
  | "CONSISTENCY_PROOF_RESPONSE";

export interface VerifiedGossipMessage {
  readonly messageId: string;
  readonly senderId: string;
  readonly recipientId: string;
  readonly scope: string;
  readonly sequence: number;
  readonly canonicalDigest: string;
  readonly messageType: GossipMessageType;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly requestNonce?: string;
  readonly responseRequestId?: string;
  readonly responseNonce?: string;
}

/** The caller must complete envelope authentication, signature, trust, scope,
 * and Merkle-proof verification before invoking this internal RPC method.
 * This object persists receiver replay state; it is not itself a trust verifier.
 */
export type GossipReplayOutcome =
  | "ACCEPTED"
  | "ACCEPTED_WITH_GAP"
  | "DUPLICATE"
  | "BLOCKED"
  | "QUARANTINE";

export interface GossipReplayResult {
  readonly outcome: GossipReplayOutcome;
  readonly reason: string;
  readonly highestSequence: number;
  readonly missingSequences: readonly number[];
}

interface StoredState {
  readonly version: 1;
  senderId: string;
  recipientId: string;
  scope: string;
  highestSequence: number;
  seenBySequence: Record<string, { messageId: string; digest: string }>;
  seenByMessageId: Record<string, { sequence: number; digest: string }>;
  outstandingRequests: Record<string, { nonce: string; expiresAt: number }>;
  consumedNonces: string[];
  missingSequences: number[];
}

function emptyState(): StoredState {
  return {
    version: 1,
    senderId: "",
    recipientId: "",
    scope: "",
    highestSequence: 0,
    seenBySequence: {},
    seenByMessageId: {},
    outstandingRequests: {},
    consumedNonces: [],
    missingSequences: [],
  };
}

function result(
  state: StoredState,
  outcome: GossipReplayOutcome,
  reason: string,
): GossipReplayResult {
  return {
    outcome,
    reason,
    highestSequence: state.highestSequence,
    missingSequences: [...state.missingSequences].sort((a, b) => a - b),
  };
}

function reject(
  state: StoredState,
  outcome: GossipReplayOutcome,
  reason: string,
): GossipReplayResult {
  return result(state, outcome, reason);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validInteger(value: unknown, minimum = 0): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum;
}

function prune(state: StoredState): void {
  const minimumSequence = Math.max(0, state.highestSequence - RETAINED_SEQUENCE_WINDOW);
  for (const key of Object.keys(state.seenBySequence)) {
    if (Number(key) < minimumSequence) {
      const item = state.seenBySequence[key];
      delete state.seenBySequence[key];
      if (item) delete state.seenByMessageId[item.messageId];
    }
  }
  const consumed = state.consumedNonces.slice(-RETAINED_SEQUENCE_WINDOW);
  state.consumedNonces = consumed;
  for (const [requestId, request] of Object.entries(state.outstandingRequests)) {
    if (request.expiresAt <= 0) delete state.outstandingRequests[requestId];
  }
}

/**
 * One Durable Object instance must be addressed per sender/recipient/scope
 * relationship. Its transaction is the serialization boundary for replay
 * decisions and durable state advancement.
 */
export class GossipReplayStateDO extends DurableObject {
  constructor(ctx: DurableObjectState, env: Record<string, unknown>) {
    super(ctx, env);
  }

  async acceptVerifiedMessage(
    message: VerifiedGossipMessage,
    trustedNow: number,
  ): Promise<GossipReplayResult> {
    return this.ctx.storage.transaction(async (txn) => {
      const state =
        (await txn.get<StoredState>("replay-state-v1")) ?? emptyState();

      if (!validInteger(trustedNow)) {
        return reject(state, "QUARANTINE", "trusted receiver time is malformed");
      }
      for (const value of [
        message.messageId,
        message.senderId,
        message.recipientId,
        message.scope,
      ]) {
        if (!nonEmpty(value)) {
          return reject(state, "QUARANTINE", "message identity or scope is malformed");
        }
      }
      if (message.senderId === message.recipientId) {
        return reject(state, "QUARANTINE", "monitor gossip message cannot be self-addressed");
      }
      if (
        state.senderId &&
        (state.senderId !== message.senderId ||
          state.recipientId !== message.recipientId ||
          state.scope !== message.scope)
      ) {
        return reject(state, "QUARANTINE", "sender, recipient or witness scope changed within this replay relationship");
      }
      if (!validInteger(message.sequence, 1)) {
        return reject(state, "QUARANTINE", "sender sequence is malformed");
      }
      if (!DIGEST.test(message.canonicalDigest)) {
        return reject(state, "QUARANTINE", "canonical message digest is malformed");
      }

      const priorMessage = state.seenByMessageId[message.messageId];
      if (priorMessage) {
        if (
          priorMessage.sequence === message.sequence &&
          priorMessage.digest === message.canonicalDigest
        ) {
          return reject(state, "DUPLICATE", "exact message replay is idempotent");
        }
        return reject(state, "QUARANTINE", "message ID was reused with different sequence or bytes");
      }

      const priorSequence = state.seenBySequence[String(message.sequence)];
      if (priorSequence) {
        if (
          priorSequence.messageId === message.messageId &&
          priorSequence.digest === message.canonicalDigest
        ) {
          return reject(state, "DUPLICATE", "exact sender sequence replay is idempotent");
        }
        return reject(state, "QUARANTINE", "sender reused a sequence for different message content");
      }

      if (message.issuedAt > trustedNow + MAX_CLOCK_SKEW_SECONDS) {
        return reject(state, "QUARANTINE", "message issue time exceeds trusted-clock skew");
      }
      if (message.expiresAt <= trustedNow) {
        return reject(state, "BLOCKED", "message has expired");
      }
      if (
        message.expiresAt <= message.issuedAt ||
        message.expiresAt - message.issuedAt > MAX_TTL_SECONDS
      ) {
        return reject(state, "QUARANTINE", "message lifetime is invalid or exceeds five minutes");
      }

      if (message.sequence <= state.highestSequence) {
        if (state.highestSequence - message.sequence >= REORDER_WINDOW) {
          return reject(state, "BLOCKED", "out-of-order message is older than the replay window");
        }
      } else if (message.sequence - state.highestSequence > MAX_SEQUENCE_GAP) {
        return reject(state, "BLOCKED", "sender sequence gap exceeds the bounded resynchronization window");
      }

      const outstanding = { ...state.outstandingRequests };
      const consumed = new Set(state.consumedNonces);

      if (message.messageType === "CONSISTENCY_PROOF_REQUEST") {
        const nonce = message.requestNonce;
        if (!nonEmpty(nonce)) {
          return reject(state, "QUARANTINE", "consistency request nonce is missing");
        }
        if (
          consumed.has(nonce) ||
          Object.values(outstanding).some((request) => request.nonce === nonce)
        ) {
          return reject(state, "QUARANTINE", "request nonce was reused");
        }
        outstanding[message.messageId] = { nonce, expiresAt: message.expiresAt };
      } else if (message.messageType === "CONSISTENCY_PROOF_RESPONSE") {
        const requestId = message.responseRequestId;
        const nonce = message.responseNonce;
        if (!nonEmpty(requestId) || !nonEmpty(nonce)) {
          return reject(state, "QUARANTINE", "proof response lacks request correlation");
        }
        const expected = outstanding[requestId];
        if (!expected) {
          return reject(state, "QUARANTINE", "proof response has no outstanding request");
        }
        if (expected.nonce !== nonce) {
          return reject(state, "QUARANTINE", "proof response nonce does not match its request");
        }
        if (trustedNow >= expected.expiresAt) {
          return reject(state, "BLOCKED", "originating proof request has expired");
        }
        delete outstanding[requestId];
        consumed.add(nonce);
      } else if (
        message.messageType !== "HEAD_ADVERTISEMENT" &&
        message.messageType !== "EQUIVOCATION_ALERT"
      ) {
        return reject(state, "QUARANTINE", "unsupported monitor gossip message type");
      } else if (
        message.requestNonce !== undefined ||
        message.responseRequestId !== undefined ||
        message.responseNonce !== undefined
      ) {
        return reject(state, "QUARANTINE", "non-request message carries request-correlation fields");
      }

      const next: StoredState = {
        ...state,
        senderId: state.senderId || message.senderId,
        recipientId: state.recipientId || message.recipientId,
        scope: state.scope || message.scope,
        highestSequence: Math.max(state.highestSequence, message.sequence),
        seenBySequence: {
          ...state.seenBySequence,
          [String(message.sequence)]: {
            messageId: message.messageId,
            digest: message.canonicalDigest,
          },
        },
        seenByMessageId: {
          ...state.seenByMessageId,
          [message.messageId]: {
            sequence: message.sequence,
            digest: message.canonicalDigest,
          },
        },
        outstandingRequests: outstanding,
        consumedNonces: [...consumed],
        missingSequences: [...state.missingSequences],
      };

      if (message.sequence > state.highestSequence + 1) {
        for (
          let missing = state.highestSequence + 1;
          missing < message.sequence;
          missing += 1
        ) {
          next.missingSequences.push(missing);
        }
      }
      next.missingSequences = next.missingSequences.filter(
        (missing) => missing !== message.sequence,
      );
      prune(next);
      await txn.put("replay-state-v1", next);

      return result(
        next,
        next.missingSequences.length > 0 ? "ACCEPTED_WITH_GAP" : "ACCEPTED",
        next.missingSequences.length > 0
          ? "message accepted; missing sender sequences remain visible"
          : "message and replay state committed atomically",
      );
    });
  }

  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}
