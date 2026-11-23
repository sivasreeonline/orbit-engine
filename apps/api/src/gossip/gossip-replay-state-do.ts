import { DurableObject } from "cloudflare:workers";
import canonicalize from "canonicalize";
import type { Env } from "../env";

const MAX_TTL_SECONDS = 300;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_SEQUENCE_GAP = 64;
const REORDER_WINDOW = 64;
const RETAINED_SEQUENCE_WINDOW = 128;
const DIGEST = /^[0-9a-f]{64}$/;
const ZERO_DIGEST = "0".repeat(64);
const REPLAY_STATE_KEY = "replay-state-v1";
const PENDING_INTENT_KEY = "pending-checkpoint-intent-v1";
const CHECKPOINT_STATE_KEY = "checkpoint-state-v1";

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
 */
export type GossipReplayOutcome =
  | "CHECKPOINT_PENDING"
  | "ACCEPTED"
  | "ACCEPTED_WITH_GAP"
  | "DUPLICATE"
  | "BLOCKED"
  | "QUARANTINE";

export interface GossipReplaySnapshot {
  readonly version: 1;
  readonly senderId: string;
  readonly recipientId: string;
  readonly scope: string;
  readonly highestSequence: number;
  readonly seenBySequence: Readonly<Record<string, { readonly messageId: string; readonly digest: string }>>;
  readonly seenByMessageId: Readonly<Record<string, { readonly sequence: number; readonly digest: string }>>;
  readonly outstandingRequests: Readonly<Record<string, { readonly nonce: string; readonly expiresAt: number }>>;
  readonly consumedNonces: readonly string[];
  readonly missingSequences: readonly number[];
}

export interface GossipReplayPendingIntent {
  readonly operationId: string;
  readonly snapshotDigest: string;
  readonly expectedGeneration: number;
  readonly expectedPreviousDigest: string;
  readonly snapshot: GossipReplaySnapshot;
}

export interface GossipReplayResult {
  readonly outcome: GossipReplayOutcome;
  readonly reason: string;
  readonly highestSequence: number;
  readonly missingSequences: readonly number[];
  readonly pendingIntent?: GossipReplayPendingIntent;
}

export interface WitnessVerificationAttestation {
  readonly verified: true;
  readonly trustBundleDigest: string;
  readonly treeHeadDigest: string;
  readonly treeSize: number;
  readonly receiptLeafHash: string;
}

export interface GossipReplayCheckpointState {
  readonly generation: number;
  readonly checkpointDigest: string;
  readonly snapshotDigest: string;
  readonly operationId: string;
  readonly receiptDigest: string;
  readonly trustBundleDigest: string;
  readonly treeHeadDigest: string;
  readonly treeSize: number;
  readonly receiptLeafHash: string;
  readonly acceptedOutcome: "ACCEPTED" | "ACCEPTED_WITH_GAP";
  readonly reason: string;
}

export interface GossipReplayFinalizeResult {
  readonly status: "FINALIZED" | "ALREADY_FINALIZED" | "BLOCKED" | "QUARANTINE";
  readonly reason: string;
  readonly replay?: GossipReplayResult;
}

type StoredState = {
  version: 1;
  senderId: string;
  recipientId: string;
  scope: string;
  highestSequence: number;
  seenBySequence: Record<string, { messageId: string; digest: string }>;
  seenByMessageId: Record<string, { sequence: number; digest: string }>;
  outstandingRequests: Record<string, { nonce: string; expiresAt: number }>;
  consumedNonces: string[];
  missingSequences: number[];
};

interface StoredPendingIntent {
  readonly version: 1;
  readonly operationId: string;
  readonly snapshotDigest: string;
  readonly expectedGeneration: number;
  readonly expectedPreviousDigest: string;
  readonly snapshot: StoredState;
  readonly acceptedOutcome: "ACCEPTED" | "ACCEPTED_WITH_GAP";
  readonly reason: string;
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

function emptyCheckpointState(): GossipReplayCheckpointState {
  return {
    generation: 0,
    checkpointDigest: ZERO_DIGEST,
    snapshotDigest: ZERO_DIGEST,
    operationId: "",
    receiptDigest: ZERO_DIGEST,
    trustBundleDigest: ZERO_DIGEST,
    treeHeadDigest: ZERO_DIGEST,
    treeSize: 0,
    receiptLeafHash: ZERO_DIGEST,
    acceptedOutcome: "ACCEPTED",
    reason: "no independently verified checkpoint has been finalized",
  };
}

function toSnapshot(state: StoredState): GossipReplaySnapshot {
  return {
    version: state.version,
    senderId: state.senderId,
    recipientId: state.recipientId,
    scope: state.scope,
    highestSequence: state.highestSequence,
    seenBySequence: structuredClone(state.seenBySequence),
    seenByMessageId: structuredClone(state.seenByMessageId),
    outstandingRequests: structuredClone(state.outstandingRequests),
    consumedNonces: [...state.consumedNonces].sort(),
    missingSequences: [...state.missingSequences].sort((left, right) => left - right),
  };
}

function toStoredState(snapshot: GossipReplaySnapshot): StoredState {
  return {
    version: snapshot.version,
    senderId: snapshot.senderId,
    recipientId: snapshot.recipientId,
    scope: snapshot.scope,
    highestSequence: snapshot.highestSequence,
    seenBySequence: structuredClone(snapshot.seenBySequence) as StoredState["seenBySequence"],
    seenByMessageId: structuredClone(snapshot.seenByMessageId) as StoredState["seenByMessageId"],
    outstandingRequests: structuredClone(snapshot.outstandingRequests) as StoredState["outstandingRequests"],
    consumedNonces: [...snapshot.consumedNonces],
    missingSequences: [...snapshot.missingSequences],
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

function validDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value);
}

function isEmptyState(state: StoredState): boolean {
  return (
    state.senderId === "" &&
    state.recipientId === "" &&
    state.scope === "" &&
    state.highestSequence === 0 &&
    Object.keys(state.seenBySequence).length === 0 &&
    Object.keys(state.seenByMessageId).length === 0 &&
    Object.keys(state.outstandingRequests).length === 0 &&
    state.consumedNonces.length === 0 &&
    state.missingSequences.length === 0
  );
}

function validAttestation(value: unknown): value is WitnessVerificationAttestation {
  if (!value || typeof value !== "object") return false;
  const attestation = value as Partial<WitnessVerificationAttestation>;
  return (
    attestation.verified === true &&
    validDigest(attestation.trustBundleDigest) &&
    validDigest(attestation.treeHeadDigest) &&
    validDigest(attestation.receiptLeafHash) &&
    validInteger(attestation.treeSize, 1)
  );
}

function prune(state: StoredState, trustedNow: number): void {
  const minimumSequence = Math.max(0, state.highestSequence - RETAINED_SEQUENCE_WINDOW);
  for (const key of Object.keys(state.seenBySequence)) {
    if (Number(key) < minimumSequence) {
      const item = state.seenBySequence[key];
      delete state.seenBySequence[key];
      if (item) delete state.seenByMessageId[item.messageId];
    }
  }
  for (const [requestId, request] of Object.entries(state.outstandingRequests)) {
    if (
      request.expiresAt <= trustedNow ||
      !state.seenByMessageId[requestId]
    ) delete state.outstandingRequests[requestId];
  }
}

async function digestSnapshot(snapshot: GossipReplaySnapshot): Promise<string> {
  const canonical = canonicalize(snapshot);
  if (typeof canonical !== "string") throw new TypeError("replay snapshot is not RFC 8785 canonicalizable");
  const bytes = new TextEncoder().encode(canonical);
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * One Durable Object instance must be addressed per sender/recipient/scope
 * relationship. Replay state is not committed until a verified witness
 * checkpoint has been finalized.
 */
export class GossipReplayStateDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  /** Returns only the replay state whose witness checkpoint has been finalized. */
  async readSnapshot(): Promise<GossipReplaySnapshot> {
    const state =
      (await this.ctx.storage.get<StoredState>(REPLAY_STATE_KEY)) ?? emptyState();
    return toSnapshot(state);
  }

  /** Read the pending state needed to resume an interrupted witness append. */
  async readPendingCheckpointIntent(): Promise<GossipReplayPendingIntent | null> {
    const pending = await this.ctx.storage.get<StoredPendingIntent>(PENDING_INTENT_KEY);
    if (!pending) return null;
    return {
      operationId: pending.operationId,
      snapshotDigest: pending.snapshotDigest,
      expectedGeneration: pending.expectedGeneration,
      expectedPreviousDigest: pending.expectedPreviousDigest,
      snapshot: toSnapshot(pending.snapshot),
    };
  }

  async readCheckpointState(): Promise<GossipReplayCheckpointState | null> {
    return (await this.ctx.storage.get<GossipReplayCheckpointState>(CHECKPOINT_STATE_KEY)) ?? null;
  }

  /**
   * Validates a message and stages its next replay state as a durable pending
   * intent. It deliberately does not advance the committed replay state.
   */
  async prepareCheckpointIntent(
    message: VerifiedGossipMessage,
    trustedNow: number,
  ): Promise<GossipReplayResult> {
    return this.ctx.storage.transaction(async (txn) => {
      const state =
        (await txn.get<StoredState>(REPLAY_STATE_KEY)) ?? emptyState();
      const pendingPrior = await txn.get<StoredPendingIntent>(PENDING_INTENT_KEY);
      if (pendingPrior) {
        return reject(state, "BLOCKED", "a witness checkpoint intent is pending; recover or finalize it before accepting another message");
      }
      const storedCheckpoint =
        await txn.get<GossipReplayCheckpointState>(CHECKPOINT_STATE_KEY);
      if (!storedCheckpoint && !isEmptyState(state)) {
        return reject(state, "QUARANTINE", "non-empty legacy replay state has no independent witness checkpoint; automatic anchoring is forbidden");
      }
      if (storedCheckpoint) {
        if (
          !validDigest(storedCheckpoint.snapshotDigest) ||
          !validDigest(storedCheckpoint.checkpointDigest) ||
          await digestSnapshot(toSnapshot(state)) !== storedCheckpoint.snapshotDigest
        ) {
          return reject(state, "QUARANTINE", "committed replay state differs from its locally recorded witness checkpoint digest");
        }
      }

      if (!message || typeof message !== "object") {
        return reject(state, "QUARANTINE", "message envelope is malformed");
      }
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

      if (!validInteger(message.issuedAt) || !validInteger(message.expiresAt)) {
        return reject(state, "QUARANTINE", "message timestamps are malformed");
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
        consumedNonces: [...consumed].sort(),
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
      next.missingSequences = next.missingSequences
        .filter((missing) => missing !== message.sequence)
        .sort((left, right) => left - right);
      prune(next, trustedNow);

      const snapshot = toSnapshot(next);
      const snapshotDigest = await digestSnapshot(snapshot);
      const checkpointState =
        (await txn.get<GossipReplayCheckpointState>(CHECKPOINT_STATE_KEY)) ??
        emptyCheckpointState();
      const acceptedOutcome =
        snapshot.missingSequences.length > 0 ? "ACCEPTED_WITH_GAP" : "ACCEPTED";
      const reason =
        snapshot.missingSequences.length > 0
          ? "message validated; replay state awaits independent witness checkpoint with missing sender sequences visible"
          : "message validated; replay state awaits independent witness checkpoint";
      const operationId = `fence-monitor-replay-${snapshotDigest}`;
      const pending: StoredPendingIntent = {
        version: 1,
        operationId,
        snapshotDigest,
        expectedGeneration: checkpointState.generation,
        expectedPreviousDigest: checkpointState.checkpointDigest,
        snapshot: toStoredState(snapshot),
        acceptedOutcome,
        reason,
      };
      await txn.put(PENDING_INTENT_KEY, pending);

      return {
        ...result(next, "CHECKPOINT_PENDING", reason),
        pendingIntent: {
          operationId,
          snapshotDigest,
          expectedGeneration: checkpointState.generation,
          expectedPreviousDigest: checkpointState.checkpointDigest,
          snapshot,
        },
      };
    });
  }

  /**
   * Compatibility entrypoint is deliberately checkpoint-gated. It stages an
   * intent and returns CHECKPOINT_PENDING; it never commits replay state itself.
   */
  async acceptVerifiedMessage(
    message: VerifiedGossipMessage,
    trustedNow: number,
  ): Promise<GossipReplayResult> {
    return this.prepareCheckpointIntent(message, trustedNow);
  }

  /**
   * Finalizes a pending replay snapshot only after the private gateway has
   * independently verified the signed receipt, trust bundle and tree-head
   * inclusion/consistency evidence.
   */
  async finalizeCheckpointIntent(input: {
    readonly operationId: string;
    readonly snapshotDigest: string;
    readonly generation: number;
    readonly checkpointDigest: string;
    readonly receiptDigest: string;
    readonly verification: WitnessVerificationAttestation;
  }): Promise<GossipReplayFinalizeResult> {
    return this.ctx.storage.transaction(async (txn) => {
      const pending = await txn.get<StoredPendingIntent>(PENDING_INTENT_KEY);
      const current =
        (await txn.get<GossipReplayCheckpointState>(CHECKPOINT_STATE_KEY)) ??
        emptyCheckpointState();
      const committed =
        (await txn.get<StoredState>(REPLAY_STATE_KEY)) ?? emptyState();

      if (!pending) {
        if (
          current.operationId === input.operationId &&
          current.snapshotDigest === input.snapshotDigest &&
          current.generation === input.generation &&
          current.checkpointDigest === input.checkpointDigest &&
          current.receiptDigest === input.receiptDigest
        ) {
          return {
            status: "ALREADY_FINALIZED",
            reason: "the exact witness checkpoint was already finalized",
            replay: result(committed, current.acceptedOutcome, current.reason),
          };
        }
        return {
          status: "QUARANTINE",
          reason: "no matching pending checkpoint intent exists",
        };
      }

      if (!validAttestation(input.verification)) {
        return {
          status: "BLOCKED",
          reason: "gateway evidence verification attestation is missing or malformed; pending intent retained",
        };
      }
      if (
        input.operationId !== pending.operationId ||
        input.snapshotDigest !== pending.snapshotDigest ||
        input.generation !== pending.expectedGeneration + 1 ||
        !validDigest(input.checkpointDigest) ||
        !validDigest(input.receiptDigest)
      ) {
        return {
          status: "QUARANTINE",
          reason: "finalization metadata does not match the exact pending operation",
        };
      }
      if (
        current.generation !== pending.expectedGeneration ||
        current.checkpointDigest !== pending.expectedPreviousDigest
      ) {
        return {
          status: "QUARANTINE",
          reason: "checkpoint predecessor changed while intent was pending",
        };
      }

      const checkpointState: GossipReplayCheckpointState = {
        generation: input.generation,
        checkpointDigest: input.checkpointDigest,
        snapshotDigest: pending.snapshotDigest,
        operationId: pending.operationId,
        receiptDigest: input.receiptDigest,
        trustBundleDigest: input.verification.trustBundleDigest,
        treeHeadDigest: input.verification.treeHeadDigest,
        treeSize: input.verification.treeSize,
        receiptLeafHash: input.verification.receiptLeafHash,
        acceptedOutcome: pending.acceptedOutcome,
        reason: pending.reason,
      };
      await txn.put(REPLAY_STATE_KEY, pending.snapshot);
      await txn.put(CHECKPOINT_STATE_KEY, checkpointState);
      await txn.delete(PENDING_INTENT_KEY);
      return {
        status: "FINALIZED",
        reason: "witness checkpoint verified and replay state atomically finalized",
        replay: result(pending.snapshot, pending.acceptedOutcome, pending.reason),
      };
    });
  }

  override async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}
