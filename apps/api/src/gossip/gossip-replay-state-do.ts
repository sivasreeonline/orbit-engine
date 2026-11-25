import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import {
  finalizePendingReplayIntent,
  hasPendingReplayIntent,
  initializeVersionedReplayState,
  stagePendingReplayIntent,
  type ReplayCheckpointStorage,
  type VersionedReplayState,
  type VerifiedReplayCheckpointEvidence,
} from "./gossip-replay-checkpoint-lifecycle";
import {
  validatePendingReplayIntent,
  type PendingReplayIntent,
} from "./gossip-replay-pending-intent";
import {
  checkpointReplayViaWitnessGateway,
  verifyEvidenceViaWitnessGateway,
} from "../witness/witness-gateway-client";

const MAX_TTL_SECONDS = 300;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_SEQUENCE_GAP = 64;
const REORDER_WINDOW = 64;
const RETAINED_SEQUENCE_WINDOW = 128;
const DIGEST = /^[0-9a-f]{64}$/;

export const REPLAY_CHECKPOINT_QUARANTINE_KEY = "replay-checkpoint-quarantine-v1";

interface ReplayCheckpointQuarantine {
  readonly version: 1;
  readonly reason: "invalid_pending_intent" | "evidence_not_verified" | "finalization_rejected";
  readonly quarantinedAt: number;
}

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
    if (request.expiresAt <= trustedNow) delete state.outstandingRequests[requestId];
  }
}

interface PendingCheckpointAlarmStorage {
  get<T>(key: string): Promise<T | undefined>;
  getAlarm(): Promise<number | null>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
}

/** Re-arm the durable retry trigger after reconstruction when a pending intent exists. */
export async function rearmPendingCheckpointAlarm(
  storage: PendingCheckpointAlarmStorage,
): Promise<void> {
  const pending = await storage.get<PendingReplayIntent>("replay-checkpoint-pending-v1");
  const quarantine = await storage.get<ReplayCheckpointQuarantine>(REPLAY_CHECKPOINT_QUARANTINE_KEY);
  if (quarantine !== undefined) {
    // Also repair a crash between persisting quarantine and deleting an
    // already-scheduled alarm.
    await storage.deleteAlarm();
    return;
  }
  if (pending !== undefined && await storage.getAlarm() === null) {
    await storage.setAlarm(Date.now() + 1_000);
  }
}

/**
 * One Durable Object instance must be addressed per sender/recipient/scope
 * relationship. Its transaction is the serialization boundary for replay
 * decisions and durable state advancement.
 */
export class GossipReplayStateDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Re-arm recovery if the object was reconstructed after the intent commit
    // but before the staging caller could schedule its first alarm.
    this.ctx.blockConcurrencyWhile(() => rearmPendingCheckpointAlarm(this.ctx.storage));
  }

  async acceptVerifiedMessage(
    message: VerifiedGossipMessage,
    trustedNow: number,
  ): Promise<GossipReplayResult> {
    return this.ctx.storage.transaction(async (txn) => {
      const state =
        (await txn.get<StoredState>("replay-state-v1")) ?? emptyState();

      if (await txn.get("replay-checkpoint-pending-v1") !== undefined) {
        return reject(state, "BLOCKED", "a durable witness checkpoint intent is pending recovery");
      }
      if (await txn.get("replay-state-envelope-v2") !== undefined) {
        return reject(state, "BLOCKED", "versioned checkpoint state must advance through the witness finalization path");
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
      prune(next, trustedNow);
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

  /** Initialize a new versioned relationship only when no legacy local-only state exists. */
  async initializeCheckpointedState(
    initial: VersionedReplayState,
  ): Promise<
    | { readonly initialized: true }
    | { readonly initialized: false; readonly reason: "legacy_state_requires_quarantine" | "state_already_exists" }
  > {
    return initializeVersionedReplayState(
      this.ctx.storage as unknown as ReplayCheckpointStorage,
      initial,
    );
  }

  /** Persist one exact pending transition before making any gateway RPC. */
  async stageCheckpointIntent(
    pending: PendingReplayIntent,
  ): Promise<Awaited<ReturnType<typeof stagePendingReplayIntent>>> {
    const staged = await stagePendingReplayIntent(
      this.ctx.storage as unknown as ReplayCheckpointStorage,
      pending,
    );
    if (staged.staged) {
      // A newly staged transition is a new operator-authorized attempt. Clear
      // any quarantine left by a prior, already-resolved pending transition.
      await this.ctx.storage.delete(REPLAY_CHECKPOINT_QUARANTINE_KEY);
      // Alarm scheduling is deliberately outside the state transaction; the
      // constructor repairs the narrow crash window between commit and alarm.
      await this.ctx.storage.setAlarm(Date.now() + 1_000);
    }
    return staged;
  }

  /** Finalize only independently verified evidence bound to the pending operation. */
  async finalizeCheckpointIntent(
    pending: PendingReplayIntent,
    evidence: VerifiedReplayCheckpointEvidence,
  ): Promise<Awaited<ReturnType<typeof finalizePendingReplayIntent>>> {
    const finalized = await finalizePendingReplayIntent(
      this.ctx.storage as unknown as ReplayCheckpointStorage,
      pending,
      evidence,
    );
    if (finalized.finalized) {
      // Clear a marker left by a racing alarm only while no newer pending
      // transition has been staged in the meantime.
      await this.ctx.storage.transaction(async (txn) => {
        if (await txn.get<PendingReplayIntent>("replay-checkpoint-pending-v1") === undefined) {
          await txn.delete(REPLAY_CHECKPOINT_QUARANTINE_KEY);
        }
      });
    }
    return finalized;
  }

  /** Read the exact persisted request for restart recovery; never reconstruct it from current state. */
  async getPendingCheckpointIntent(): Promise<PendingReplayIntent | undefined> {
    return this.ctx.storage.get<PendingReplayIntent>("replay-checkpoint-pending-v1");
  }

  async hasPendingCheckpointIntent(): Promise<boolean> {
    return hasPendingReplayIntent(
      this.ctx.storage as unknown as ReplayCheckpointStorage,
    );
  }

  /** Read-only snapshot for internal integration assertions and diagnostics. */
  async getCheckpointedState(): Promise<VersionedReplayState | undefined> {
    return this.ctx.storage.get<VersionedReplayState>("replay-state-envelope-v2");
  }

  /**
   * Resume the exact persisted checkpoint after object reconstruction.
   * Every RPC is outside a storage transaction. Any unavailable, ambiguous,
   * or unverifiable result leaves the pending intent and accepted state intact.
   */
  async recoverPendingCheckpointIntent(): Promise<
    | { readonly recovered: false; readonly reason:
        | "no_pending_intent"
        | "invalid_pending_intent"
        | "gateway_unavailable"
        | "checkpoint_not_committed"
        | "evidence_not_verified"
        | "finalization_rejected"
        | "recovery_error" }
    | { readonly recovered: true; readonly stateVersion: number }
  > {
    try {
      const pending = await this.getPendingCheckpointIntent();
      if (!pending) return { recovered: false, reason: "no_pending_intent" };
      if (!(await validatePendingReplayIntent(pending))) {
        return { recovered: false, reason: "invalid_pending_intent" };
      }

      const checkpoint = await checkpointReplayViaWitnessGateway(
        this.env,
        new TextEncoder().encode(pending.intent.canonicalCheckpointBody),
      );
      if (!checkpoint.checkpointed) {
        if (
          checkpoint.reason === "gateway_unavailable" ||
          checkpoint.reason === "caller_identity_unconfigured" ||
          checkpoint.reason === "caller_proof_signing_failed"
        ) return { recovered: false, reason: "gateway_unavailable" };
        if (
          checkpoint.reason === "provider_unavailable" ||
          checkpoint.reason === "ambiguous_commit"
        ) return { recovered: false, reason: "checkpoint_not_committed" };
        return { recovered: false, reason: "finalization_rejected" };
      }

      const verification = await verifyEvidenceViaWitnessGateway(
        this.env,
        checkpoint.canonicalEvidenceBody,
      );
      if (!verification.verified) {
        if (
          verification.reason === "gateway_unavailable" ||
          verification.reason === "caller_identity_unconfigured" ||
          verification.reason === "caller_proof_signing_failed" ||
          verification.reason === "trust_configuration_unavailable" ||
          verification.reason === "trust_state_unavailable"
        ) return { recovered: false, reason: "gateway_unavailable" };
        return { recovered: false, reason: "evidence_not_verified" };
      }

      const finalized = await this.finalizeCheckpointIntent(pending, {
        verified: true,
        operationId: verification.operationId,
        checkpointDigest: verification.checkpointDigest,
        snapshotDigest: verification.snapshotDigest,
        trustDomainId: verification.trustDomainId,
        witnessId: verification.witnessId,
        authorityId: verification.authorityId,
        hostId: verification.hostId,
        predecessorGeneration: verification.predecessorGeneration,
        predecessorDigest: verification.predecessorDigest,
        generation: verification.generation,
        treeSize: verification.treeSize,
        treeHeadDigest: verification.treeHeadDigest,
        receiptLeafHash: verification.receiptLeafHash,
      });
      if (!finalized.finalized) {
        return { recovered: false, reason: "finalization_rejected" };
      }
      return { recovered: true, stateVersion: finalized.stateVersion };
    } catch {
      return { recovered: false, reason: "recovery_error" };
    }
  }

  /** Durable retry trigger. Failed recovery keeps the relationship blocked. */
  override async alarm(): Promise<void> {
    const attemptedPending = await this.getPendingCheckpointIntent();
    const result = await this.recoverPendingCheckpointIntent();
    if (!result.recovered && (
      result.reason === "invalid_pending_intent" ||
      result.reason === "evidence_not_verified" ||
      result.reason === "finalization_rejected"
    )) {
      // Persist quarantine so constructor recovery cannot re-arm this intent
      // after eviction/restart. The pending bytes and accepted state are kept.
      const quarantined = await this.ctx.storage.transaction(async (txn) => {
        // A concurrent direct recovery may have finalized the intent after
        // this alarm observed its integrity failure. Quarantine only if the
        // exact pending slot still exists at this atomic boundary.
        const currentPending = await txn.get<PendingReplayIntent>("replay-checkpoint-pending-v1");
        if (
          !attemptedPending ||
          currentPending === undefined ||
          currentPending.transitionDigest !== attemptedPending.transitionDigest
        ) {
          return false;
        }
        await txn.put<ReplayCheckpointQuarantine>(
          REPLAY_CHECKPOINT_QUARANTINE_KEY,
          { version: 1, reason: result.reason, quarantinedAt: Date.now() },
        );
        return true;
      });
      if (quarantined) await this.ctx.storage.deleteAlarm();
      return;
    }
    if (
      !result.recovered &&
      (
        result.reason === "gateway_unavailable" ||
        result.reason === "checkpoint_not_committed" ||
        result.reason === "recovery_error"
      )
    ) {
      // Retry transient infrastructure/evidence-availability failures only.
      await this.ctx.storage.setAlarm(Date.now() + 30_000);
    }
  }

  override async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}
