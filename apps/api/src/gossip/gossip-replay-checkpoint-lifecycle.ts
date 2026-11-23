import {
  validatePendingReplayIntent,
  type PendingReplayIntent,
} from "./gossip-replay-pending-intent";

export const REPLAY_STATE_ENVELOPE_KEY = "replay-state-envelope-v2";
export const REPLAY_PENDING_INTENT_KEY = "replay-checkpoint-pending-v1";
export const LEGACY_REPLAY_STATE_KEY = "replay-state-v1";

export interface ReplayWitnessHead {
  readonly generation: number;
  readonly digest: string;
  readonly treeSize: number;
  readonly treeHeadDigest: string;
}

export interface VersionedReplayState {
  readonly version: 2;
  readonly stateVersion: number;
  readonly snapshot: Record<string, unknown>;
  readonly witnessHead: ReplayWitnessHead;
}

export interface VerifiedReplayCheckpointEvidence {
  readonly verified: true;
  readonly operationId: string;
  readonly checkpointDigest: string;
  readonly snapshotDigest: string;
  readonly trustDomainId: string;
  readonly witnessId: string;
  readonly authorityId: string;
  readonly hostId: string;
  readonly predecessorGeneration: number;
  readonly predecessorDigest: string;
  readonly generation: number;
  readonly treeSize: number;
  readonly treeHeadDigest: string;
  readonly receiptLeafHash: string;
}

export interface ReplayCheckpointStorageTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

export interface ReplayCheckpointStorage {
  transaction<T>(
    callback: (txn: ReplayCheckpointStorageTransaction) => Promise<T>,
  ): Promise<T>;
}

export async function initializeVersionedReplayState(
  storage: ReplayCheckpointStorage,
  initial: VersionedReplayState,
): Promise<
  | { readonly initialized: true }
  | { readonly initialized: false; readonly reason: "legacy_state_requires_quarantine" | "state_already_exists" }
> {
  if (
    initial.version !== 2 || !Number.isSafeInteger(initial.stateVersion) || initial.stateVersion < 0 ||
    !Number.isSafeInteger(initial.witnessHead.generation) || initial.witnessHead.generation < 0 ||
    !Number.isSafeInteger(initial.witnessHead.treeSize) || initial.witnessHead.treeSize < 0 ||
    !/^[0-9a-f]{64}$/.test(initial.witnessHead.digest) ||
    !/^[0-9a-f]{64}$/.test(initial.witnessHead.treeHeadDigest)
  ) throw new TypeError("initial versioned replay state is malformed");
  return storage.transaction(async (txn) => {
    const legacy = await txn.get<unknown>(LEGACY_REPLAY_STATE_KEY);
    if (legacy !== undefined) {
      return { initialized: false, reason: "legacy_state_requires_quarantine" } as const;
    }
    const current = await txn.get<VersionedReplayState>(REPLAY_STATE_ENVELOPE_KEY);
    if (current) return { initialized: false, reason: "state_already_exists" } as const;
    await txn.put(REPLAY_STATE_ENVELOPE_KEY, initial);
    return { initialized: true } as const;
  });
}

export type StagePendingIntentResult =
  | { readonly staged: true; readonly stateVersion: number }
  | {
      readonly staged: false;
      readonly reason: "legacy_state_requires_quarantine" | "state_missing" |
        "pending_intent_exists" | "stale_state_version" | "witness_predecessor_mismatch" |
        "invalid_pending_intent";
    };

export type FinalizePendingIntentResult =
  | { readonly finalized: true; readonly stateVersion: number }
  | {
      readonly finalized: false;
      readonly reason: "pending_intent_missing" | "pending_intent_mismatch" |
        "state_version_changed" | "evidence_binding_mismatch" | "invalid_pending_intent";
    };

/**
 * Persist intent before any gateway call. This transaction never changes the
 * accepted snapshot; legacy local-only state is deliberately not upgraded.
 */
export async function stagePendingReplayIntent(
  storage: ReplayCheckpointStorage,
  pending: PendingReplayIntent,
): Promise<StagePendingIntentResult> {
  if (!(await validatePendingReplayIntent(pending))) {
    return { staged: false, reason: "invalid_pending_intent" };
  }
  return storage.transaction(async (txn) => {
    const legacy = await txn.get<unknown>(LEGACY_REPLAY_STATE_KEY);
    if (legacy !== undefined) {
      return { staged: false, reason: "legacy_state_requires_quarantine" } as const;
    }
    const current = await txn.get<VersionedReplayState>(REPLAY_STATE_ENVELOPE_KEY);
    if (!current) return { staged: false, reason: "state_missing" } as const;
    const existing = await txn.get<PendingReplayIntent>(REPLAY_PENDING_INTENT_KEY);
    if (existing) return { staged: false, reason: "pending_intent_exists" } as const;
    if (current.stateVersion !== pending.intent.baseStateVersion) {
      return { staged: false, reason: "stale_state_version" } as const;
    }
    if (
      current.witnessHead.generation !== pending.intent.expectedPredecessor.generation ||
      current.witnessHead.digest !== pending.intent.expectedPredecessor.digest
    ) return { staged: false, reason: "witness_predecessor_mismatch" } as const;
    await txn.put(REPLAY_PENDING_INTENT_KEY, pending);
    return { staged: true, stateVersion: current.stateVersion } as const;
  });
}

/**
 * Commit snapshot, witness head and incremented version together. Call only
 * after the gateway evidence has been independently verified and bound to
 * this exact operation and predecessor.
 */
export async function finalizePendingReplayIntent(
  storage: ReplayCheckpointStorage,
  pending: PendingReplayIntent,
  evidence: VerifiedReplayCheckpointEvidence,
): Promise<FinalizePendingIntentResult> {
  return storage.transaction(async (txn) => {
    const stored = await txn.get<PendingReplayIntent>(REPLAY_PENDING_INTENT_KEY);
    if (!stored) return { finalized: false, reason: "pending_intent_missing" } as const;
    if (
      stored.transitionDigest !== pending.transitionDigest ||
      stored.intent.canonicalCheckpointBody !== pending.intent.canonicalCheckpointBody
    ) return { finalized: false, reason: "pending_intent_mismatch" } as const;
    if (!(await validatePendingReplayIntent(stored))) {
      return { finalized: false, reason: "invalid_pending_intent" } as const;
    }
    const current = await txn.get<VersionedReplayState>(REPLAY_STATE_ENVELOPE_KEY);
    if (!current || current.stateVersion !== stored.intent.baseStateVersion) {
      return { finalized: false, reason: "state_version_changed" } as const;
    }
    if (
      evidence.verified !== true ||
      evidence.operationId !== stored.intent.operationId ||
      evidence.snapshotDigest !== stored.intent.snapshotDigest ||
      evidence.trustDomainId !== stored.intent.scope.trustDomainId ||
      evidence.witnessId !== stored.intent.scope.witnessId ||
      evidence.authorityId !== stored.intent.scope.authorityId ||
      evidence.hostId !== stored.intent.scope.hostId ||
      !/^[0-9a-f]{64}$/.test(evidence.checkpointDigest) ||
      evidence.predecessorGeneration !== stored.intent.expectedPredecessor.generation ||
      evidence.predecessorDigest !== stored.intent.expectedPredecessor.digest ||
      !Number.isSafeInteger(evidence.generation) ||
      evidence.generation !== current.witnessHead.generation + 1 ||
      !Number.isSafeInteger(evidence.treeSize) || evidence.treeSize <= current.witnessHead.treeSize ||
      !/^[0-9a-f]{64}$/.test(evidence.treeHeadDigest) ||
      !/^[0-9a-f]{64}$/.test(evidence.receiptLeafHash)
    ) return { finalized: false, reason: "evidence_binding_mismatch" } as const;

    const next: VersionedReplayState = {
      version: 2,
      stateVersion: current.stateVersion + 1,
      snapshot: stored.proposedState,
      witnessHead: {
        generation: evidence.generation,
        digest: evidence.checkpointDigest,
        treeSize: evidence.treeSize,
        treeHeadDigest: evidence.treeHeadDigest,
      },
    };
    await txn.put(REPLAY_STATE_ENVELOPE_KEY, next);
    await txn.delete(REPLAY_PENDING_INTENT_KEY);
    return { finalized: true, stateVersion: next.stateVersion } as const;
  });
}

/** A pending intent is an admission lock, including after object reconstruction. */
export async function hasPendingReplayIntent(
  storage: ReplayCheckpointStorage,
): Promise<boolean> {
  return storage.transaction(async (txn) =>
    (await txn.get<PendingReplayIntent>(REPLAY_PENDING_INTENT_KEY)) !== undefined
  );
}
