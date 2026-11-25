/**
 * Pure FENCE-001 trust recovery decision model.
 *
 * This module deliberately does not persist state, contact a witness, or write
 * an external anchor. It classifies independently obtained observations so the
 * gateway/operations layer can fail closed before taking any recovery action.
 */
export interface TrustCheckpoint {
  readonly trustBundleGeneration: number;
  readonly trustBundleDigest: string;
  readonly logId: string;
  readonly treeSize: number;
  readonly treeRootHash: string;
  readonly treeHeadDigest: string;
  readonly anchorSequence: number;
  readonly anchorRecordDigest: string;
}

export interface MonitorObservation {
  readonly monitorId: string;
  readonly checkpoint: Pick<TrustCheckpoint, "logId" | "treeSize" | "treeRootHash">;
}

export type TrustRecoveryDecision =
  | { readonly action: "CONTINUE"; readonly reason: "all_views_agree" }
  | { readonly action: "REPAIR_LOCAL_FORWARD"; readonly reason: "anchor_ahead"; readonly requiredCheckpoint: TrustCheckpoint }
  | { readonly action: "ADVANCE_ANCHOR"; readonly reason: "witness_ahead"; readonly requiredCheckpoint: TrustCheckpoint }
  | { readonly action: "QUARANTINE"; readonly reason:
      | "local_ahead"
      | "anchor_rollback"
      | "witness_rollback"
      | "tree_fork"
      | "monitor_disagreement"
      | "anchor_sequence_conflict"
      | "log_identity_mismatch"
      | "trust_bundle_regression"
      | "trust_bundle_conflict"
      | "invalid_observation"
      | "insufficient_monitor_agreement"
      | "consistency_unproven"
      | "anchor_unavailable"
      | "witness_unavailable" };

export interface TrustRecoveryInput {
  readonly local: TrustCheckpoint;
  readonly anchor: TrustCheckpoint | null;
  readonly witness: TrustCheckpoint | null;
  readonly monitors: readonly MonitorObservation[];
  readonly requiredMonitorCount: number;
  readonly witnessExtendsAnchor: boolean;
  /** Root-signed bundle chain from local state to the independently stored anchor. */
  readonly anchorTrustBundleExtendsLocal: boolean;
  /** Root-signed bundle chain from the anchor to the current witness view. */
  readonly witnessTrustBundleExtendsAnchor: boolean;
  readonly anchorAvailable: boolean;
}

const DIGEST = /^[0-9a-f]{64}$/;

function validCheckpoint(value: TrustCheckpoint): boolean {
  return Number.isSafeInteger(value.trustBundleGeneration) && value.trustBundleGeneration >= 0 &&
    DIGEST.test(value.trustBundleDigest) &&
    value.logId.length > 0 &&
    Number.isSafeInteger(value.treeSize) && value.treeSize >= 0 &&
    DIGEST.test(value.treeRootHash) &&
    DIGEST.test(value.treeHeadDigest) &&
    Number.isSafeInteger(value.anchorSequence) && value.anchorSequence >= 0 &&
    DIGEST.test(value.anchorRecordDigest);
}

function sameHead(
  a: Pick<TrustCheckpoint, "logId" | "treeSize" | "treeRootHash">,
  b: Pick<TrustCheckpoint, "logId" | "treeSize" | "treeRootHash">,
): boolean {
  return a.logId === b.logId && a.treeSize === b.treeSize && a.treeRootHash === b.treeRootHash;
}

function compareProgress(a: TrustCheckpoint, b: TrustCheckpoint): number {
  if (a.trustBundleGeneration !== b.trustBundleGeneration) {
    return a.trustBundleGeneration < b.trustBundleGeneration ? -1 : 1;
  }
  if (a.treeSize !== b.treeSize) return a.treeSize < b.treeSize ? -1 : 1;
  return 0;
}

/**
 * Classify local, independently anchored, witness and monitor views.
 * A caller must separately verify signatures, consistency proofs and anchor CAS.
 */
export function decideTrustRecovery(input: TrustRecoveryInput): TrustRecoveryDecision {
  const { local, anchor, witness, monitors } = input;
  if (!validCheckpoint(local) || (anchor !== null && !validCheckpoint(anchor)) ||
      (witness !== null && !validCheckpoint(witness)) ||
      !Number.isSafeInteger(input.requiredMonitorCount) || input.requiredMonitorCount < 1 ||
      !Array.isArray(monitors) || monitors.some((item) =>
        !item.monitorId || !item.checkpoint.logId ||
        !Number.isSafeInteger(item.checkpoint.treeSize) || item.checkpoint.treeSize < 0 ||
        !DIGEST.test(item.checkpoint.treeRootHash)
      )) return { action: "QUARANTINE", reason: "invalid_observation" };

  if (!input.anchorAvailable || !anchor) {
    return { action: "QUARANTINE", reason: "anchor_unavailable" };
  }
  if (!witness) return { action: "QUARANTINE", reason: "witness_unavailable" };

  if (local.logId !== anchor.logId || anchor.logId !== witness.logId) {
    return { action: "QUARANTINE", reason: "log_identity_mismatch" };
  }
  if (local.trustBundleGeneration > anchor.trustBundleGeneration) {
    return { action: "QUARANTINE", reason: "local_ahead" };
  }
  if (anchor.trustBundleGeneration > local.trustBundleGeneration &&
      !input.anchorTrustBundleExtendsLocal) {
    return { action: "QUARANTINE", reason: "consistency_unproven" };
  }
  if (witness.trustBundleGeneration < anchor.trustBundleGeneration) {
    return { action: "QUARANTINE", reason: "trust_bundle_regression" };
  }
  if (witness.trustBundleGeneration > anchor.trustBundleGeneration &&
      !input.witnessTrustBundleExtendsAnchor) {
    return { action: "QUARANTINE", reason: "consistency_unproven" };
  }
  if (local.trustBundleGeneration === anchor.trustBundleGeneration &&
      local.trustBundleDigest !== anchor.trustBundleDigest) {
    return { action: "QUARANTINE", reason: "trust_bundle_conflict" };
  }
  if (anchor.trustBundleGeneration === witness.trustBundleGeneration &&
      anchor.trustBundleDigest !== witness.trustBundleDigest) {
    return { action: "QUARANTINE", reason: "trust_bundle_conflict" };
  }

  if (local.anchorSequence < anchor.anchorSequence) {
    // A local snapshot behind the external anchor can only be repaired forward.
    if (compareProgress(local, anchor) > 0) {
      return { action: "QUARANTINE", reason: "anchor_sequence_conflict" };
    }
  } else if (local.anchorSequence > anchor.anchorSequence) {
    return { action: "QUARANTINE", reason: "local_ahead" };
  } else if (local.anchorRecordDigest !== anchor.anchorRecordDigest) {
    return { action: "QUARANTINE", reason: "anchor_sequence_conflict" };
  }

  if (local.treeSize === anchor.treeSize && local.treeRootHash !== anchor.treeRootHash) {
    return { action: "QUARANTINE", reason: "tree_fork" };
  }
  if (anchor.treeSize === witness.treeSize && anchor.treeRootHash !== witness.treeRootHash) {
    return { action: "QUARANTINE", reason: "tree_fork" };
  }
  if (witness.treeSize < anchor.treeSize) {
    return { action: "QUARANTINE", reason: "witness_rollback" };
  }
  if (local.treeSize > anchor.treeSize ||
      local.trustBundleGeneration > anchor.trustBundleGeneration) {
    return { action: "QUARANTINE", reason: "local_ahead" };
  }

  const uniqueMonitorViews = new Map<string, Set<string>>();
  for (const observation of monitors) {
    const key = JSON.stringify([
      observation.checkpoint.logId,
      observation.checkpoint.treeSize,
      observation.checkpoint.treeRootHash,
    ]);
    const ids = uniqueMonitorViews.get(key) ?? new Set<string>();
    ids.add(observation.monitorId);
    uniqueMonitorViews.set(key, ids);
  }
  if (uniqueMonitorViews.size > 1) {
    return { action: "QUARANTINE", reason: "monitor_disagreement" };
  }
  const agreeing = uniqueMonitorViews.values().next().value as Set<string> | undefined;
  if (!agreeing || agreeing.size < input.requiredMonitorCount) {
    return { action: "QUARANTINE", reason: "insufficient_monitor_agreement" };
  }
  const monitorView = monitors[0]?.checkpoint;
  if (!monitorView || !sameHead(monitorView, witness)) {
    return { action: "QUARANTINE", reason: "monitor_disagreement" };
  }

  if (!sameHead(local, anchor)) {
    if (anchor.treeSize > local.treeSize) {
      return { action: "REPAIR_LOCAL_FORWARD", reason: "anchor_ahead", requiredCheckpoint: anchor };
    }
    return { action: "QUARANTINE", reason: "local_ahead" };
  }

  if (!sameHead(anchor, witness)) {
    if (!input.witnessExtendsAnchor) {
      return { action: "QUARANTINE", reason: "consistency_unproven" };
    }
    return { action: "ADVANCE_ANCHOR", reason: "witness_ahead", requiredCheckpoint: witness };
  }

  return { action: "CONTINUE", reason: "all_views_agree" };
}

export type RootRotationPhase =
  | "OVERLAP_REQUIRED"
  | "SUCCESSOR_BUNDLE_ACCEPTED"
  | "SUCCESSOR_HEAD_ACCEPTED"
  | "OLD_ROOT_REMOVAL_ALLOWED"
  | "BLOCKED";

export function evaluateRootRotation(input: {
  readonly oldRootPinned: boolean;
  readonly successorRootPinned: boolean;
  readonly successorBundleAccepted: boolean;
  readonly successorTreeHeadAccepted: boolean;
  readonly storedPriorHeadVerifiable: boolean;
  readonly emergencyCompromise: boolean;
  readonly independentEmergencyApproval: boolean;
}): RootRotationPhase {
  if (input.emergencyCompromise && !input.independentEmergencyApproval) return "BLOCKED";
  if (!input.oldRootPinned || !input.successorRootPinned) return "BLOCKED";
  if (!input.successorBundleAccepted) return "OVERLAP_REQUIRED";
  if (!input.successorTreeHeadAccepted || !input.storedPriorHeadVerifiable) {
    return "SUCCESSOR_BUNDLE_ACCEPTED";
  }
  return "OLD_ROOT_REMOVAL_ALLOWED";
}
