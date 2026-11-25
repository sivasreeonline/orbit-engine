/**
 * Pure reference model for an external trust-anchor compare-and-set.
 *
 * This module is intentionally non-persistent. It does not authenticate a
 * writer, hash/sign records, verify proofs, or contact an independent anchor.
 * Callers must verify those inputs before using this decision function.
 */
export const EMPTY_ANCHOR_DIGEST = "0".repeat(64);

export interface AnchorCheckpoint {
  readonly trustBundleGeneration: number;
  readonly trustBundleDigest: string;
  readonly logId: string;
  readonly treeSize: number;
  readonly treeRootHash: string;
  readonly treeHeadDigest: string;
}

export interface ExternalAnchorRecord {
  readonly sequence: number;
  readonly previousRecordDigest: string;
  readonly recordDigest: string;
  readonly operationId: string;
  /** Digest of the complete canonical request, including the proposed checkpoint. */
  readonly requestDigest: string;
  readonly checkpoint: AnchorCheckpoint;
}

export interface AnchorCasInput {
  readonly current: ExternalAnchorRecord | null;
  readonly expectedSequence: number;
  readonly expectedRecordDigest: string;
  readonly proposed: ExternalAnchorRecord;
  /** Set only after verifying the root-signed bundle chain, when generation advances. */
  readonly trustBundleChainVerified: boolean;
  /** Set only after verifying the Merkle consistency proof, when tree size advances. */
  readonly treeHeadConsistencyVerified: boolean;
}

export type AnchorCasDecision =
  | { readonly action: "APPLIED"; readonly record: ExternalAnchorRecord }
  | { readonly action: "ALREADY_APPLIED"; readonly record: ExternalAnchorRecord }
  | { readonly action: "REJECTED"; readonly reason:
      | "invalid_record"
      | "operation_id_conflict"
      | "stale_predecessor"
      | "sequence_mismatch"
      | "predecessor_mismatch"
      | "log_identity_mismatch"
      | "trust_bundle_regression"
      | "trust_bundle_conflict"
      | "tree_rollback"
      | "tree_fork"
      | "trust_bundle_chain_unverified"
      | "tree_consistency_unverified" };

const DIGEST = /^[0-9a-f]{64}$/;

function validCheckpoint(value: AnchorCheckpoint): boolean {
  return Number.isSafeInteger(value.trustBundleGeneration) &&
    value.trustBundleGeneration >= 0 &&
    DIGEST.test(value.trustBundleDigest) &&
    value.logId.length > 0 &&
    Number.isSafeInteger(value.treeSize) && value.treeSize >= 0 &&
    DIGEST.test(value.treeRootHash) &&
    DIGEST.test(value.treeHeadDigest);
}

function validRecord(value: ExternalAnchorRecord): boolean {
  return Number.isSafeInteger(value.sequence) && value.sequence > 0 &&
    DIGEST.test(value.previousRecordDigest) &&
    DIGEST.test(value.recordDigest) &&
    DIGEST.test(value.requestDigest) &&
    value.operationId.length > 0 &&
    validCheckpoint(value.checkpoint);
}

function sameRecord(a: ExternalAnchorRecord, b: ExternalAnchorRecord): boolean {
  return a.sequence === b.sequence &&
    a.previousRecordDigest === b.previousRecordDigest &&
    a.recordDigest === b.recordDigest &&
    a.operationId === b.operationId &&
    a.requestDigest === b.requestDigest &&
    a.checkpoint.trustBundleGeneration === b.checkpoint.trustBundleGeneration &&
    a.checkpoint.trustBundleDigest === b.checkpoint.trustBundleDigest &&
    a.checkpoint.logId === b.checkpoint.logId &&
    a.checkpoint.treeSize === b.checkpoint.treeSize &&
    a.checkpoint.treeRootHash === b.checkpoint.treeRootHash &&
    a.checkpoint.treeHeadDigest === b.checkpoint.treeHeadDigest;
}

/**
 * Decide whether a proposal can replace the current anchor record.
 *
 * An exact retry is recognized before predecessor CAS validation so a writer
 * can safely recover after the anchor committed but its acknowledgement was
 * lost. Reuse of an operation ID with different bytes is always rejected.
 */
export function evaluateAnchorCompareAndSet(input: AnchorCasInput): AnchorCasDecision {
  const { current, proposed } = input;
  if (!validRecord(proposed) || (current !== null && !validRecord(current)) ||
      !Number.isSafeInteger(input.expectedSequence) || input.expectedSequence < 0 ||
      !DIGEST.test(input.expectedRecordDigest)) {
    return { action: "REJECTED", reason: "invalid_record" };
  }

  if (current?.operationId === proposed.operationId) {
    return sameRecord(current, proposed)
      ? { action: "ALREADY_APPLIED", record: current }
      : { action: "REJECTED", reason: "operation_id_conflict" };
  }

  const currentSequence = current?.sequence ?? 0;
  const currentDigest = current?.recordDigest ?? EMPTY_ANCHOR_DIGEST;
  if (input.expectedSequence !== currentSequence ||
      input.expectedRecordDigest !== currentDigest) {
    return { action: "REJECTED", reason: "stale_predecessor" };
  }
  if (proposed.sequence !== currentSequence + 1) {
    return { action: "REJECTED", reason: "sequence_mismatch" };
  }
  if (proposed.previousRecordDigest !== currentDigest) {
    return { action: "REJECTED", reason: "predecessor_mismatch" };
  }

  if (current) {
    const before = current.checkpoint;
    const after = proposed.checkpoint;
    if (after.logId !== before.logId) {
      return { action: "REJECTED", reason: "log_identity_mismatch" };
    }
    if (after.trustBundleGeneration < before.trustBundleGeneration) {
      return { action: "REJECTED", reason: "trust_bundle_regression" };
    }
    if (after.trustBundleGeneration === before.trustBundleGeneration &&
        after.trustBundleDigest !== before.trustBundleDigest) {
      return { action: "REJECTED", reason: "trust_bundle_conflict" };
    }
    if (after.treeSize < before.treeSize) {
      return { action: "REJECTED", reason: "tree_rollback" };
    }
    if (after.treeSize === before.treeSize &&
        after.treeRootHash !== before.treeRootHash) {
      return { action: "REJECTED", reason: "tree_fork" };
    }
    if (after.trustBundleGeneration > before.trustBundleGeneration &&
        !input.trustBundleChainVerified) {
      return { action: "REJECTED", reason: "trust_bundle_chain_unverified" };
    }
    if (after.treeSize > before.treeSize &&
        !input.treeHeadConsistencyVerified) {
      return { action: "REJECTED", reason: "tree_consistency_unverified" };
    }
  }

  return { action: "APPLIED", record: proposed };
}
