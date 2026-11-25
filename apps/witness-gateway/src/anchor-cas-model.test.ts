import { describe, expect, it } from "vitest";
import {
  EMPTY_ANCHOR_DIGEST,
  evaluateAnchorCompareAndSet,
  type AnchorCasInput,
  type ExternalAnchorRecord,
} from "./anchor-cas-model";

const d = (character: string) => character.repeat(64);

function rejectedReason(decision: ReturnType<typeof evaluateAnchorCompareAndSet>): string | undefined {
  return decision.action === "REJECTED" ? decision.reason : undefined;
}

function record(overrides: Partial<ExternalAnchorRecord> = {}): ExternalAnchorRecord {
  return {
    sequence: 1,
    previousRecordDigest: EMPTY_ANCHOR_DIGEST,
    recordDigest: d("a"),
    operationId: "operation-1",
    requestDigest: d("b"),
    checkpoint: {
      trustBundleGeneration: 3,
      trustBundleDigest: d("c"),
      logId: "log-1",
      treeSize: 10,
      treeRootHash: d("d"),
      treeHeadDigest: d("e"),
    },
    ...overrides,
  };
}

function input(overrides: Partial<AnchorCasInput> = {}): AnchorCasInput {
  return {
    current: null,
    expectedSequence: 0,
    expectedRecordDigest: EMPTY_ANCHOR_DIGEST,
    proposed: record(),
    trustBundleChainVerified: false,
    treeHeadConsistencyVerified: false,
    ...overrides,
  };
}

describe("evaluateAnchorCompareAndSet", () => {
  it("applies the first record against the explicit empty predecessor", () => {
    expect(evaluateAnchorCompareAndSet(input())).toEqual({
      action: "APPLIED",
      record: record(),
    });
  });

  it("recognizes an exact retry after a lost acknowledgement", () => {
    const committed = record();
    expect(evaluateAnchorCompareAndSet(input({
      current: committed,
      proposed: committed,
    }))).toEqual({ action: "ALREADY_APPLIED", record: committed });
  });

  it("rejects reuse of an operation ID with changed request bytes", () => {
    const committed = record();
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      current: committed,
      proposed: record({ requestDigest: d("f"), recordDigest: d("1") }),
    })))).toBe("operation_id_conflict");
  });

  it("recognizes a retry from the immutable operation index after later commits", () => {
    const first = record();
    const second = record({
      sequence: 2,
      previousRecordDigest: first.recordDigest,
      recordDigest: d("2"),
      operationId: "operation-2",
      requestDigest: d("3"),
      checkpoint: { ...first.checkpoint, treeSize: 12, treeRootHash: d("f"), treeHeadDigest: d("1") },
    });
    expect(evaluateAnchorCompareAndSet(input({
      current: second,
      knownOperations: [first, second],
      proposed: first,
    }))).toEqual({ action: "ALREADY_APPLIED", record: first });
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      current: second,
      knownOperations: [first, second],
      proposed: record({ requestDigest: d("f"), recordDigest: d("4") }),
    })))).toBe("operation_id_conflict");
  });

  it("allows only one writer from a shared predecessor", () => {
    const first = record();
    const competing = record({
      recordDigest: d("2"),
      operationId: "operation-2",
      requestDigest: d("3"),
    });
    expect(evaluateAnchorCompareAndSet(input({
      current: first,
      expectedSequence: 0,
      expectedRecordDigest: EMPTY_ANCHOR_DIGEST,
      proposed: competing,
    }))).toEqual({ action: "REJECTED", reason: "stale_predecessor" });
  });

  it("rejects a stale expected digest even when the sequence matches", () => {
    const current = record();
    expect(evaluateAnchorCompareAndSet(input({
      current,
      expectedSequence: 1,
      expectedRecordDigest: d("f"),
      proposed: record({
        sequence: 2,
        previousRecordDigest: current.recordDigest,
        recordDigest: d("2"),
        operationId: "operation-2",
        requestDigest: d("3"),
      }),
    }))).toEqual({ action: "REJECTED", reason: "stale_predecessor" });
  });

  it("rejects predecessor substitution and sequence replay", () => {
    const current = record();
    const next = record({
      sequence: 2,
      previousRecordDigest: d("f"),
      recordDigest: d("2"),
      operationId: "operation-2",
      requestDigest: d("3"),
    });
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      current,
      expectedSequence: 1,
      expectedRecordDigest: current.recordDigest,
      proposed: next,
    })))).toBe("predecessor_mismatch");
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      current,
      expectedSequence: 1,
      expectedRecordDigest: current.recordDigest,
      proposed: { ...next, sequence: 1, previousRecordDigest: current.recordDigest },
    })))).toBe("sequence_mismatch");
  });

  it("requires verified evidence before advancing a tree head or trust bundle", () => {
    const current = record();
    const proposed = record({
      sequence: 2,
      previousRecordDigest: current.recordDigest,
      recordDigest: d("2"),
      operationId: "operation-2",
      requestDigest: d("3"),
      checkpoint: {
        ...current.checkpoint,
        trustBundleGeneration: 4,
        trustBundleDigest: d("f"),
        treeSize: 12,
        treeRootHash: d("1"),
        treeHeadDigest: d("2"),
      },
    });
    const base = {
      current,
      expectedSequence: 1,
      expectedRecordDigest: current.recordDigest,
      proposed,
    };
    expect(rejectedReason(evaluateAnchorCompareAndSet(input(base))))
      .toBe("trust_bundle_chain_unverified");
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      ...base,
      trustBundleChainVerified: true,
    })))).toBe("tree_consistency_unverified");
    expect(evaluateAnchorCompareAndSet(input({
      ...base,
      trustBundleChainVerified: true,
      treeHeadConsistencyVerified: true,
    })).action).toBe("APPLIED");
  });

  it("rejects tree rollback, same-size forks, log changes, and bundle conflicts", () => {
    const current = record();
    const base = {
      current,
      expectedSequence: 1,
      expectedRecordDigest: current.recordDigest,
    };
    const next = (checkpoint: ExternalAnchorRecord["checkpoint"]) => record({
      sequence: 2,
      previousRecordDigest: current.recordDigest,
      recordDigest: d("2"),
      operationId: "operation-2",
      requestDigest: d("3"),
      checkpoint,
    });
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      ...base,
      proposed: next({ ...current.checkpoint, treeSize: 9 }),
    })))).toBe("tree_rollback");
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      ...base,
      proposed: next({ ...current.checkpoint, treeRootHash: d("f") }),
    })))).toBe("tree_fork");
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      ...base,
      proposed: next({ ...current.checkpoint, logId: "other-log" }),
    })))).toBe("log_identity_mismatch");
    expect(rejectedReason(evaluateAnchorCompareAndSet(input({
      ...base,
      proposed: next({ ...current.checkpoint, trustBundleDigest: d("f") }),
    })))).toBe("trust_bundle_conflict");
  });
});
