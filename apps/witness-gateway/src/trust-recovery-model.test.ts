import { describe, expect, it } from "vitest";
import {
  decideTrustRecovery,
  evaluateRootRotation,
  type MonitorObservation,
  type TrustCheckpoint,
  type TrustRecoveryInput,
} from "./trust-recovery-model";

const d = (character: string) => character.repeat(64);

function checkpoint(overrides: Partial<TrustCheckpoint> = {}): TrustCheckpoint {
  return {
    trustBundleGeneration: 3,
    trustBundleDigest: d("a"),
    logId: "log-1",
    treeSize: 10,
    treeRootHash: d("b"),
    treeHeadDigest: d("c"),
    anchorSequence: 7,
    anchorRecordDigest: d("d"),
    ...overrides,
  };
}

function monitors(view: TrustCheckpoint): MonitorObservation[] {
  return [
    { monitorId: "monitor-east", checkpoint: view },
    { monitorId: "monitor-west", checkpoint: view },
  ];
}

function input(overrides: Partial<TrustRecoveryInput> = {}): TrustRecoveryInput {
  const local = checkpoint();
  return {
    local,
    anchor: checkpoint(),
    witness: checkpoint(),
    monitors: monitors(local),
    requiredMonitorCount: 2,
    witnessExtendsAnchor: false,
    anchorTrustBundleExtendsLocal: false,
    witnessTrustBundleExtendsAnchor: false,
    anchorAvailable: true,
    ...overrides,
  };
}

describe("decideTrustRecovery", () => {
  it("continues only when local, anchor, witness and independent monitors agree", () => {
    expect(decideTrustRecovery(input())).toEqual({
      action: "CONTINUE",
      reason: "all_views_agree",
    });
  });

  it("repairs a restored local snapshot forward to the independent anchor", () => {
    const local = checkpoint({
      treeSize: 5,
      treeRootHash: d("e"),
      treeHeadDigest: d("f"),
      anchorSequence: 6,
      anchorRecordDigest: d("1"),
    });
    const anchor = checkpoint({ anchorSequence: 7 });
    const witness = anchor;
    expect(decideTrustRecovery(input({
      local,
      anchor,
      witness,
      monitors: monitors(witness),
    }))).toMatchObject({
      action: "REPAIR_LOCAL_FORWARD",
      reason: "anchor_ahead",
      requiredCheckpoint: anchor,
    });
  });

  it("repairs a local snapshot after a verified trust-bundle generation advance", () => {
    const local = checkpoint({
      trustBundleGeneration: 2,
      trustBundleDigest: d("e"),
      treeSize: 5,
      treeRootHash: d("f"),
      treeHeadDigest: d("1"),
      anchorSequence: 6,
      anchorRecordDigest: d("2"),
    });
    const anchor = checkpoint({
      trustBundleGeneration: 3,
      trustBundleDigest: d("a"),
      anchorSequence: 7,
    });
    expect(decideTrustRecovery(input({
      local,
      anchor,
      witness: anchor,
      monitors: monitors(anchor),
      anchorTrustBundleExtendsLocal: true,
    }))).toMatchObject({
      action: "REPAIR_LOCAL_FORWARD",
      reason: "anchor_ahead",
      requiredCheckpoint: anchor,
    });
  });

  it("requires a verified root-signed trust-bundle chain before accepting a newer witness bundle", () => {
    const anchor = checkpoint();
    const witness = checkpoint({
      trustBundleGeneration: 4,
      trustBundleDigest: d("e"),
      treeSize: 12,
      treeRootHash: d("f"),
      treeHeadDigest: d("1"),
    });
    expect(decideTrustRecovery(input({
      local: anchor,
      anchor,
      witness,
      monitors: monitors(witness),
      witnessExtendsAnchor: true,
      witnessTrustBundleExtendsAnchor: false,
    }))).toEqual({ action: "QUARANTINE", reason: "consistency_unproven" });
    expect(decideTrustRecovery(input({
      local: anchor,
      anchor,
      witness,
      monitors: monitors(witness),
      witnessExtendsAnchor: true,
      witnessTrustBundleExtendsAnchor: true,
    })).action).toBe("ADVANCE_ANCHOR");
  });

  it("advances the anchor only when the witness head extends it and monitors agree", () => {
    const anchor = checkpoint();
    const witness = checkpoint({
      treeSize: 12,
      treeRootHash: d("e"),
      treeHeadDigest: d("f"),
    });
    expect(decideTrustRecovery(input({
      local: anchor,
      anchor,
      witness,
      monitors: monitors(witness),
      witnessExtendsAnchor: true,
    }))).toMatchObject({
      action: "ADVANCE_ANCHOR",
      reason: "witness_ahead",
      requiredCheckpoint: witness,
    });
  });

  it("quarantines witness rollback", () => {
    const anchor = checkpoint({ treeSize: 12, treeRootHash: d("e") });
    const witness = checkpoint({ treeSize: 10 });
    expect(decideTrustRecovery(input({
      local: anchor,
      anchor,
      witness,
      monitors: monitors(witness),
    }))).toEqual({ action: "QUARANTINE", reason: "witness_rollback" });
  });

  it("quarantines same-size different roots", () => {
    const local = checkpoint();
    const anchor = checkpoint({ treeRootHash: d("e") });
    expect(decideTrustRecovery(input({
      local,
      anchor,
      witness: anchor,
      monitors: monitors(anchor),
    }))).toEqual({ action: "QUARANTINE", reason: "tree_fork" });
  });

  it("quarantines independent monitor disagreement", () => {
    const local = checkpoint();
    const conflicting = checkpoint({ treeRootHash: d("e") });
    expect(decideTrustRecovery(input({
      local,
      anchor: local,
      witness: local,
      monitors: [
        { monitorId: "monitor-east", checkpoint: local },
        { monitorId: "monitor-west", checkpoint: conflicting },
      ],
    }))).toEqual({ action: "QUARANTINE", reason: "monitor_disagreement" });
  });

  it("quarantines a missing or unavailable external anchor", () => {
    expect(decideTrustRecovery(input({
      anchor: null,
      anchorAvailable: false,
    }))).toEqual({ action: "QUARANTINE", reason: "anchor_unavailable" });
  });

  it("quarantines local-ahead state instead of silently advancing the anchor", () => {
    const local = checkpoint({ treeSize: 12, treeRootHash: d("e"), anchorSequence: 8 });
    const anchor = checkpoint();
    expect(decideTrustRecovery(input({
      local,
      anchor,
      witness: local,
      monitors: monitors(local),
    }))).toEqual({ action: "QUARANTINE", reason: "local_ahead" });
  });

  it("requires proof before accepting a witness-ahead head", () => {
    const anchor = checkpoint();
    const witness = checkpoint({ treeSize: 11, treeRootHash: d("e") });
    expect(decideTrustRecovery(input({
      local: anchor,
      anchor,
      witness,
      monitors: monitors(witness),
      witnessExtendsAnchor: false,
    }))).toEqual({ action: "QUARANTINE", reason: "consistency_unproven" });
  });

  it("quarantines when the required number of distinct monitors is not met", () => {
    const view = checkpoint();
    expect(decideTrustRecovery(input({
      local: view,
      anchor: view,
      witness: view,
      monitors: [{ monitorId: "monitor-east", checkpoint: view }],
      requiredMonitorCount: 2,
    }))).toEqual({ action: "QUARANTINE", reason: "insufficient_monitor_agreement" });
  });

  it("quarantines malformed observations", () => {
    const view = checkpoint({ treeRootHash: "not-a-digest" });
    expect(decideTrustRecovery(input({
      local: view,
      anchor: view,
      witness: view,
      monitors: monitors(view),
    }))).toEqual({ action: "QUARANTINE", reason: "invalid_observation" });
  });
});

describe("evaluateRootRotation", () => {
  const safeOverlap = {
    oldRootPinned: true,
    successorRootPinned: true,
    successorBundleAccepted: false,
    successorTreeHeadAccepted: false,
    storedPriorHeadVerifiable: true,
    emergencyCompromise: false,
    independentEmergencyApproval: false,
  };

  it("requires overlap before accepting the successor bundle", () => {
    expect(evaluateRootRotation(safeOverlap)).toBe("OVERLAP_REQUIRED");
  });

  it("does not permit old-root removal before a successor tree head is accepted", () => {
    expect(evaluateRootRotation({
      ...safeOverlap,
      successorBundleAccepted: true,
      successorTreeHeadAccepted: false,
    })).toBe("SUCCESSOR_BUNDLE_ACCEPTED");
  });

  it("permits old-root removal only after successor bundle and head acceptance", () => {
    expect(evaluateRootRotation({
      ...safeOverlap,
      successorBundleAccepted: true,
      successorTreeHeadAccepted: true,
    })).toBe("OLD_ROOT_REMOVAL_ALLOWED");
  });

  it("blocks removal when the stored prior head is no longer verifiable", () => {
    expect(evaluateRootRotation({
      ...safeOverlap,
      successorBundleAccepted: true,
      successorTreeHeadAccepted: true,
      storedPriorHeadVerifiable: false,
    })).toBe("SUCCESSOR_BUNDLE_ACCEPTED");
  });

  it("requires independent approval for emergency compromised-root recovery", () => {
    expect(evaluateRootRotation({
      ...safeOverlap,
      emergencyCompromise: true,
    })).toBe("BLOCKED");
  });
});
