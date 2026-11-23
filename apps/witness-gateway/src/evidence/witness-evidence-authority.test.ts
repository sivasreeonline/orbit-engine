import canonicalize from "canonicalize";
import { describe, expect, it, vi } from "vitest";
import {
  assertEvidenceAuthorityBundleMatchesRequest,
  issueOrRecoverWitnessEvidence,
  WitnessEvidenceAuthorityAmbiguousCommitError,
  WitnessEvidenceAuthorityOperationConflictError,
  type WitnessEvidenceAuthority,
  type WitnessEvidenceAuthorityBundle,
  type WitnessEvidenceAuthorityRequest,
} from "./witness-evidence-authority";
import type {
  MonitorReplayCheckpointBody,
  WitnessReceiptEnvelope,
  WitnessTreeHeadEnvelope,
  WitnessTrustBundleEnvelope,
} from "../../../api/src/witness/witness-profile-verifier";
import type { WitnessCheckpointScope } from "../provider/witness-provider-adapter";

const scope: WitnessCheckpointScope = {
  trustDomainId: "trust-domain-a",
  witnessId: "witness-a",
  authorityId: "authority-a",
  hostId: "host-a",
};

async function fixture() {
  const checkpointBody: MonitorReplayCheckpointBody = {
    profile: "sky-high-fence-monitor-replay-v1",
    schemaVersion: 1,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    senderId: "monitor-a",
    recipientId: "monitor-b",
    generation: 1,
    operationId: "fence-monitor-replay-evidence-test",
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    previousCheckpointDigest: "0".repeat(64),
    snapshotDigest: "1".repeat(64),
    snapshotByteLength: 128,
    baseStateVersion: 0,
    messageDigest: "2".repeat(64),
  };
  const canonical = canonicalize(checkpointBody);
  if (typeof canonical !== "string") throw new Error("test checkpoint is not canonical JSON");
  const bytes = new TextEncoder().encode(canonical);
  const digestBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const checkpointDigest = [...digestBytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const request: WitnessEvidenceAuthorityRequest = {
    scope,
    checkpointBody,
    canonicalCheckpointBodyBytes: bytes,
    checkpointDigest,
  };
  const receiptEnvelope = {
    body: {
      profile: "sky-high-fence-witness-v1",
      schemaVersion: 1,
      witnessId: scope.witnessId,
      authorityId: scope.authorityId,
      hostId: scope.hostId,
      generation: 1,
      operationId: checkpointBody.operationId,
      checkpointDigest,
      previousCheckpointDigest: checkpointBody.previousCheckpointDigest,
      keyId: "3".repeat(64),
      committedAt: "2026-11-23T00:00:00Z",
      consistencyToken: "opaque-test-metadata",
    },
    signature: "A".repeat(86),
  } as unknown as WitnessReceiptEnvelope;
  const trustBundleEnvelope = {
    body: {
      profile: "sky-high-fence-witness-v1",
      schemaVersion: 1,
      trustDomainId: scope.trustDomainId,
      witnessId: scope.witnessId,
      generation: 1,
      previousBundleDigest: "0".repeat(64),
      keys: [],
      revocations: [],
    },
    bundleDigest: "4".repeat(64),
    rootKeyId: "5".repeat(64),
    rootSignature: "A".repeat(86),
  } as unknown as WitnessTrustBundleEnvelope;
  const treeHeadEnvelope = {
    body: {
      profile: "sky-high-fence-witness-merkle-v1",
      schemaVersion: 1,
      witnessId: scope.witnessId,
      authorityId: scope.authorityId,
      hostId: scope.hostId,
      logId: "log-a",
      treeSize: 1,
      rootHash: "6".repeat(64),
      timestamp: "2026-11-23T00:00:00Z",
      keyId: "7".repeat(64),
    },
    signature: "A".repeat(86),
  } as unknown as WitnessTreeHeadEnvelope;
  const bundle: WitnessEvidenceAuthorityBundle = {
    canonicalCheckpointBodyBytes: bytes,
    checkpointDigest,
    trustBundleEnvelope,
    receiptEnvelope,
    treeHeadEnvelope,
    leafIndex: 0,
    inclusionProofHex: [],
    consistencyProofHex: [],
  };
  return { request, bundle };
}

describe("independent witness evidence authority contract", () => {
  it("requires exact checkpoint bytes, digest, receipt identity and scoped signed-head metadata", async () => {
    const { request, bundle } = await fixture();
    await expect(assertEvidenceAuthorityBundleMatchesRequest(request, bundle)).resolves.toBeUndefined();

    await expect(assertEvidenceAuthorityBundleMatchesRequest(request, {
      ...bundle,
      canonicalCheckpointBodyBytes: new TextEncoder().encode("{}"),
    })).rejects.toBeInstanceOf(WitnessEvidenceAuthorityOperationConflictError);

    await expect(assertEvidenceAuthorityBundleMatchesRequest(request, {
      ...bundle,
      receiptEnvelope: {
        ...bundle.receiptEnvelope,
        body: { ...bundle.receiptEnvelope.body, operationId: "another-operation" },
      },
    })).rejects.toBeInstanceOf(WitnessEvidenceAuthorityOperationConflictError);
  });

  it("recovers an ambiguous issuance acknowledgement by immutable operation lookup", async () => {
    const { request, bundle } = await fixture();
    const authority: WitnessEvidenceAuthority = {
      issueOrRecoverEvidence: vi.fn().mockRejectedValue(
        new WitnessEvidenceAuthorityAmbiguousCommitError(),
      ),
      readEvidenceByOperation: vi.fn().mockResolvedValue(bundle),
    };
    const recovered = await issueOrRecoverWitnessEvidence(authority, request);
    expect(recovered).toBe(bundle);
    expect(authority.issueOrRecoverEvidence).toHaveBeenCalledTimes(1);
    expect(authority.readEvidenceByOperation).toHaveBeenCalledWith(
      scope,
      request.checkpointBody.operationId,
    );
  });

  it("does not recover or accept evidence bound to another operation", async () => {
    const { request, bundle } = await fixture();
    const authority: WitnessEvidenceAuthority = {
      issueOrRecoverEvidence: vi.fn().mockRejectedValue(
        new WitnessEvidenceAuthorityAmbiguousCommitError(),
      ),
      readEvidenceByOperation: vi.fn().mockResolvedValue({
        ...bundle,
        receiptEnvelope: {
          ...bundle.receiptEnvelope,
          body: { ...bundle.receiptEnvelope.body, operationId: "foreign-operation" },
        },
      }),
    };
    await expect(issueOrRecoverWitnessEvidence(authority, request))
      .rejects.toBeInstanceOf(WitnessEvidenceAuthorityOperationConflictError);
  });
});
