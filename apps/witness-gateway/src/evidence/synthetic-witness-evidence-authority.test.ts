import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import { issueOrRecoverWitnessEvidence } from "./witness-evidence-authority";
import {
  SyntheticWitnessEvidenceAuthority,
} from "../../test-support/synthetic-witness-evidence-authority";
import type { WitnessEvidenceAuthorityRequest } from "./witness-evidence-authority";

const scope = {
  trustDomainId: "synthetic-trust-domain",
  witnessId: "synthetic-witness",
  authorityId: "synthetic-authority",
  hostId: "synthetic-host",
};

async function requestFixture(
  generation = 1,
  previousCheckpointDigest = "0".repeat(64),
): Promise<WitnessEvidenceAuthorityRequest> {
  const checkpointBody = {
    profile: "sky-high-fence-monitor-replay-v1" as const,
    schemaVersion: 1 as const,
    trustDomainId: scope.trustDomainId,
    witnessId: scope.witnessId,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    senderId: "monitor-sender",
    recipientId: "monitor-recipient",
    generation,
    operationId: `synthetic-evidence-operation-00${generation}`,
    phase: "MONITOR_GOSSIP_REPLAY_V1" as const,
    previousCheckpointDigest,
    snapshotDigest: "1".repeat(64),
    snapshotByteLength: 64,
    baseStateVersion: 0,
    messageDigest: "2".repeat(64),
  };
  const serialized = canonicalize(checkpointBody);
  if (typeof serialized !== "string") throw new Error("checkpoint body is not canonical");
  const canonicalCheckpointBodyBytes = new TextEncoder().encode(serialized);
  const checkpointDigest = [...new Uint8Array(
    await crypto.subtle.digest("SHA-256", canonicalCheckpointBodyBytes),
  )].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return {
    scope,
    checkpointBody,
    canonicalCheckpointBodyBytes,
    checkpointDigest,
  };
}

describe("synthetic independent evidence authority", () => {
  it("issues ephemeral signed trust, receipt and Merkle evidence accepted by the production verifier", async () => {
    const request = await requestFixture();
    const authority = new SyntheticWitnessEvidenceAuthority();
    const bundle = await authority.issueOrRecoverEvidence(request);

    await expect(authority.verifyIssuedBundle(request, bundle)).resolves.toBeUndefined();
    expect(bundle.trustBundleEnvelope.body.generation).toBe(1);
    expect(bundle.receiptEnvelope.body.checkpointDigest).toBe(request.checkpointDigest);
    expect(bundle.treeHeadEnvelope.body.treeSize).toBe(1);
    expect(bundle.leafIndex).toBe(0);
    expect(bundle.inclusionProofHex).toEqual([]);
    expect(bundle.consistencyProofHex).toEqual([]);
  });

  it("exports only the matching ephemeral public root pin for gateway test configuration", async () => {
    const request = await requestFixture();
    const authority = new SyntheticWitnessEvidenceAuthority();
    const pin = await authority.getPinnedRootKey();
    const bundle = await authority.issueOrRecoverEvidence(request);

    expect(pin.keyId).toBe(bundle.trustBundleEnvelope.rootKeyId);
    expect(pin.publicKeyBase64Url).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pin).not.toHaveProperty("privateKey");
    expect(await authority.getPinnedRootKey()).toEqual(pin);

    const independentAuthority = new SyntheticWitnessEvidenceAuthority();
    expect((await independentAuthority.getPinnedRootKey()).keyId).not.toBe(pin.keyId);
  });

  it("is idempotent by exact scope and operation, and rejects rebinding", async () => {
    const request = await requestFixture();
    const authority = new SyntheticWitnessEvidenceAuthority();
    const first = await authority.issueOrRecoverEvidence(request);
    const retry = await authority.issueOrRecoverEvidence(request);
    expect(retry).toBe(first);

    await expect(authority.issueOrRecoverEvidence({
      ...request,
      checkpointDigest: "f".repeat(64),
    })).rejects.toThrow("different checkpoint bytes");
  });

  it("recovers a committed evidence bundle after a lost acknowledgement", async () => {
    const request = await requestFixture();
    const authority = new SyntheticWitnessEvidenceAuthority();
    let firstCall = true;
    const flaky = {
      issueOrRecoverEvidence: async (input: WitnessEvidenceAuthorityRequest) => {
        const bundle = await authority.issueOrRecoverEvidence(input);
        if (firstCall) {
          firstCall = false;
          throw new Error("synthetic lost acknowledgement");
        }
        return bundle;
      },
      readEvidenceByOperation: authority.readEvidenceByOperation.bind(authority),
    };
    const recovered = await issueOrRecoverWitnessEvidence(flaky, request);
    await expect(authority.verifyIssuedBundle(request, recovered)).resolves.toBeUndefined();
  });
  it("publishes multi-leaf inclusion and consistency proofs across checkpoint generations", async () => {
    const authority = new SyntheticWitnessEvidenceAuthority();
    const firstRequest = await requestFixture();
    const firstBundle = await authority.issueOrRecoverEvidence(firstRequest);
    const secondRequest = await requestFixture(2, firstRequest.checkpointDigest);
    const secondBundle = await authority.issueOrRecoverEvidence(secondRequest);

    expect(secondBundle.treeHeadEnvelope.body.treeSize).toBe(2);
    expect(secondBundle.leafIndex).toBe(1);
    expect(secondBundle.inclusionProofHex).toHaveLength(1);
    expect(secondBundle.consistencyProofHex.length).toBeGreaterThan(0);
    await expect(authority.verifyIssuedBundle(secondRequest, secondBundle)).resolves.toBeUndefined();
    await expect(authority.verifyIssuedBundleExtension(firstBundle, secondBundle)).resolves.toBeUndefined();
  });

});
