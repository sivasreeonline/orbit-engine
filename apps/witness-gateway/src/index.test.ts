import { describe, expect, it } from "vitest";
import canonicalize from "canonicalize";
import {
  buildMonitorReplayCheckpoint,
  parseAllowedWitnessScopes,
  parsePinnedWitnessRoots,
  parseTrustedWorkloadKeys,
} from "./index";
import { deriveReplayCheckpointOperationId } from "../../api/src/gossip/gossip-replay-checkpoint-intent";
import type { WitnessCheckpointScope } from "./provider/witness-provider-adapter";

describe("parseTrustedWorkloadKeys", () => {
  it("fails closed when the allowlist is missing or empty", () => {
    expect(parseTrustedWorkloadKeys(undefined)).toBeNull();
    expect(parseTrustedWorkloadKeys("")).toBeNull();
    expect(parseTrustedWorkloadKeys("[]")).toBeNull();
  });

  it("fails closed for malformed JSON and incomplete key records", () => {
    expect(parseTrustedWorkloadKeys("{")).toBeNull();
    expect(parseTrustedWorkloadKeys(JSON.stringify([{ callerId: "api" }]))).toBeNull();
  });

  it("accepts a structurally complete pinned public-key record", () => {
    const record = {
      callerId: "api-worker",
      keyId: "a".repeat(64),
      publicKeyBase64Url: "A".repeat(43),
      audiences: ["sky-high-witness-gateway"],
      scopes: ["witness:authorize"],
      notBefore: 1_700_000_000,
      notAfter: 1_900_000_000
    };
    expect(parseTrustedWorkloadKeys(JSON.stringify([record]))).toEqual([record]);
  });
});
describe("parsePinnedWitnessRoots", () => {
  it("fails closed for missing, empty and malformed root pin configuration", () => {
    expect(parsePinnedWitnessRoots(undefined)).toBeNull();
    expect(parsePinnedWitnessRoots("[]")).toBeNull();
    expect(parsePinnedWitnessRoots("{")).toBeNull();
    expect(parsePinnedWitnessRoots(JSON.stringify([{ keyId: "bad" }]))).toBeNull();
  });

  it("accepts unique pinned Ed25519 root fingerprints", () => {
    const roots = [{
      keyId: "a".repeat(64),
      publicKeyBase64Url: "A".repeat(43),
    }];
    expect(parsePinnedWitnessRoots(JSON.stringify(roots))).toEqual(roots);
  });
});

describe("parseAllowedWitnessScopes", () => {
  it("fails closed when no exact scope allowlist is configured", () => {
    expect(parseAllowedWitnessScopes(undefined)).toBeNull();
    expect(parseAllowedWitnessScopes("[]")).toBeNull();
    expect(parseAllowedWitnessScopes(JSON.stringify([{ witnessId: "w" }]))).toBeNull();
  });

  it("accepts exact trust-domain, witness, authority and host tuples", () => {
    const scopes = [{
      trustDomainId: "trust-domain",
      witnessId: "witness",
      authorityId: "authority",
      hostId: "host",
    }];
    expect(parseAllowedWitnessScopes(JSON.stringify(scopes))).toEqual(scopes);
  });

  it("rejects duplicate scope tuples", () => {
    const scope = {
      trustDomainId: "trust-domain",
      witnessId: "witness",
      authorityId: "authority",
      hostId: "host",
    };
    expect(parseAllowedWitnessScopes(JSON.stringify([scope, scope]))).toBeNull();
  });
});

describe("buildMonitorReplayCheckpoint", () => {
  const scope: WitnessCheckpointScope = {
    trustDomainId: "trust-domain",
    witnessId: "witness",
    authorityId: "authority",
    hostId: "host",
  };
  const predecessor = { generation: 0, digest: "0".repeat(64) };

  async function requestFixture() {
    const snapshot = {
      version: 1,
      senderId: "monitor-a",
      recipientId: "monitor-b",
      highestSequence: 1,
      seenByMessageId: {
        "message-1": { sequence: 1, digest: "a".repeat(64) },
      },
    };
    const snapshotCanonical = canonicalize(snapshot);
    if (typeof snapshotCanonical !== "string") throw new Error("snapshot not canonical");
    const snapshotBytes = new TextEncoder().encode(snapshotCanonical);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", snapshotBytes));
    const snapshotDigest = [...hash].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    const operationId = await deriveReplayCheckpointOperationId({
      scope,
      expectedPredecessor: predecessor,
      snapshotDigest,
    });
    return {
      snapshot,
      input: {
        scope,
        senderId: "monitor-a",
        recipientId: "monitor-b",
        messageDigest: "a".repeat(64),
        baseStateVersion: 0,
        operationId,
        expectedPredecessor: predecessor,
        snapshotDigest,
        snapshotBytes,
      },
    };
  }

  it("constructs a canonical replay checkpoint with a distinct checkpoint digest", async () => {
    const { input } = await requestFixture();
    const built = await buildMonitorReplayCheckpoint(input);
    expect(built.checkpointBody.profile).toBe("sky-high-fence-monitor-replay-v1");
    expect(built.checkpointBody.snapshotDigest).toBe(input.snapshotDigest);
    expect(built.checkpointBody.snapshotByteLength).toBe(input.snapshotBytes.length);
    expect(built.checkpointBody.operationId).toBe(input.operationId);
    expect(built.checkpointDigest).not.toBe(input.snapshotDigest);
    expect(new TextDecoder().decode(built.canonicalCheckpointBodyBytes))
      .toBe(canonicalize(built.checkpointBody));
  });

  it("rejects a triggering message digest absent from the exact snapshot", async () => {
    const { input } = await requestFixture();
    await expect(buildMonitorReplayCheckpoint({
      ...input,
      messageDigest: "b".repeat(64),
    })).rejects.toThrow("triggering message identity");
  });

  it("rejects a sender/recipient relationship that differs from the snapshot", async () => {
    const { input } = await requestFixture();
    await expect(buildMonitorReplayCheckpoint({
      ...input,
      senderId: "another-monitor",
    })).rejects.toThrow("triggering message identity");
  });

  it("rejects a snapshot whose bytes do not match the persisted digest", async () => {
    const { input } = await requestFixture();
    const changedSnapshot = {
      version: 1,
      senderId: input.senderId,
      recipientId: input.recipientId,
      highestSequence: 2,
      seenByMessageId: {
        "message-1": { sequence: 1, digest: input.messageDigest },
      },
    };
    const changedCanonical = canonicalize(changedSnapshot);
    if (typeof changedCanonical !== "string") throw new Error("changed snapshot not canonical");
    const changedBytes = new TextEncoder().encode(changedCanonical);
    await expect(buildMonitorReplayCheckpoint({
      ...input,
      snapshotBytes: changedBytes,
    })).rejects.toThrow("snapshot digest mismatch");
  });
});
