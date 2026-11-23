import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import type { GossipReplaySnapshot } from "../gossip/gossip-replay-state-do";
import {
  buildMonitorReplayCheckpointArtifact,
  canonicalReplaySnapshotBytes,
  MONITOR_REPLAY_ZERO_DIGEST,
  type MonitorReplayTrustScope,
} from "./monitor-replay-checkpoint";

const scope: MonitorReplayTrustScope = {
  trustDomainId: "monitor-trust-domain",
  witnessId: "monitor-witness",
  authorityId: "monitor-authority",
  hostId: "monitor-host",
  senderId: "monitor-a",
  recipientId: "monitor-b",
  replayScope: "monitor-domain|monitor-witness|monitor-authority|monitor-host",
};

function snapshot(): GossipReplaySnapshot {
  return {
    version: 1,
    senderId: "monitor-a",
    recipientId: "monitor-b",
    scope: "monitor-domain|monitor-witness|monitor-authority|monitor-host",
    highestSequence: 4,
    seenBySequence: {
      "2": { messageId: "message-2", digest: "2".repeat(64) },
      "4": { messageId: "message-4", digest: "4".repeat(64) },
    },
    seenByMessageId: {
      "message-2": { sequence: 2, digest: "2".repeat(64) },
      "message-4": { sequence: 4, digest: "4".repeat(64) },
    },
    outstandingRequests: {
      "message-4": { nonce: "nonce-4", expiresAt: 1_900_000_000 },
    },
    consumedNonces: ["nonce-z", "nonce-a"],
    missingSequences: [3, 1],
  };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function digest(bytes: Uint8Array): Promise<string> {
  const value = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes)));
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("monitor replay checkpoint artifact mapping", () => {
  it("binds the complete normalized replay snapshot into the existing checkpoint profile", async () => {
    const current = snapshot();
    const artifact = await buildMonitorReplayCheckpointArtifact(
      current,
      scope,
      1,
      MONITOR_REPLAY_ZERO_DIGEST,
    );

    expect(artifact.snapshotDigest).toBe(await digest(artifact.canonicalSnapshotBytes));
    // Shared Python/TypeScript conformance vector for the same RFC 8785 bytes.
    expect(artifact.snapshotDigest).toBe("3e67d5db1c0f34ddd48fd964ef7b3993ee395f3fd166010ebd74076594dba7cb");
    expect(artifact.operationId).toBe(`fence-monitor-replay-${artifact.snapshotDigest}`);
    expect(artifact.checkpointBody).toMatchObject({
      profile: "sky-high-fence-witness-v1",
      schemaVersion: 1,
      authorityId: scope.authorityId,
      hostId: scope.hostId,
      generation: 1,
      phase: "ACCEPTED",
      operationId: artifact.operationId,
      previousCheckpointDigest: MONITOR_REPLAY_ZERO_DIGEST,
      authorityStateDigest: artifact.snapshotDigest,
      epoch: 4,
      recordVersion: 1,
    });
    expect(artifact.checkpointBody.responseDigest).toBe("6f6d145824a1186726d43b65ff6edff79631be9e088f33e655386d3c1b189a5d");
    expect(artifact.canonicalCheckpointBodyBytes).toEqual(
      new TextEncoder().encode(canonicalize(artifact.checkpointBody)!),
    );
    expect(artifact.checkpointDigest).toBe(await digest(
      artifact.canonicalCheckpointBodyBytes,
    ));
    expect(artifact.checkpointDigest).toBe("c9db31c134f4e476758bca6860ce8dd4567691fae04a78dc18814cf9e1426ce2");
    expect(artifact.checkpointDigest).not.toBe(artifact.snapshotDigest);
    expect(artifact.providerCheckpoint).toMatchObject({
      generation: 1,
      operationId: artifact.operationId,
      phase: "MONITOR_GOSSIP_REPLAY_V1",
      checkpointDigest: artifact.checkpointDigest,
      previousDigest: MONITOR_REPLAY_ZERO_DIGEST,
      snapshotDigest: artifact.snapshotDigest,
    });
  });

  it("normalizes set-like arrays so equivalent replay states have identical bytes", async () => {
    const left = snapshot();
    const right = {
      ...snapshot(),
      consumedNonces: ["nonce-a", "nonce-z"],
      missingSequences: [1, 3],
    };
    expect(canonicalReplaySnapshotBytes(left, scope)).toEqual(
      canonicalReplaySnapshotBytes(right, scope),
    );
    const first = await buildMonitorReplayCheckpointArtifact(left, scope, 1, MONITOR_REPLAY_ZERO_DIGEST);
    const second = await buildMonitorReplayCheckpointArtifact(right, scope, 1, MONITOR_REPLAY_ZERO_DIGEST);
    expect(second.snapshotDigest).toBe(first.snapshotDigest);
    expect(second.checkpointDigest).toBe(first.checkpointDigest);
  });

  it("changes both snapshot and artifact digests when replay evidence changes", async () => {
    const first = await buildMonitorReplayCheckpointArtifact(snapshot(), scope, 1, MONITOR_REPLAY_ZERO_DIGEST);
    const original = snapshot();
    const changed: GossipReplaySnapshot = {
      ...original,
      seenBySequence: {
        ...original.seenBySequence,
        "4": { messageId: "message-4", digest: "f".repeat(64) },
      },
      seenByMessageId: {
        ...original.seenByMessageId,
        "message-4": { sequence: 4, digest: "f".repeat(64) },
      },
    };
    const second = await buildMonitorReplayCheckpointArtifact(changed, scope, 1, MONITOR_REPLAY_ZERO_DIGEST);
    expect(second.snapshotDigest).not.toBe(first.snapshotDigest);
    expect(second.checkpointDigest).not.toBe(first.checkpointDigest);
  });

  it("rejects relationship substitution, inconsistent indexes and unknown fields", async () => {
    expect(() => canonicalReplaySnapshotBytes(snapshot(), {
      ...scope,
      senderId: "attacker",
    })).toThrow("relationship binding");

    const original = snapshot();
    const inconsistent: GossipReplaySnapshot = {
      ...original,
      seenByMessageId: {
        ...original.seenByMessageId,
        "message-4": {
          sequence: 3,
          digest: "4".repeat(64),
        },
      },
    };
    await expect(buildMonitorReplayCheckpointArtifact(
      inconsistent,
      scope,
      1,
      MONITOR_REPLAY_ZERO_DIGEST,
    )).rejects.toThrow();

    const extra = { ...snapshot(), unrecognized: true } as GossipReplaySnapshot;
    expect(() => canonicalReplaySnapshotBytes(extra, scope)).toThrow("unexpected shape");
  });

  it("requires exact next-generation metadata and a valid predecessor digest", async () => {
    await expect(buildMonitorReplayCheckpointArtifact(
      snapshot(), scope, 0, MONITOR_REPLAY_ZERO_DIGEST,
    )).rejects.toThrow("generation or trust scope");
    await expect(buildMonitorReplayCheckpointArtifact(
      snapshot(), scope, 2, "not-a-digest",
    )).rejects.toThrow("generation or trust scope");
    const first = await buildMonitorReplayCheckpointArtifact(snapshot(), scope, 1, MONITOR_REPLAY_ZERO_DIGEST);
    const second = await buildMonitorReplayCheckpointArtifact(snapshot(), scope, 2, first.checkpointDigest);
    expect(second.checkpointBody.generation).toBe(2);
    expect(second.checkpointBody.previousCheckpointDigest).toBe(first.checkpointDigest);
  });
});
