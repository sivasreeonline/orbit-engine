import { describe, expect, it } from "vitest";
import type { GossipReplaySnapshot } from "../../api/src/gossip/gossip-replay-state-do";
import type {
  WitnessReceiptEnvelope,
  WitnessTreeHeadEnvelope,
  WitnessTrustBundleEnvelope,
} from "../../api/src/witness/witness-profile-verifier";
import type { MonitorReplayTrustScope } from "../../api/src/witness/monitor-replay-checkpoint";
import {
  checkpointMonitorReplaySnapshot,
  WitnessProviderAmbiguousCommitError,
  WitnessProviderAppendConflictError,
  WitnessProviderIntegrityError,
  type WitnessProviderAdapter,
  type WitnessProviderCheckpointRecord,
  type WitnessProviderRecord,
  type VerifyWitnessProviderRecord,
} from "./witness-provider-coordinator";

const scope: MonitorReplayTrustScope = {
  trustDomainId: "provider-test-domain",
  witnessId: "provider-test-witness",
  authorityId: "provider-test-authority",
  hostId: "provider-test-host",
  senderId: "provider-sender",
  recipientId: "provider-recipient",
  replayScope: "provider-replay-scope",
};

function replaySnapshot(): GossipReplaySnapshot {
  return {
    version: 1,
    senderId: scope.senderId,
    recipientId: scope.recipientId,
    scope: scope.replayScope,
    highestSequence: 2,
    seenBySequence: {
      "1": { messageId: "message-1", digest: "1".repeat(64) },
      "2": { messageId: "message-2", digest: "2".repeat(64) },
    },
    seenByMessageId: {
      "message-1": { sequence: 1, digest: "1".repeat(64) },
      "message-2": { sequence: 2, digest: "2".repeat(64) },
    },
    outstandingRequests: {},
    consumedNonces: ["nonce-b", "nonce-a"],
    missingSequences: [],
  };
}

function scopeKey(value: MonitorReplayTrustScope): string {
  return JSON.stringify([
    value.trustDomainId,
    value.witnessId,
    value.authorityId,
    value.hostId,
    value.senderId,
    value.recipientId,
    value.replayScope,
  ]);
}

class InMemoryWitnessProvider implements WitnessProviderAdapter {
  readonly operations = new Map<string, WitnessProviderRecord>();
  readonly latest = new Map<string, WitnessProviderRecord>();
  appendCount = 0;
  loseNextAcknowledgement = false;
  rejectNextAppend = false;
  corruptNextReceipt = false;

  async appendIfCurrent(
    checkpoint: WitnessProviderCheckpointRecord,
    expectedGeneration: number,
    expectedDigest: string,
    idempotencyKey: string,
  ): Promise<WitnessReceiptEnvelope> {
    this.appendCount += 1;
    if (this.rejectNextAppend) {
      this.rejectNextAppend = false;
      throw new WitnessProviderAppendConflictError();
    }
    if (idempotencyKey !== checkpoint.operationId) {
      throw new Error("idempotency key must equal deterministic operation ID");
    }

    const operationKey = `${scopeKey({
      trustDomainId: checkpoint.scope.trustDomainId,
      witnessId: checkpoint.scope.witnessId,
      authorityId: checkpoint.scope.authorityId,
      hostId: checkpoint.scope.hostId,
      senderId: checkpoint.scope.senderId,
      recipientId: checkpoint.scope.recipientId,
      replayScope: checkpoint.scope.replayScope,
    })}:${idempotencyKey}`;
    const existing = this.operations.get(operationKey);
    if (existing) {
      if (existing.checkpoint.checkpointDigest !== checkpoint.checkpointDigest) {
        throw new WitnessProviderAppendConflictError("idempotency key reused with different checkpoint bytes");
      }
      return existing.receiptEnvelope;
    }

    const key = scopeKey({
      trustDomainId: checkpoint.scope.trustDomainId,
      witnessId: checkpoint.scope.witnessId,
      authorityId: checkpoint.scope.authorityId,
      hostId: checkpoint.scope.hostId,
      senderId: checkpoint.scope.senderId,
      recipientId: checkpoint.scope.recipientId,
      replayScope: checkpoint.scope.replayScope,
    });
    const current = this.latest.get(key);
    const currentGeneration = current?.checkpoint.generation ?? 0;
    const currentDigest = current?.checkpoint.checkpointDigest ?? "0".repeat(64);
    if (
      currentGeneration !== expectedGeneration ||
      currentDigest !== expectedDigest ||
      checkpoint.generation !== expectedGeneration + 1 ||
      checkpoint.previousDigest !== expectedDigest
    ) throw new WitnessProviderAppendConflictError("expected predecessor is stale");

    const receiptEnvelope: WitnessReceiptEnvelope = {
      body: {
        profile: "sky-high-fence-witness-v1",
        schemaVersion: 1,
        witnessId: checkpoint.scope.witnessId,
        authorityId: checkpoint.scope.authorityId,
        hostId: checkpoint.scope.hostId,
        generation: checkpoint.generation,
        operationId: checkpoint.operationId,
        checkpointDigest: checkpoint.checkpointDigest,
        previousCheckpointDigest: checkpoint.previousDigest,
        keyId: "a".repeat(64),
        committedAt: "2026-11-23T08:00:00Z",
        consistencyToken: `synthetic-token-${checkpoint.generation}`,
      },
      signature: "A".repeat(86),
    };
    const record: WitnessProviderRecord = {
      checkpoint,
      receiptEnvelope: this.corruptNextReceipt
        ? {
            ...receiptEnvelope,
            body: { ...receiptEnvelope.body, checkpointDigest: "f".repeat(64) },
          }
        : receiptEnvelope,
      trustBundleEnvelope: {
        body: {
          profile: "sky-high-fence-witness-v1",
          schemaVersion: 1,
          trustDomainId: checkpoint.scope.trustDomainId,
          witnessId: checkpoint.scope.witnessId,
          generation: 1,
          previousBundleDigest: "0".repeat(64),
          keys: [],
          revocations: [],
        },
        bundleDigest: "b".repeat(64),
        rootKeyId: "c".repeat(64),
        rootSignature: "A".repeat(86),
      } as unknown as WitnessTrustBundleEnvelope,
      treeHeadEnvelope: {
        body: {
          profile: "sky-high-fence-witness-merkle-v1",
          schemaVersion: 1,
          witnessId: checkpoint.scope.witnessId,
          authorityId: checkpoint.scope.authorityId,
          hostId: checkpoint.scope.hostId,
          logId: "synthetic-provider-log",
          treeSize: checkpoint.generation,
          rootHash: "d".repeat(64),
          timestamp: "2026-11-23T08:00:00Z",
          keyId: "e".repeat(64),
        },
        signature: "A".repeat(86),
      } as unknown as WitnessTreeHeadEnvelope,
      leafIndex: 0,
      inclusionProofHex: [],
      consistencyProofHex: [],
    };
    this.operations.set(operationKey, record);
    this.latest.set(key, record);
    if (this.loseNextAcknowledgement) {
      this.loseNextAcknowledgement = false;
      throw new WitnessProviderAmbiguousCommitError();
    }
    return record.receiptEnvelope;
  }

  async readByOperation(
    value: MonitorReplayTrustScope,
    operationId: string,
  ): Promise<WitnessProviderRecord | null> {
    return this.operations.get(`${scopeKey(value)}:${operationId}`) ?? null;
  }

  async readLatest(value: MonitorReplayTrustScope): Promise<WitnessProviderRecord | null> {
    return this.latest.get(scopeKey(value)) ?? null;
  }
}

const verifySyntheticRecord: VerifyWitnessProviderRecord = async (record) => {
  if (
    record.receiptEnvelope.signature !== "A".repeat(86) ||
    record.receiptEnvelope.body.consistencyToken.length === 0
  ) throw new WitnessProviderIntegrityError("synthetic receipt verification failed");
};

describe("provider-neutral monitor replay checkpoint coordinator", () => {
  it("performs atomic append, immutable operation lookup and strong latest readback", async () => {
    const provider = new InMemoryWitnessProvider();
    const snapshot = replaySnapshot();
    const first = await checkpointMonitorReplaySnapshot(
      provider, snapshot, scope, verifySyntheticRecord,
    );
    expect(first).toMatchObject({
      status: "CHECKPOINTED",
      generation: 1,
      snapshotDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      checkpointDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(provider.appendCount).toBe(1);

    const retry = await checkpointMonitorReplaySnapshot(
      provider, snapshot, scope, verifySyntheticRecord,
    );
    expect(retry).toMatchObject({
      status: "ALREADY_CHECKPOINTED",
      generation: 1,
      operationId: first.operationId,
      checkpointDigest: first.checkpointDigest,
    });
    expect(provider.appendCount).toBe(1);
  });

  it("chains the next artifact to the prior checkpoint artifact digest", async () => {
    const provider = new InMemoryWitnessProvider();
    const firstSnapshot = replaySnapshot();
    const first = await checkpointMonitorReplaySnapshot(
      provider, firstSnapshot, scope, verifySyntheticRecord,
    );
    const original = replaySnapshot();
    const secondSnapshot: GossipReplaySnapshot = {
      ...original,
      highestSequence: 3,
      seenBySequence: {
        ...original.seenBySequence,
        "3": { messageId: "message-3", digest: "3".repeat(64) },
      },
      seenByMessageId: {
        ...original.seenByMessageId,
        "message-3": { sequence: 3, digest: "3".repeat(64) },
      },
    };
    const second = await checkpointMonitorReplaySnapshot(
      provider, secondSnapshot, scope, verifySyntheticRecord,
    );
    expect(second).toMatchObject({ status: "CHECKPOINTED", generation: 2 });
    const latest = await provider.readLatest(scope);
    expect(latest?.checkpoint.previousDigest).toBe(first.checkpointDigest);
    expect(latest?.checkpoint.snapshotDigest).toBe(second.snapshotDigest);
  });

  it("recovers an ambiguous append acknowledgement by immutable operation lookup", async () => {
    const provider = new InMemoryWitnessProvider();
    provider.loseNextAcknowledgement = true;
    const result = await checkpointMonitorReplaySnapshot(
      provider, replaySnapshot(), scope, verifySyntheticRecord,
    );
    expect(result.status).toBe("CHECKPOINTED");
    expect(result.generation).toBe(1);
    expect(provider.appendCount).toBe(1);
  });

  it("rejects a previously committed operation when it is no longer the current head", async () => {
    const provider = new InMemoryWitnessProvider();
    const first = replaySnapshot();
    await checkpointMonitorReplaySnapshot(provider, first, scope, verifySyntheticRecord);
    const original = replaySnapshot();
    const second: GossipReplaySnapshot = {
      ...original,
      highestSequence: 3,
      seenBySequence: {
        ...original.seenBySequence,
        "3": { messageId: "message-3", digest: "3".repeat(64) },
      },
      seenByMessageId: {
        ...original.seenByMessageId,
        "message-3": { sequence: 3, digest: "3".repeat(64) },
      },
    };
    await checkpointMonitorReplaySnapshot(provider, second, scope, verifySyntheticRecord);
    await expect(checkpointMonitorReplaySnapshot(
      provider, first, scope, verifySyntheticRecord,
    )).rejects.toThrow("no longer the current witness head");
  });

  it("fails closed on provider conflicts and corrupt receipt readback", async () => {
    const conflictProvider = new InMemoryWitnessProvider();
    conflictProvider.rejectNextAppend = true;
    await expect(checkpointMonitorReplaySnapshot(
      conflictProvider, replaySnapshot(), scope, verifySyntheticRecord,
    )).rejects.toBeInstanceOf(WitnessProviderAppendConflictError);

    const corruptProvider = new InMemoryWitnessProvider();
    corruptProvider.corruptNextReceipt = true;
    await expect(checkpointMonitorReplaySnapshot(
      corruptProvider, replaySnapshot(), scope, verifySyntheticRecord,
    )).rejects.toThrow("provider receipt does not bind");
  });
});
