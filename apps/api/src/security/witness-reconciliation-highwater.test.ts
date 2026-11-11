import { describe, expect, it } from "vitest";
import {
  AppendCheckpointInput,
  AppendCheckpointResult,
  ExternalWitnessAdapter,
  WitnessCheckpoint,
  WitnessRecord,
  WitnessScope,
  ZERO_CHECKPOINT_DIGEST,
} from "./external-witness-adapter";
import { anchorCheckpoint } from "./witness-reconciliation";

const scope: WitnessScope = { authorityId: "authority-test", hostId: "host-test" };
const witnessId = "witness-test";

function record(checkpoint: WitnessCheckpoint): WitnessRecord {
  return {
    checkpoint,
    receipt: {
      schemaVersion: 1,
      witnessId,
      authorityId: checkpoint.authorityId,
      hostId: checkpoint.hostId,
      generation: checkpoint.generation,
      operationId: checkpoint.operationId,
      checkpointDigest: checkpoint.checkpointDigest,
      previousCheckpointDigest: checkpoint.previousCheckpointDigest,
      keyId: "test-key",
      signature: "test-signature",
      committedAt: "2026-11-11T00:00:00.000Z",
      consistencyToken: `generation-${checkpoint.generation}`,
    },
  };
}

function issuedCheckpoint(): WitnessCheckpoint {
  return {
    schemaVersion: 1,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    generation: 1,
    phase: "ISSUED",
    operationId: "issue-1",
    previousCheckpointDigest: ZERO_CHECKPOINT_DIGEST,
    checkpointDigest: "a".repeat(64),
    authorityStateDigest: "b".repeat(64),
    responseDigest: "c".repeat(64),
    epoch: 10,
    recordVersion: 1,
  };
}

describe("witness operation replay high-water enforcement", () => {
  it("rejects an operation-index hit when a later checkpoint is now high-water", async () => {
    const issued = issuedCheckpoint();
    const accepted: WitnessCheckpoint = {
      ...issued,
      generation: 2,
      phase: "ACCEPTED",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      recordVersion: 2,
    };
    const historicalRecord = record(issued);
    const latestRecord = record(accepted);
    const adapter: ExternalWitnessAdapter = {
      appendCheckpoint: async (_input: AppendCheckpointInput): Promise<AppendCheckpointResult> => {
        throw new Error("append must not be called for an existing operation");
      },
      readLatest: async () => latestRecord,
      readByOperation: async (_scope, operationId, phase) =>
        operationId === issued.operationId && phase === issued.phase ? historicalRecord : null,
    };

    await expect(anchorCheckpoint(adapter, { verify: async () => true }, {
      expectedGeneration: 0,
      expectedCheckpointDigest: ZERO_CHECKPOINT_DIGEST,
      checkpoint: issued,
      expectedWitnessId: witnessId,
    })).rejects.toThrow("different checkpoint");
  });

  it("rejects an operation-index hit when the latest checkpoint is missing", async () => {
    const issued = issuedCheckpoint();
    const historicalRecord = record(issued);
    const adapter: ExternalWitnessAdapter = {
      appendCheckpoint: async (_input: AppendCheckpointInput): Promise<AppendCheckpointResult> => {
        throw new Error("append must not be called for an existing operation");
      },
      readLatest: async () => null,
      readByOperation: async () => historicalRecord,
    };

    await expect(anchorCheckpoint(adapter, { verify: async () => true }, {
      expectedGeneration: 0,
      expectedCheckpointDigest: ZERO_CHECKPOINT_DIGEST,
      checkpoint: issued,
      expectedWitnessId: witnessId,
    })).rejects.toThrow("high-water checkpoint is missing");
  });
});
