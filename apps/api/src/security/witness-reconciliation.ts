import {
  AppendCheckpointInput,
  assertCheckpointFollows,
  assertReceiptMatchesCheckpoint,
  ExternalWitnessAdapter,
  WitnessConflictError,
  WitnessReceiptVerifier,
  WitnessRecord,
  WitnessUnavailableError,
  ZERO_CHECKPOINT_DIGEST,
} from "./external-witness-adapter";

export interface AnchorCheckpointInput extends AppendCheckpointInput {
  readonly expectedWitnessId: string;
}

export interface AnchorCheckpointResult {
  readonly status: "ANCHORED" | "ALREADY_ANCHORED";
  readonly record: WitnessRecord;
}

function sameCheckpoint(
  left: WitnessRecord["checkpoint"],
  right: WitnessRecord["checkpoint"],
): boolean {
  return left.schemaVersion === right.schemaVersion
    && left.authorityId === right.authorityId
    && left.hostId === right.hostId
    && left.generation === right.generation
    && left.phase === right.phase
    && left.operationId === right.operationId
    && left.previousCheckpointDigest === right.previousCheckpointDigest
    && left.checkpointDigest === right.checkpointDigest
    && left.authorityStateDigest === right.authorityStateDigest
    && left.responseDigest === right.responseDigest
    && left.epoch === right.epoch
    && left.recordVersion === right.recordVersion;
}

async function verifyRecord(
  record: WitnessRecord,
  expectedCheckpoint: WitnessRecord["checkpoint"],
  expectedWitnessId: string,
  verifier: WitnessReceiptVerifier,
): Promise<void> {
  if (!sameCheckpoint(record.checkpoint, expectedCheckpoint)) {
    throw new WitnessConflictError("witness returned a different checkpoint for this operation phase");
  }
  assertReceiptMatchesCheckpoint(record, expectedWitnessId);
  if (!(await verifier.verify(record))) {
    throw new WitnessConflictError("witness receipt signature or trust verification failed");
  }
}

/**
 * Anchor one authority transition in the external witness.
 *
 * This coordinator never falls back to the local database. An unknown append
 * outcome is reconciled by operation ID + phase; if that read is unavailable
 * or cannot prove the exact candidate, the caller must quarantine the change.
 */
export async function anchorCheckpoint(
  adapter: ExternalWitnessAdapter,
  verifier: WitnessReceiptVerifier,
  input: AnchorCheckpointInput,
): Promise<AnchorCheckpointResult> {
  const { checkpoint, expectedGeneration, expectedCheckpointDigest, expectedWitnessId } = input;
  const scope = { authorityId: checkpoint.authorityId, hostId: checkpoint.hostId };

  const current = await adapter.readLatest(scope);
  const currentGeneration = current?.checkpoint.generation ?? 0;
  const currentDigest = current?.checkpoint.checkpointDigest ?? ZERO_CHECKPOINT_DIGEST;
  if (
    currentGeneration !== expectedGeneration
    || currentDigest !== expectedCheckpointDigest
  ) {
    throw new WitnessConflictError("external witness high-water differs from the expected compare-and-append head");
  }

  if (current) {
    assertReceiptMatchesCheckpoint(current, expectedWitnessId);
    if (!(await verifier.verify(current))) {
      throw new WitnessConflictError("preceding witness receipt failed verification");
    }
  }
  assertCheckpointFollows(current?.checkpoint ?? null, checkpoint);

  try {
    const appended = await adapter.appendCheckpoint({
      expectedGeneration,
      expectedCheckpointDigest,
      checkpoint,
    });
    await verifyRecord(appended.record, checkpoint, expectedWitnessId, verifier);
    return {
      status: appended.status === "APPENDED" ? "ANCHORED" : "ALREADY_ANCHORED",
      record: appended.record,
    };
  } catch (error) {
    if (!(error instanceof WitnessUnavailableError)) throw error;

    // The append may have committed before its acknowledgement was lost.
    // Read by operation AND phase; never issue a different candidate here.
    const recovered = await adapter.readByOperation(scope, checkpoint.operationId, checkpoint.phase);
    if (!recovered) {
      throw new WitnessUnavailableError(
        "append outcome remains unknown; authority transition must stay checkpoint-pending",
      );
    }

    await verifyRecord(recovered, checkpoint, expectedWitnessId, verifier);
    return { status: "ALREADY_ANCHORED", record: recovered };
  }
}
