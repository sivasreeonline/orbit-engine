import canonicalize from "canonicalize";
import {
  buildMonitorReplayCheckpointArtifact,
  type MonitorReplayCheckpointArtifact,
  type MonitorReplayProviderCheckpoint,
  type MonitorReplayTrustScope,
} from "../../api/src/witness/monitor-replay-checkpoint";
import type {
  WitnessReceiptEnvelope,
  WitnessTreeHeadEnvelope,
  WitnessTrustBundleEnvelope,
} from "../../api/src/witness/witness-profile-verifier";

export interface WitnessProviderCheckpointRecord extends MonitorReplayProviderCheckpoint {
  readonly checkpointBody: MonitorReplayCheckpointArtifact["checkpointBody"];
}

export interface WitnessProviderRecord {
  readonly checkpoint: WitnessProviderCheckpointRecord;
  readonly receiptEnvelope: WitnessReceiptEnvelope;
  readonly trustBundleEnvelope: WitnessTrustBundleEnvelope;
  readonly treeHeadEnvelope: WitnessTreeHeadEnvelope;
  readonly leafIndex: number;
  readonly inclusionProofHex: readonly string[];
  readonly consistencyProofHex: readonly string[];
}

export interface WitnessProviderAdapter {
  /**
   * Atomically compare-and-append. The provider must enforce expected generation,
   * expected predecessor digest, and idempotencyKey as one transaction.
   */
  appendIfCurrent(
    checkpoint: WitnessProviderCheckpointRecord,
    expectedGeneration: number,
    expectedDigest: string,
    idempotencyKey: string,
  ): Promise<WitnessReceiptEnvelope>;

  /** Immutable lookup by deterministic operation ID. */
  readByOperation(
    scope: MonitorReplayTrustScope,
    operationId: string,
  ): Promise<WitnessProviderRecord | null>;

  /** Strongly consistent latest read for the exact provider scope. */
  readLatest(scope: MonitorReplayTrustScope): Promise<WitnessProviderRecord | null>;
}

export type VerifyWitnessProviderRecord = (record: WitnessProviderRecord) => Promise<void>;

export class WitnessProviderAppendConflictError extends Error {
  constructor(message = "witness provider compare-and-append conflict") {
    super(message);
    this.name = "WitnessProviderAppendConflictError";
  }
}

export class WitnessProviderAmbiguousCommitError extends Error {
  constructor(message = "witness provider acknowledgement is ambiguous") {
    super(message);
    this.name = "WitnessProviderAmbiguousCommitError";
  }
}

export class WitnessProviderUnavailableError extends Error {
  constructor(message = "witness provider is unavailable") {
    super(message);
    this.name = "WitnessProviderUnavailableError";
  }
}

export class WitnessProviderIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WitnessProviderIntegrityError";
  }
}

export interface WitnessCheckpointCoordinatorResult {
  readonly status: "CHECKPOINTED" | "ALREADY_CHECKPOINTED";
  readonly generation: number;
  readonly operationId: string;
  readonly snapshotDigest: string;
  readonly checkpointDigest: string;
  readonly receiptEnvelope: WitnessReceiptEnvelope;
}

const ZERO_DIGEST = "0".repeat(64);
const REPLAY_PHASE = "MONITOR_GOSSIP_REPLAY_V1";

function canonicalString(value: unknown): string {
  const serialized = canonicalize(value);
  if (typeof serialized !== "string") throw new WitnessProviderIntegrityError("provider record is not canonicalizable JSON");
  return serialized;
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalString(left) === canonicalString(right);
}

function assertScopeMatches(
  actual: MonitorReplayProviderCheckpoint["scope"],
  expected: MonitorReplayTrustScope,
): void {
  if (
    actual.trustDomainId !== expected.trustDomainId ||
    actual.witnessId !== expected.witnessId ||
    actual.authorityId !== expected.authorityId ||
    actual.hostId !== expected.hostId ||
    actual.senderId !== expected.senderId ||
    actual.recipientId !== expected.recipientId ||
    actual.replayScope !== expected.replayScope
  ) throw new WitnessProviderIntegrityError("provider record scope substitution");
}

function assertReceiptMatchesCheckpoint(record: WitnessProviderRecord): void {
  const checkpoint = record.checkpoint;
  const receipt = record.receiptEnvelope.body;
  if (
    receipt.witnessId !== checkpoint.scope.witnessId ||
    receipt.authorityId !== checkpoint.scope.authorityId ||
    receipt.hostId !== checkpoint.scope.hostId ||
    receipt.generation !== checkpoint.generation ||
    receipt.operationId !== checkpoint.operationId ||
    receipt.checkpointDigest !== checkpoint.checkpointDigest ||
    receipt.previousCheckpointDigest !== checkpoint.previousDigest
  ) throw new WitnessProviderIntegrityError("provider receipt does not bind the exact checkpoint artifact");
}

async function assertRecordMatchesArtifact(
  record: WitnessProviderRecord,
  artifact: MonitorReplayCheckpointArtifact,
  scope: MonitorReplayTrustScope,
  verifyRecord: VerifyWitnessProviderRecord,
): Promise<void> {
  const expected = artifact.providerCheckpoint;
  assertScopeMatches(record.checkpoint.scope, scope);
  if (
    record.checkpoint.generation !== expected.generation ||
    record.checkpoint.operationId !== expected.operationId ||
    record.checkpoint.phase !== REPLAY_PHASE ||
    record.checkpoint.checkpointDigest !== expected.checkpointDigest ||
    record.checkpoint.previousDigest !== expected.previousDigest ||
    record.checkpoint.snapshotDigest !== expected.snapshotDigest ||
    !sameCanonical(record.checkpoint.checkpointBody, artifact.checkpointBody)
  ) throw new WitnessProviderIntegrityError("provider operation record differs from canonical replay checkpoint artifact");
  assertReceiptMatchesCheckpoint(record);
  await verifyRecord(record);
}

async function assertLatestRecord(
  record: WitnessProviderRecord,
  scope: MonitorReplayTrustScope,
  verifyRecord: VerifyWitnessProviderRecord,
): Promise<void> {
  assertScopeMatches(record.checkpoint.scope, scope);
  if (
    record.checkpoint.phase !== REPLAY_PHASE ||
    !/^[0-9a-f]{64}$/.test(record.checkpoint.checkpointDigest) ||
    !/^[0-9a-f]{64}$/.test(record.checkpoint.snapshotDigest) ||
    !/^[0-9a-f]{64}$/.test(record.checkpoint.previousDigest)
  ) throw new WitnessProviderIntegrityError("latest provider checkpoint metadata is malformed");
  assertReceiptMatchesCheckpoint(record);
  await verifyRecord(record);
}

function resultFromRecord(
  status: WitnessCheckpointCoordinatorResult["status"],
  record: WitnessProviderRecord,
): WitnessCheckpointCoordinatorResult {
  return {
    status,
    generation: record.checkpoint.generation,
    operationId: record.checkpoint.operationId,
    snapshotDigest: record.checkpoint.snapshotDigest,
    checkpointDigest: record.checkpoint.checkpointDigest,
    receiptEnvelope: record.receiptEnvelope,
  };
}

/**
 * Provider-neutral compare/append/readback coordinator. It never trusts an
 * append acknowledgement alone: immutable operation lookup and a strong latest
 * read must both confirm the exact canonical artifact and signed receipt.
 */
export async function checkpointMonitorReplaySnapshot(
  adapter: WitnessProviderAdapter,
  snapshot: Parameters<typeof buildMonitorReplayCheckpointArtifact>[0],
  scope: MonitorReplayTrustScope,
  verifyRecord: VerifyWitnessProviderRecord,
): Promise<WitnessCheckpointCoordinatorResult> {
  const initialArtifact = await buildMonitorReplayCheckpointArtifact(
    snapshot,
    scope,
    1,
    ZERO_DIGEST,
  );
  const operationId = initialArtifact.operationId;

  const priorOperation = await adapter.readByOperation(scope, operationId);
  if (priorOperation) {
    const artifact = await buildMonitorReplayCheckpointArtifact(
      snapshot,
      scope,
      priorOperation.checkpoint.generation,
      priorOperation.checkpoint.previousDigest,
    );
    await assertRecordMatchesArtifact(priorOperation, artifact, scope, verifyRecord);

    const latest = await adapter.readLatest(scope);
    if (!latest) throw new WitnessProviderIntegrityError("operation exists but provider latest read is empty");
    await assertLatestRecord(latest, scope, verifyRecord);
    if (
      latest.checkpoint.operationId !== priorOperation.checkpoint.operationId ||
      latest.checkpoint.checkpointDigest !== priorOperation.checkpoint.checkpointDigest ||
      !sameCanonical(latest.receiptEnvelope, priorOperation.receiptEnvelope)
    ) throw new WitnessProviderIntegrityError("replayed snapshot operation is no longer the current witness head");
    return resultFromRecord("ALREADY_CHECKPOINTED", priorOperation);
  }

  const latest = await adapter.readLatest(scope);
  let expectedGeneration = 0;
  let expectedDigest = ZERO_DIGEST;
  if (latest) {
    await assertLatestRecord(latest, scope, verifyRecord);
    expectedGeneration = latest.checkpoint.generation;
    expectedDigest = latest.checkpoint.checkpointDigest;
  }

  const artifact = await buildMonitorReplayCheckpointArtifact(
    snapshot,
    scope,
    expectedGeneration + 1,
    expectedDigest,
  );
  const checkpoint: WitnessProviderCheckpointRecord = {
    ...artifact.providerCheckpoint,
    checkpointBody: artifact.checkpointBody,
  };

  let acknowledgedReceipt: WitnessReceiptEnvelope | null = null;
  try {
    acknowledgedReceipt = await adapter.appendIfCurrent(
      checkpoint,
      expectedGeneration,
      expectedDigest,
      artifact.operationId,
    );
  } catch (error) {
    if (!(error instanceof WitnessProviderAmbiguousCommitError)) throw error;
  }

  const committed = await adapter.readByOperation(scope, artifact.operationId);
  if (!committed) {
    if (acknowledgedReceipt === null) {
      throw new WitnessProviderUnavailableError("ambiguous append could not be recovered by immutable operation lookup");
    }
    throw new WitnessProviderIntegrityError("provider acknowledged append but immutable operation lookup is empty");
  }
  await assertRecordMatchesArtifact(committed, artifact, scope, verifyRecord);
  if (
    acknowledgedReceipt !== null &&
    !sameCanonical(acknowledgedReceipt, committed.receiptEnvelope)
  ) throw new WitnessProviderIntegrityError("append acknowledgement receipt differs from immutable readback");

  const strongLatest = await adapter.readLatest(scope);
  if (!strongLatest) throw new WitnessProviderIntegrityError("provider latest read is empty after append");
  await assertLatestRecord(strongLatest, scope, verifyRecord);
  if (
    strongLatest.checkpoint.operationId !== artifact.operationId ||
    strongLatest.checkpoint.checkpointDigest !== artifact.checkpointDigest ||
    !sameCanonical(strongLatest.receiptEnvelope, committed.receiptEnvelope)
  ) throw new WitnessProviderIntegrityError("strong latest readback differs from the exact appended replay checkpoint");

  return resultFromRecord("CHECKPOINTED", committed);
}
