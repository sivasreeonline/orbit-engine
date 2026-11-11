import { describe, expect, it } from "vitest";
import {
  assertCheckpointFollows,
  CheckpointTransitionError,
  ExternalWitnessAdapter,
  AppendCheckpointInput,
  AppendCheckpointResult,
  WitnessCheckpoint,
  WitnessConflictError,
  WitnessRecord,
  WitnessScope,
  WitnessUnavailableError,
  ZERO_CHECKPOINT_DIGEST,
} from "./external-witness-adapter";

const scope: WitnessScope = { authorityId: "authority-test", hostId: "host-test" };

function checkpoint(overrides: Partial<WitnessCheckpoint> = {}): WitnessCheckpoint {
  return {
    schemaVersion: 1,
    authorityId: scope.authorityId,
    hostId: scope.hostId,
    generation: 1,
    phase: "ISSUED",
    operationId: "operation-1",
    previousCheckpointDigest: ZERO_CHECKPOINT_DIGEST,
    checkpointDigest: "a".repeat(64),
    authorityStateDigest: "b".repeat(64),
    responseDigest: "c".repeat(64),
    epoch: 10,
    recordVersion: 2,
    ...overrides,
  };
}

class InMemoryWitnessContractAdapter implements ExternalWitnessAdapter {
  private readonly records = new Map<string, WitnessRecord[]>();
  private readonly operations = new Map<string, WitnessRecord>();
  unavailable = false;
  loseAcknowledgementOnce = false;

  async appendCheckpoint(input: AppendCheckpointInput): Promise<AppendCheckpointResult> {
    if (this.unavailable) throw new WitnessUnavailableError();

    const key = this.scopeKey(input.checkpoint);
    const operationKey = `${key}:${input.checkpoint.operationId}`;
    const existing = this.operations.get(operationKey);
    if (existing) {
      if (JSON.stringify(existing.checkpoint) !== JSON.stringify(input.checkpoint)) {
        throw new WitnessConflictError("operation ID was rebound to a different checkpoint");
      }
      return { status: "EXISTING", record: existing };
    }

    const chain = this.records.get(key) ?? [];
    const latest = chain[chain.length - 1];
    const previous = latest ? latest.checkpoint : null;
    const currentGeneration = previous?.generation ?? 0;
    const currentDigest = previous?.checkpointDigest ?? ZERO_CHECKPOINT_DIGEST;
    if (
      input.expectedGeneration !== currentGeneration
      || input.expectedCheckpointDigest !== currentDigest
    ) {
      throw new WitnessConflictError("compare-and-append predecessor is stale or forked");
    }

    assertCheckpointFollows(previous, input.checkpoint);
    const record: WitnessRecord = {
      checkpoint: input.checkpoint,
      receipt: {
        schemaVersion: 1,
        witnessId: "in-memory-contract-test-double",
        authorityId: input.checkpoint.authorityId,
        hostId: input.checkpoint.hostId,
        generation: input.checkpoint.generation,
        operationId: input.checkpoint.operationId,
        checkpointDigest: input.checkpoint.checkpointDigest,
        previousCheckpointDigest: input.checkpoint.previousCheckpointDigest,
        keyId: "not-a-real-key",
        signature: "not-a-real-signature",
        committedAt: "2026-11-11T00:00:00.000Z",
        consistencyToken: `test-generation-${input.checkpoint.generation}`,
      },
    };

    chain.push(record);
    this.records.set(key, chain);
    this.operations.set(operationKey, record);

    if (this.loseAcknowledgementOnce) {
      this.loseAcknowledgementOnce = false;
      throw new WitnessUnavailableError("simulated lost acknowledgement after commit");
    }
    return { status: "APPENDED", record };
  }

  async readLatest(requestedScope: WitnessScope): Promise<WitnessRecord | null> {
    if (this.unavailable) throw new WitnessUnavailableError();
    const chain = this.records.get(this.scopeKey(requestedScope)) ?? [];
    return chain[chain.length - 1] ?? null;
  }

  async readByOperation(
    requestedScope: WitnessScope,
    operationId: string,
  ): Promise<WitnessRecord | null> {
    if (this.unavailable) throw new WitnessUnavailableError();
    return this.operations.get(`${this.scopeKey(requestedScope)}:${operationId}`) ?? null;
  }

  private scopeKey(value: WitnessScope): string {
    return `${value.authorityId}:${value.hostId}`;
  }
}

function inputFor(
  value: WitnessCheckpoint,
  expectedGeneration: number,
  expectedCheckpointDigest: string,
): AppendCheckpointInput {
  return { checkpoint: value, expectedGeneration, expectedCheckpointDigest };
}

describe("provider-neutral external witness contract", () => {
  it("enforces issuance → exact acceptance → next issuance predecessor linkage", () => {
    const issued = checkpoint();
    const accepted = checkpoint({
      generation: 2,
      phase: "ACCEPTED",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      recordVersion: 3,
    });
    const nextIssued = checkpoint({
      generation: 3,
      operationId: "operation-2",
      previousCheckpointDigest: accepted.checkpointDigest,
      checkpointDigest: "e".repeat(64),
      responseDigest: "f".repeat(64),
      epoch: 11,
      recordVersion: 4,
    });

    expect(() => assertCheckpointFollows(null, issued)).not.toThrow();
    expect(() => assertCheckpointFollows(issued, accepted)).not.toThrow();
    expect(() => assertCheckpointFollows(accepted, nextIssued)).not.toThrow();
  });

  it("rejects generation gaps, predecessor forks and acceptance rebinding", () => {
    const issued = checkpoint();
    expect(() => assertCheckpointFollows(issued, checkpoint({
      generation: 3,
      phase: "ACCEPTED",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      recordVersion: 3,
    }))).toThrow(CheckpointTransitionError);

    expect(() => assertCheckpointFollows(issued, checkpoint({
      generation: 2,
      phase: "ACCEPTED",
      previousCheckpointDigest: "f".repeat(64),
      checkpointDigest: "d".repeat(64),
      recordVersion: 3,
    }))).toThrow(CheckpointTransitionError);

    expect(() => assertCheckpointFollows(issued, checkpoint({
      generation: 2,
      phase: "ACCEPTED",
      operationId: "operation-rebound",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      recordVersion: 3,
    }))).toThrow(CheckpointTransitionError);
  });

  it("returns the exact original receipt after a committed append loses its acknowledgement", async () => {
    const adapter = new InMemoryWitnessContractAdapter();
    const first = checkpoint();
    adapter.loseAcknowledgementOnce = true;

    await expect(adapter.appendCheckpoint(inputFor(first, 0, ZERO_CHECKPOINT_DIGEST)))
      .rejects.toBeInstanceOf(WitnessUnavailableError);

    const recovered = await adapter.readByOperation(scope, first.operationId);
    expect(recovered?.checkpoint).toEqual(first);
    expect(recovered?.receipt.signature).toBe("not-a-real-signature");

    const retry = await adapter.appendCheckpoint(inputFor(first, 0, ZERO_CHECKPOINT_DIGEST));
    expect(retry.status).toBe("EXISTING");
    expect(retry.record.receipt).toBe(recovered?.receipt);
    expect((await adapter.readLatest(scope))?.checkpoint).toEqual(first);
  });

  it("allows exactly one winner for concurrent successors using the same CAS predecessor", async () => {
    const adapter = new InMemoryWitnessContractAdapter();
    const issued = checkpoint();
    await adapter.appendCheckpoint(inputFor(issued, 0, ZERO_CHECKPOINT_DIGEST));

    const accepted = checkpoint({
      generation: 2,
      phase: "ACCEPTED",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      recordVersion: 3,
    });
    await adapter.appendCheckpoint(inputFor(accepted, 1, issued.checkpointDigest));

    const left = checkpoint({
      generation: 3,
      operationId: "operation-left",
      previousCheckpointDigest: accepted.checkpointDigest,
      checkpointDigest: "e".repeat(64),
      responseDigest: "1".repeat(64),
      epoch: 11,
      recordVersion: 4,
    });
    const right = checkpoint({
      generation: 3,
      operationId: "operation-right",
      previousCheckpointDigest: accepted.checkpointDigest,
      checkpointDigest: "f".repeat(64),
      responseDigest: "2".repeat(64),
      epoch: 11,
      recordVersion: 4,
    });

    const outcomes = await Promise.allSettled([
      adapter.appendCheckpoint(inputFor(left, 2, accepted.checkpointDigest)),
      adapter.appendCheckpoint(inputFor(right, 2, accepted.checkpointDigest)),
    ]);
    expect(outcomes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect((await adapter.readLatest(scope))?.checkpoint.generation).toBe(3);
  });

  it("fails closed when the witness is unavailable and treats revocation as terminal", async () => {
    const adapter = new InMemoryWitnessContractAdapter();
    const issued = checkpoint();
    adapter.unavailable = true;
    await expect(adapter.appendCheckpoint(inputFor(issued, 0, ZERO_CHECKPOINT_DIGEST)))
      .rejects.toBeInstanceOf(WitnessUnavailableError);
    adapter.unavailable = false;

    await adapter.appendCheckpoint(inputFor(issued, 0, ZERO_CHECKPOINT_DIGEST));
    const revoked = checkpoint({
      generation: 2,
      phase: "REVOKED",
      operationId: "revocation-1",
      previousCheckpointDigest: issued.checkpointDigest,
      checkpointDigest: "d".repeat(64),
      responseDigest: "e".repeat(64),
      recordVersion: 3,
    });
    await adapter.appendCheckpoint(inputFor(revoked, 1, issued.checkpointDigest));

    expect(() => assertCheckpointFollows(revoked, checkpoint({
      generation: 3,
      operationId: "operation-2",
      previousCheckpointDigest: revoked.checkpointDigest,
      checkpointDigest: "f".repeat(64),
      responseDigest: "1".repeat(64),
      epoch: 11,
      recordVersion: 4,
    }))).toThrow(CheckpointTransitionError);
  });
});
