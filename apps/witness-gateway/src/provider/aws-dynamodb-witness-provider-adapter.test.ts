import {
  CreateTableCommand,
  DeleteTableCommand,
  DescribeTableCommand,
  DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import canonicalize from "canonicalize";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deriveReplayCheckpointOperationId } from "../../../api/src/gossip/gossip-replay-checkpoint-intent";
import { AwsDynamoDBWitnessProviderAdapter, createLocalDynamoDBWitnessProviderAdapter } from "./aws-dynamodb-witness-provider-adapter";
import {
  WitnessAppendConflict,
  WitnessIdempotencyConflict,
  type WitnessCheckpoint,
  type WitnessCheckpointScope,
} from "./witness-provider-adapter";

const endpoint = process.env.FENCE_DDB_LOCAL_ENDPOINT;
const region = process.env.AWS_REGION ?? "us-east-1";
const scope: WitnessCheckpointScope = {
  trustDomainId: "dynamodb-local-domain",
  witnessId: "dynamodb-local-witness",
  authorityId: "dynamodb-local-authority",
  hostId: "dynamodb-local-host",
};
const zero = "0".repeat(64);

async function sha256(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
  return [...hash].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function makeCheckpoint(
  checkpointScope: WitnessCheckpointScope,
  snapshot: Record<string, unknown>,
  predecessor: { readonly generation: number; readonly digest: string },
): Promise<WitnessCheckpoint> {
  const snapshotJson = canonicalize(snapshot);
  if (typeof snapshotJson !== "string") throw new Error("snapshot not canonical JSON");
  const canonicalSnapshotBytes = new TextEncoder().encode(snapshotJson);
  const snapshotDigest = await sha256(canonicalSnapshotBytes);
  const operationId = await deriveReplayCheckpointOperationId({
    scope: checkpointScope,
    expectedPredecessor: predecessor,
    snapshotDigest,
  });
  const body = {
    profile: "sky-high-fence-monitor-replay-v1",
    schemaVersion: 1,
    trustDomainId: checkpointScope.trustDomainId,
    witnessId: checkpointScope.witnessId,
    authorityId: checkpointScope.authorityId,
    hostId: checkpointScope.hostId,
    senderId: "monitor-sender",
    recipientId: "monitor-recipient",
    generation: predecessor.generation + 1,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    previousCheckpointDigest: predecessor.digest,
    snapshotDigest,
    snapshotByteLength: canonicalSnapshotBytes.length,
    baseStateVersion: predecessor.generation,
    messageDigest: "a".repeat(64),
  };
  const bodyJson = canonicalize(body);
  if (typeof bodyJson !== "string") throw new Error("checkpoint body not canonical JSON");
  const canonicalCheckpointBodyBytes = new TextEncoder().encode(bodyJson);
  return {
    scope: checkpointScope,
    generation: predecessor.generation + 1,
    operationId,
    phase: "MONITOR_GOSSIP_REPLAY_V1",
    snapshotDigest,
    checkpointDigest: await sha256(canonicalCheckpointBodyBytes),
    previousDigest: predecessor.digest,
    canonicalSnapshotBytes,
    canonicalCheckpointBodyBytes,
  };
}

describe.skipIf(!endpoint)("AWS DynamoDB dual-digest provider adapter (DynamoDB Local only)", () => {
  const tableName = `fence-dual-digest-${randomUUID().replace(/-/g, "").slice(0, 18)}`;
  const client = new DynamoDBClient({
    endpoint: endpoint!,
    region,
    credentials: { accessKeyId: "local", secretAccessKey: "local" },
  });
  let adapter: AwsDynamoDBWitnessProviderAdapter;

  beforeAll(async () => {
    await client.send(new CreateTableCommand({
      TableName: tableName,
      AttributeDefinitions: [
        { AttributeName: "PK", AttributeType: "S" },
        { AttributeName: "SK", AttributeType: "S" },
      ],
      KeySchema: [
        { AttributeName: "PK", KeyType: "HASH" },
        { AttributeName: "SK", KeyType: "RANGE" },
      ],
      BillingMode: "PAY_PER_REQUEST",
    }));
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const result = await client.send(new DescribeTableCommand({ TableName: tableName }));
      if (result.Table?.TableStatus === "ACTIVE") break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    adapter = createLocalDynamoDBWitnessProviderAdapter({
      endpointUrl: endpoint!,
      region,
      tableName,
    });
  });

  afterAll(async () => {
    try {
      await client.send(new DeleteTableCommand({ TableName: tableName }));
    } finally {
      adapter?.destroy();
      client.destroy();
    }
  });

  it("atomically persists and strongly reads back both exact byte sequences and digests", async () => {
    const snapshot = {
      version: 1,
      senderId: "monitor-sender",
      recipientId: "monitor-recipient",
      highestSequence: 1,
      seenByMessageId: { "message-1": { sequence: 1, digest: "a".repeat(64) } },
      largeEvidenceMarker: "x".repeat(96 * 1024),
    };
    const testScope = { ...scope, witnessId: "witness-exact-byte-readback" };
    const predecessor = { generation: 0, digest: zero };
    const checkpoint = await makeCheckpoint(testScope, snapshot, predecessor);
    const receipt = await adapter.appendIfCurrent(checkpoint, predecessor, checkpoint.operationId);

    expect(receipt).toMatchObject({
      generation: 1,
      operationId: checkpoint.operationId,
      checkpointDigest: checkpoint.checkpointDigest,
      previousDigest: zero,
    });
    const byOperation = await adapter.readByOperation(testScope, checkpoint.operationId);
    const latest = await adapter.readLatest(testScope);
    expect(byOperation).not.toBeNull();
    expect(latest).not.toBeNull();
    expect(byOperation?.checkpoint.canonicalSnapshotBytes).toEqual(checkpoint.canonicalSnapshotBytes);
    expect(byOperation?.checkpoint.canonicalCheckpointBodyBytes).toEqual(checkpoint.canonicalCheckpointBodyBytes);
    expect(byOperation?.checkpoint.snapshotDigest).toBe(checkpoint.snapshotDigest);
    expect(byOperation?.checkpoint.checkpointDigest).toBe(checkpoint.checkpointDigest);
    expect(latest?.receipt).toEqual(receipt);
  });

  it("recovers a durable idempotency record without creating another generation", async () => {
    const snapshot = {
      version: 1,
      senderId: "monitor-sender",
      recipientId: "monitor-recipient",
      highestSequence: 1,
      seenByMessageId: { "message-1": { sequence: 1, digest: "a".repeat(64) } },
    };
    const testScope = { ...scope, witnessId: "witness-idempotency-retry" };
    const predecessor = { generation: 0, digest: zero };
    const checkpoint = await makeCheckpoint(testScope, snapshot, predecessor);
    const first = await adapter.appendIfCurrent(checkpoint, predecessor, "stable-idempotency-key");
    const retry = await adapter.appendIfCurrent(checkpoint, predecessor, "stable-idempotency-key");
    expect(retry).toEqual(first);
    expect((await adapter.readLatest(testScope))?.checkpoint.generation).toBe(1);
  });

  it("rejects idempotency-key rebinding and stale predecessor appends", async () => {
    const snapshot = {
      version: 1,
      senderId: "monitor-sender",
      recipientId: "monitor-recipient",
      highestSequence: 1,
      seenByMessageId: { "message-1": { sequence: 1, digest: "a".repeat(64) } },
    };
    const testScope = { ...scope, witnessId: "witness-conflict-tests" };
    const predecessor = { generation: 0, digest: zero };
    const checkpoint = await makeCheckpoint(testScope, snapshot, predecessor);
    await adapter.appendIfCurrent(checkpoint, predecessor, "bound-idempotency-key");
    const changed = await makeCheckpoint(testScope, { ...snapshot, highestSequence: 2 }, predecessor);
    await expect(adapter.appendIfCurrent(changed, predecessor, "bound-idempotency-key"))
      .rejects.toBeInstanceOf(WitnessIdempotencyConflict);
    await expect(adapter.appendIfCurrent(changed, predecessor, "different-idempotency-key"))
      .rejects.toBeInstanceOf(WitnessAppendConflict);
  });

  it("serializes independent concurrent writers with exactly one winner", async () => {
    const genesisSnapshot = {
      version: 1,
      senderId: "monitor-sender",
      recipientId: "monitor-recipient",
      highestSequence: 1,
      seenByMessageId: { "message-1": { sequence: 1, digest: "a".repeat(64) } },
    };
    const testScope = { ...scope, witnessId: "witness-concurrency" };
    const genesisPredecessor = { generation: 0, digest: zero };
    const genesis = await makeCheckpoint(testScope, genesisSnapshot, genesisPredecessor);
    await adapter.appendIfCurrent(genesis, genesisPredecessor, "race-genesis");

    const predecessor = { generation: 1, digest: genesis.checkpointDigest };
    const candidates = await Promise.all([2, 3, 4, 5].map((sequence) =>
      makeCheckpoint(testScope, {
        ...genesisSnapshot,
        highestSequence: sequence,
        seenByMessageId: {
          ...genesisSnapshot.seenByMessageId,
          [`message-${sequence}`]: { sequence, digest: String(sequence).padStart(64, "0") },
        },
      }, predecessor),
    ));
    const adapters = candidates.map(() => createLocalDynamoDBWitnessProviderAdapter({
      endpointUrl: endpoint!,
      region,
      tableName,
    }));
    try {
      const outcomes = await Promise.allSettled(candidates.map((candidate, index) =>
        adapters[index]!.appendIfCurrent(candidate, predecessor, candidate.operationId),
      ));
      expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(3);
      expect((await adapter.readLatest(testScope))?.checkpoint.generation).toBe(2);
    } finally {
      adapters.forEach((independentAdapter) => independentAdapter.destroy());
    }
  });
});

describe("DynamoDB adapter local-only factory", () => {
  it("rejects non-loopback AWS endpoints so live writes cannot be enabled by this factory", () => {
    expect(() => createLocalDynamoDBWitnessProviderAdapter({
      endpointUrl: "https://dynamodb.us-east-1.amazonaws.com",
      region: "us-east-1",
      tableName: "production-witness-table",
    })).toThrow("loopback");
  });

  it("rejects non-HTTP loopback endpoints", () => {
    expect(() => createLocalDynamoDBWitnessProviderAdapter({
      endpointUrl: "https://127.0.0.1:8000",
      region: "us-east-1",
      tableName: "local-witness-table",
    })).toThrow("loopback");
  });
});
