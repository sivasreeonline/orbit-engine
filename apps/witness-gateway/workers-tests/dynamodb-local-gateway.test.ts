import { DynamoDBClient, CreateTableCommand, DeleteTableCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { env } from "cloudflare:workers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { WitnessGatewayRpc } from "../../api/src/witness/witness-gateway-contract";
import { createApiWorkloadProof } from "../../api/src/witness/workload-proof-signer";
import { createReplayCheckpointIntent } from "../../api/src/gossip/gossip-replay-checkpoint-intent";
import { createFetchDynamoDBRequestHandler } from "../src/provider/aws-dynamodb-witness-provider-adapter";
import type {
  StoredWitnessCheckpoint,
  WitnessCheckpointScope,
  WitnessProviderAdapter,
} from "../src/provider/witness-provider-adapter";

interface IntegrationEnv {
  readonly WITNESS_GATEWAY: WitnessGatewayRpc;
  readonly WITNESS_PROVIDER: WitnessProviderAdapter;
  readonly FENCE_TEST_CALLER_ID: string;
  readonly FENCE_TEST_CALLER_KEY_ID: string;
  readonly FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8: string;
  readonly FENCE_DDB_LOCAL_ENDPOINT: string;
  readonly FENCE_DDB_LOCAL_REGION: string;
  readonly FENCE_DDB_LOCAL_TABLE_NAME: string;
}

const bindings = env as unknown as IntegrationEnv;
const scope: WitnessCheckpointScope = {
  trustDomainId: "workerd-dynamodb-domain",
  witnessId: "workerd-dynamodb-witness",
  authorityId: "workerd-dynamodb-authority",
  hostId: "workerd-dynamodb-host",
};
const predecessor = { generation: 0, digest: "0".repeat(64) };
const admin = new DynamoDBClient({
  endpoint: bindings.FENCE_DDB_LOCAL_ENDPOINT,
  region: bindings.FENCE_DDB_LOCAL_REGION,
  credentials: { accessKeyId: "local", secretAccessKey: "local" },
  requestHandler: createFetchDynamoDBRequestHandler(),
});

describe("gateway provider binding against DynamoDB Local in workerd", () => {
  beforeAll(async () => {
    await admin.send(new CreateTableCommand({
      TableName: bindings.FENCE_DDB_LOCAL_TABLE_NAME,
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
    let active = false;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const result = await admin.send(new DescribeTableCommand({
        TableName: bindings.FENCE_DDB_LOCAL_TABLE_NAME,
      }));
      if (result.Table?.TableStatus === "ACTIVE") {
        active = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!active) throw new Error("DynamoDB Local table did not become ACTIVE");
  }, 10_000);

  afterAll(async () => {
    try {
      await admin.send(new DeleteTableCommand({
        TableName: bindings.FENCE_DDB_LOCAL_TABLE_NAME,
      }));
    } finally {
      admin.destroy();
    }
  });

  it("commits through the gateway's provider RPC, verifies authority evidence, and reads exact bytes back", async () => {
    const messageDigest = "a".repeat(64);
    const senderId = "workerd-monitor-a";
    const recipientId = "workerd-monitor-b";
    const snapshot = {
      version: 1,
      senderId,
      recipientId,
      highestSequence: 1,
      seenByMessageId: {
        "workerd-dynamodb-message-1": {
          sequence: 1,
          digest: messageDigest,
        },
      },
    };
    const intent = await createReplayCheckpointIntent({
      baseStateVersion: 0,
      senderId,
      recipientId,
      messageDigest,
      scope: [
        scope.trustDomainId,
        scope.witnessId,
        scope.authorityId,
        scope.hostId,
      ].join("|"),
      expectedPredecessor: predecessor,
      nextState: snapshot,
    });
    const requestBytes = new TextEncoder().encode(intent.canonicalCheckpointBody);
    const signed = await createApiWorkloadProof({
      callerId: bindings.FENCE_TEST_CALLER_ID,
      keyId: bindings.FENCE_TEST_CALLER_KEY_ID,
      privateKeyPkcs8: bindings.FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8,
    }, requestBytes, "checkpoint_replay");
    expect(signed.created).toBe(true);
    if (!signed.created) throw new Error("test caller proof could not be signed");

    const checkpoint = await bindings.WITNESS_GATEWAY.checkpointReplay(
      signed.proof,
      requestBytes,
    );
    expect(checkpoint.checkpointed).toBe(true);
    if (!checkpoint.checkpointed) {
      throw new Error(`gateway checkpoint failed: ${checkpoint.reason}`);
    }

    const evidenceProof = await createApiWorkloadProof({
      callerId: bindings.FENCE_TEST_CALLER_ID,
      keyId: bindings.FENCE_TEST_CALLER_KEY_ID,
      privateKeyPkcs8: bindings.FENCE_TEST_CALLER_PRIVATE_KEY_PKCS8,
    }, checkpoint.canonicalEvidenceBody, "verify_evidence");
    expect(evidenceProof.created).toBe(true);
    if (!evidenceProof.created) throw new Error("test evidence proof could not be signed");

    const verified = await bindings.WITNESS_GATEWAY.verifyEvidence(
      evidenceProof.proof,
      checkpoint.canonicalEvidenceBody,
    );
    expect(verified.verified).toBe(true);
    if (!verified.verified) {
      throw new Error(`gateway evidence verification failed: ${verified.reason}`);
    }

    const stored = await bindings.WITNESS_PROVIDER.readByOperation(
      scope,
      intent.operationId,
    ) as StoredWitnessCheckpoint | null;
    expect(stored).not.toBeNull();
    expect(stored?.checkpoint.generation).toBe(1);
    expect(stored?.checkpoint.snapshotDigest).toBe(intent.snapshotDigest);
    expect(stored?.checkpoint.checkpointDigest).toBe(verified.checkpointDigest);
    expect(stored?.checkpoint.checkpointDigest).not.toBe(intent.snapshotDigest);
    expect(new TextDecoder().decode(stored!.checkpoint.canonicalSnapshotBytes))
      .toBe(JSON.stringify(snapshot, Object.keys(snapshot).sort()));
    expect(stored?.receipt.checkpointDigest).toBe(verified.checkpointDigest);

    const latest = await bindings.WITNESS_PROVIDER.readLatest(scope);
    expect(latest?.checkpoint.operationId).toBe(intent.operationId);
    expect(latest?.checkpoint.canonicalCheckpointBodyBytes).toEqual(
      stored?.checkpoint.canonicalCheckpointBodyBytes,
    );
  });
});
