import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
  type AttributeValue,
  type DynamoDBClientConfig,
  type TransactWriteItem,
} from "@aws-sdk/client-dynamodb";
import canonicalize from "canonicalize";
import {
  WitnessAmbiguousCommit,
  WitnessAppendConflict,
  WitnessIdempotencyConflict,
  type StoredWitnessCheckpoint,
  type WitnessCheckpoint,
  type WitnessCheckpointReceipt,
  type WitnessCheckpointScope,
  type WitnessProviderAdapter,
} from "./witness-provider-adapter";

interface DynamoDBCheckpointMetadata {
  readonly scope: WitnessCheckpointScope;
  readonly generation: number;
  readonly operationId: string;
  readonly phase: "MONITOR_GOSSIP_REPLAY_V1";
  readonly snapshotDigest: string;
  readonly checkpointDigest: string;
  readonly previousDigest: string;
  readonly snapshotByteLength: number;
  readonly checkpointBodyByteLength: number;
  readonly snapshotChunkCount: number;
  readonly checkpointBodyChunkCount: number;
}

const ZERO_DIGEST = "0".repeat(64);
const DIGEST = /^[0-9a-f]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const CHUNK_BYTES = 32 * 1024;
const MAX_SNAPSHOT_BYTES = 512 * 1024;
const MAX_CHECKPOINT_BODY_BYTES = 64 * 1024;

interface FetchDynamoDBRequest {
  readonly protocol: string;
  readonly hostname: string;
  readonly port?: number;
  readonly path: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body?: string | Uint8Array | ArrayBuffer;
}

/** Web Fetch transport for AWS SDK v3; avoids Node socket handlers in Workers. */
export function createFetchDynamoDBRequestHandler():
  NonNullable<DynamoDBClientConfig["requestHandler"]> {
  return {
    async handle(request: FetchDynamoDBRequest) {
      const authority = `${request.protocol}//${request.hostname}${request.port ? `:${request.port}` : ""}`;
      const url = new URL(request.path, authority);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        const normalized = name.toLowerCase();
        if (
          normalized === "host" ||
          normalized === "content-length" ||
          normalized === "connection" ||
          normalized === "transfer-encoding"
        ) continue;
        headers.set(name, value);
      }
      const response = await fetch(url, {
        method: request.method,
        headers,
        ...(request.body === undefined ? {} : { body: request.body as BodyInit }),
      });
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, name) => {
        responseHeaders[name] = value;
      });
      return {
        response: {
          statusCode: response.status,
          headers: responseHeaders,
          body: new Uint8Array(await response.arrayBuffer()),
        },
      };
    },
    destroy() {
      // Fetch owns and releases each request's resources.
    },
  } as unknown as NonNullable<DynamoDBClientConfig["requestHandler"]>;
}

export interface AwsDynamoDBWitnessProviderConfig {
  readonly endpointUrl: string;
  readonly region: string;
  readonly tableName: string;
  readonly accessKeyId?: string;
  readonly secretAccessKey?: string;
  readonly sessionToken?: string;
}

/**
 * DynamoDB adapter for the dual-digest replay checkpoint contract.
 *
 * Exact snapshot and checkpoint-body bytes are stored in immutable 32 KiB
 * chunks, while the generation/operation/idempotency/head records are written
 * atomically in the same TransactWriteItems request. The 512 KiB snapshot cap
 * stays below DynamoDB's 4 MiB transaction limit without creating >400 KiB
 * individual items.
 */
export class AwsDynamoDBWitnessProviderAdapter implements WitnessProviderAdapter {
  constructor(
    private readonly client: DynamoDBClient,
    private readonly tableName: string,
  ) {
    if (!tableName || tableName.length > 255) throw new TypeError("DynamoDB table name is invalid");
  }

  destroy(): void {
    this.client.destroy();
  }

  async readLatest(scope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    const head = await this.get(scope, "HEAD");
    if (!head) return null;
    const checkpointJson = this.stringAttribute(head, "checkpointJson");
    const metadata = this.parseCheckpointMetadata(checkpointJson);
    const record = await this.readRecord(scope, metadata.operationId);
    if (
      !record ||
      record.stored.checkpoint.generation !== metadata.generation ||
      record.stored.checkpoint.checkpointDigest !== metadata.checkpointDigest
    ) throw new Error("DynamoDB HEAD does not resolve to its exact immutable operation record");
    return record.stored;
  }

  async readByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    if (!SAFE_ID.test(operationId)) throw new TypeError("operation ID is invalid");
    const record = await this.readRecord(scope, operationId);
    return record?.stored ?? null;
  }

  async appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expectedPredecessor: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt> {
    this.validateAppend(checkpoint, expectedPredecessor, idempotencyKey);
    if (await this.sha256Hex(checkpoint.canonicalSnapshotBytes) !== checkpoint.snapshotDigest) {
      throw new TypeError("canonical snapshot bytes do not match snapshotDigest");
    }
    if (await this.sha256Hex(checkpoint.canonicalCheckpointBodyBytes) !== checkpoint.checkpointDigest) {
      throw new TypeError("canonical checkpoint-body bytes do not match checkpointDigest");
    }
    const partitionKey = await this.partitionKey(checkpoint.scope);
    const idempotencyKeySha256 = await this.sha256Hex(new TextEncoder().encode(idempotencyKey));
    const checkpointJson = canonicalize({
      scope: checkpoint.scope,
      generation: checkpoint.generation,
      operationId: checkpoint.operationId,
      phase: checkpoint.phase,
      snapshotDigest: checkpoint.snapshotDigest,
      checkpointDigest: checkpoint.checkpointDigest,
      previousDigest: checkpoint.previousDigest,
      snapshotByteLength: checkpoint.canonicalSnapshotBytes.length,
      checkpointBodyByteLength: checkpoint.canonicalCheckpointBodyBytes.length,
      snapshotChunkCount: this.chunkCount(checkpoint.canonicalSnapshotBytes),
      checkpointBodyChunkCount: this.chunkCount(checkpoint.canonicalCheckpointBodyBytes),
    });
    if (typeof checkpointJson !== "string") throw new TypeError("checkpoint metadata is not canonical JSON");

    const priorIdempotency = await this.get(checkpoint.scope, `IDEMP#${idempotencyKeySha256}`);
    if (priorIdempotency) {
      const priorOperationId = this.stringAttribute(priorIdempotency, "operationId");
      const priorKeyHash = this.stringAttribute(priorIdempotency, "idempotencyKeySha256");
      if (priorKeyHash !== idempotencyKeySha256) throw new WitnessIdempotencyConflict();
      const prior = await this.readRecord(checkpoint.scope, priorOperationId);
      if (!prior || prior.idempotencyKeySha256 !== idempotencyKeySha256 ||
          !this.exactCheckpoint(prior.stored.checkpoint, checkpoint)) {
        throw new WitnessIdempotencyConflict("idempotency key is already bound to different checkpoint bytes");
      }
      return prior.stored.receipt;
    }

    if (await this.get(checkpoint.scope, `OP#${checkpoint.operationId}`)) {
      throw new WitnessIdempotencyConflict("operation ID already exists with another idempotency binding");
    }

    const latest = await this.readLatest(checkpoint.scope);
    const actualGeneration = latest?.checkpoint.generation ?? 0;
    const actualDigest = latest?.checkpoint.checkpointDigest ?? ZERO_DIGEST;
    if (
      actualGeneration !== expectedPredecessor.generation ||
      actualDigest !== expectedPredecessor.digest
    ) throw new WitnessAppendConflict("DynamoDB latest head differs from expected predecessor");

    const receipt: WitnessCheckpointReceipt = {
      scope: checkpoint.scope,
      generation: checkpoint.generation,
      operationId: checkpoint.operationId,
      checkpointDigest: checkpoint.checkpointDigest,
      previousDigest: checkpoint.previousDigest,
      // Opaque adapter correlation only; never used as cryptographic proof.
      consistencyToken: `dynamodb-correlation-${(await this.sha256Hex(
        new TextEncoder().encode(`${this.tableName}\0${partitionKey}\0${idempotencyKeySha256}\0${checkpointJson}`),
      )).slice(0, 32)}`,
    };
    const receiptJson = canonicalize(receipt);
    if (typeof receiptJson !== "string") throw new TypeError("witness receipt metadata is not canonical JSON");

    const record = this.recordItem(partitionKey, "GEN#" + String(checkpoint.generation).padStart(20, "0"),
      checkpointJson, receiptJson, idempotencyKeySha256, checkpoint);
    const operation = this.recordItem(partitionKey, `OP#${checkpoint.operationId}`,
      checkpointJson, receiptJson, idempotencyKeySha256, checkpoint);
    const idempotency = this.recordItem(partitionKey, `IDEMP#${idempotencyKeySha256}`,
      checkpointJson, receiptJson, idempotencyKeySha256, checkpoint);
    const head = this.recordItem(partitionKey, "HEAD",
      checkpointJson, receiptJson, idempotencyKeySha256, checkpoint);

    const transaction: TransactWriteItem[] = [
      this.put(record),
      this.put(operation),
      this.put(idempotency),
      ...this.chunkItems(partitionKey, "SNAP", checkpoint.operationId, checkpoint.canonicalSnapshotBytes),
      ...this.chunkItems(partitionKey, "BODY", checkpoint.operationId, checkpoint.canonicalCheckpointBodyBytes),
    ];
    if (expectedPredecessor.generation === 0) {
      transaction.push(this.put(head));
    } else {
      transaction.push({
        Update: {
          TableName: this.tableName,
          Key: { PK: { S: partitionKey }, SK: { S: "HEAD" } },
          UpdateExpression: "SET #type = :type, #generation = :generation, #digest = :digest, #operation = :operation, #checkpoint = :checkpoint, #receipt = :receipt, #idempotency = :idempotency",
          ConditionExpression: "#generation = :expectedGeneration AND #digest = :expectedDigest",
          ExpressionAttributeNames: {
            "#type": "recordType",
            "#generation": "generation",
            "#digest": "checkpointDigest",
            "#operation": "operationId",
            "#checkpoint": "checkpointJson",
            "#receipt": "receiptJson",
            "#idempotency": "idempotencyKeySha256",
          },
          ExpressionAttributeValues: {
            ":type": { S: "HEAD" },
            ":generation": { N: String(checkpoint.generation) },
            ":digest": { S: checkpoint.checkpointDigest },
            ":operation": { S: checkpoint.operationId },
            ":checkpoint": { S: checkpointJson },
            ":receipt": { S: receiptJson },
            ":idempotency": { S: idempotencyKeySha256 },
            ":expectedGeneration": { N: String(expectedPredecessor.generation) },
            ":expectedDigest": { S: expectedPredecessor.digest },
          },
        },
      });
    }

    try {
      await this.client.send(new TransactWriteItemsCommand({
        TransactItems: transaction,
      }));
      return receipt;
    } catch (error) {
      const recovered = await this.readRecord(checkpoint.scope, checkpoint.operationId).catch(() => null);
      if (recovered) {
        if (
          recovered.idempotencyKeySha256 !== idempotencyKeySha256 ||
          !this.exactCheckpoint(recovered.stored.checkpoint, checkpoint) ||
          !this.exactReceipt(recovered.stored.receipt, receipt)
        ) throw new WitnessIdempotencyConflict("DynamoDB operation readback differs from append request");
        return recovered.stored.receipt;
      }
      const name = error instanceof Error ? error.name : "";
      if (name === "TransactionCanceledException" || name === "ConditionalCheckFailedException") {
        const current = await this.readLatest(checkpoint.scope).catch(() => null);
        const currentGeneration = current?.checkpoint.generation ?? 0;
        const currentDigest = current?.checkpoint.checkpointDigest ?? ZERO_DIGEST;
        if (
          currentGeneration !== expectedPredecessor.generation ||
          currentDigest !== expectedPredecessor.digest
        ) throw new WitnessAppendConflict("DynamoDB compare-and-append lost the predecessor race");
        throw new WitnessAppendConflict("DynamoDB rejected an immutable record condition");
      }
      throw new WitnessAmbiguousCommit(
        "DynamoDB transaction acknowledgement is ambiguous; retry the exact operation and bytes",
      );
    }
  }

  private validateAppend(
    checkpoint: WitnessCheckpoint,
    predecessor: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): void {
    if (
      !checkpoint.scope ||
      ![checkpoint.scope.trustDomainId, checkpoint.scope.witnessId,
        checkpoint.scope.authorityId, checkpoint.scope.hostId].every((v) =>
        typeof v === "string" && v.length > 0 && v.length <= 256
      )
    ) throw new TypeError("witness scope is malformed");
    if (
      !Number.isSafeInteger(predecessor.generation) || predecessor.generation < 0 ||
      !DIGEST.test(predecessor.digest) ||
      checkpoint.generation !== predecessor.generation + 1 ||
      checkpoint.previousDigest !== predecessor.digest
    ) throw new WitnessAppendConflict("checkpoint does not name the exact predecessor");
    if (
      !SAFE_ID.test(checkpoint.operationId) ||
      checkpoint.phase !== "MONITOR_GOSSIP_REPLAY_V1" ||
      !DIGEST.test(checkpoint.snapshotDigest) ||
      !DIGEST.test(checkpoint.checkpointDigest) ||
      !/^[0-9a-f]{64}$/.test(checkpoint.previousDigest) ||
      !(checkpoint.canonicalSnapshotBytes instanceof Uint8Array) ||
      checkpoint.canonicalSnapshotBytes.length === 0 ||
      checkpoint.canonicalSnapshotBytes.length > MAX_SNAPSHOT_BYTES ||
      !(checkpoint.canonicalCheckpointBodyBytes instanceof Uint8Array) ||
      checkpoint.canonicalCheckpointBodyBytes.length === 0 ||
      checkpoint.canonicalCheckpointBodyBytes.length > MAX_CHECKPOINT_BODY_BYTES ||
      typeof idempotencyKey !== "string" ||
      idempotencyKey.trim().length === 0 ||
      new TextEncoder().encode(idempotencyKey).length > 512
    ) throw new TypeError("witness checkpoint or idempotency fields are malformed");
  }

  private async readRecord(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<{ stored: StoredWitnessCheckpoint; idempotencyKeySha256: string } | null> {
    const item = await this.get(scope, `OP#${operationId}`);
    if (!item) return null;
    const checkpointMetadata = this.parseCheckpointMetadata(this.stringAttribute(item, "checkpointJson"));
    const receipt = JSON.parse(this.stringAttribute(item, "receiptJson")) as WitnessCheckpointReceipt;
    if (
      checkpointMetadata.operationId !== operationId ||
      !this.sameScope(checkpointMetadata.scope, scope) ||
      !this.sameScope(receipt.scope, scope)
    ) throw new Error("DynamoDB operation metadata scope or identity mismatch");

    const snapshotBytes = await this.readChunks(scope, "SNAP", operationId,
      checkpointMetadata.snapshotChunkCount, checkpointMetadata.snapshotByteLength);
    const checkpointBodyBytes = await this.readChunks(scope, "BODY", operationId,
      checkpointMetadata.checkpointBodyChunkCount, checkpointMetadata.checkpointBodyByteLength);
    if (
      await this.sha256Hex(snapshotBytes) !== checkpointMetadata.snapshotDigest ||
      await this.sha256Hex(checkpointBodyBytes) !== checkpointMetadata.checkpointDigest
    ) throw new Error("DynamoDB immutable byte chunks do not match their checkpoint digests");

    const checkpoint: WitnessCheckpoint = {
      scope: checkpointMetadata.scope,
      generation: checkpointMetadata.generation,
      operationId: checkpointMetadata.operationId,
      phase: checkpointMetadata.phase,
      snapshotDigest: checkpointMetadata.snapshotDigest,
      checkpointDigest: checkpointMetadata.checkpointDigest,
      previousDigest: checkpointMetadata.previousDigest,
      canonicalSnapshotBytes: snapshotBytes,
      canonicalCheckpointBodyBytes: checkpointBodyBytes,
    };
    const idempotencyKeySha256 = this.stringAttribute(item, "idempotencyKeySha256");
    if (!DIGEST.test(idempotencyKeySha256)) throw new Error("DynamoDB idempotency hash is malformed");
    return { stored: { checkpoint, receipt }, idempotencyKeySha256 };
  }

  private async readChunks(
    scope: WitnessCheckpointScope,
    kind: "SNAP" | "BODY",
    operationId: string,
    count: number,
    expectedLength: number,
  ): Promise<Uint8Array> {
    if (!Number.isSafeInteger(count) || count < 1 || count > 20 ||
        !Number.isSafeInteger(expectedLength) || expectedLength < 1) {
      throw new Error("DynamoDB chunk manifest is malformed");
    }
    const chunks: Uint8Array[] = [];
    for (let index = 0; index < count; index += 1) {
      const item = await this.get(scope, `${kind}#${operationId}#${String(index).padStart(4, "0")}`);
      const data = item?.data?.B;
      if (!(data instanceof Uint8Array)) throw new Error("DynamoDB immutable byte chunk is missing");
      chunks.push(data);
    }
    const bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    if (bytes.length !== expectedLength) throw new Error("DynamoDB chunk length differs from its manifest");
    return bytes;
  }

  private recordItem(
    partitionKey: string,
    sortKey: string,
    checkpointJson: string,
    receiptJson: string,
    idempotencyKeySha256: string,
    checkpoint: WitnessCheckpoint,
  ): Record<string, AttributeValue> {
    return {
      PK: { S: partitionKey },
      SK: { S: sortKey },
      recordType: { S: sortKey.split("#", 1)[0]! },
      generation: { N: String(checkpoint.generation) },
      checkpointDigest: { S: checkpoint.checkpointDigest },
      operationId: { S: checkpoint.operationId },
      idempotencyKeySha256: { S: idempotencyKeySha256 },
      checkpointJson: { S: checkpointJson },
      receiptJson: { S: receiptJson },
    };
  }

  private put(item: Record<string, AttributeValue>): TransactWriteItem {
    return {
      Put: {
        TableName: this.tableName,
        Item: item,
        ConditionExpression: "attribute_not_exists(PK)",
      },
    };
  }

  private chunkItems(
    partitionKey: string,
    kind: "SNAP" | "BODY",
    operationId: string,
    bytes: Uint8Array,
  ): TransactWriteItem[] {
    const chunks: TransactWriteItem[] = [];
    for (let offset = 0, index = 0; offset < bytes.length; offset += CHUNK_BYTES, index += 1) {
      const chunk = bytes.slice(offset, Math.min(offset + CHUNK_BYTES, bytes.length));
      chunks.push(this.put({
        PK: { S: partitionKey },
        SK: { S: `${kind}#${operationId}#${String(index).padStart(4, "0")}` },
        recordType: { S: `${kind}_CHUNK` },
        data: { B: chunk },
      }));
    }
    return chunks;
  }

  private chunkCount(bytes: Uint8Array): number {
    return Math.ceil(bytes.length / CHUNK_BYTES);
  }

  private async get(scope: WitnessCheckpointScope, sortKey: string) {
    const partitionKey = await this.partitionKey(scope);
    const response = await this.client.send(new GetItemCommand({
      TableName: this.tableName,
      Key: { PK: { S: partitionKey }, SK: { S: sortKey } },
      ConsistentRead: true,
    }));
    return response.Item;
  }

  private async partitionKey(scope: WitnessCheckpointScope): Promise<string> {
    const serialized = canonicalize(scope);
    if (typeof serialized !== "string") throw new TypeError("witness scope is not canonical JSON");
    return `SCOPE#${await this.sha256Hex(new TextEncoder().encode(serialized))}`;
  }

  private parseCheckpointMetadata(value: string): DynamoDBCheckpointMetadata {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("DynamoDB checkpoint metadata is malformed");
    }
    const item = parsed as Record<string, unknown>;
    if (
      !item.scope || typeof item.scope !== "object" ||
      !Number.isSafeInteger(item.generation) ||
      typeof item.operationId !== "string" ||
      item.phase !== "MONITOR_GOSSIP_REPLAY_V1" ||
      typeof item.snapshotDigest !== "string" ||
      typeof item.checkpointDigest !== "string" ||
      typeof item.previousDigest !== "string" ||
      !Number.isSafeInteger(item.snapshotByteLength) ||
      !Number.isSafeInteger(item.checkpointBodyByteLength) ||
      !Number.isSafeInteger(item.snapshotChunkCount) ||
      !Number.isSafeInteger(item.checkpointBodyChunkCount)
    ) throw new Error("DynamoDB checkpoint metadata fields are malformed");
    return item as unknown as DynamoDBCheckpointMetadata;
  }

  private stringAttribute(item: Record<string, AttributeValue>, key: string): string {
    const value = item[key]?.S;
    if (typeof value !== "string") throw new Error(`DynamoDB attribute ${key} is missing`);
    return value;
  }

  private sameScope(a: WitnessCheckpointScope, b: WitnessCheckpointScope): boolean {
    return a.trustDomainId === b.trustDomainId &&
      a.witnessId === b.witnessId &&
      a.authorityId === b.authorityId &&
      a.hostId === b.hostId;
  }

  private exactCheckpoint(a: WitnessCheckpoint, b: WitnessCheckpoint): boolean {
    return this.sameScope(a.scope, b.scope) &&
      a.generation === b.generation &&
      a.operationId === b.operationId &&
      a.phase === b.phase &&
      a.snapshotDigest === b.snapshotDigest &&
      a.checkpointDigest === b.checkpointDigest &&
      a.previousDigest === b.previousDigest &&
      this.bytesEqual(a.canonicalSnapshotBytes, b.canonicalSnapshotBytes) &&
      this.bytesEqual(a.canonicalCheckpointBodyBytes, b.canonicalCheckpointBodyBytes);
  }

  private exactReceipt(a: WitnessCheckpointReceipt, b: WitnessCheckpointReceipt): boolean {
    return this.sameScope(a.scope, b.scope) &&
      a.generation === b.generation &&
      a.operationId === b.operationId &&
      a.checkpointDigest === b.checkpointDigest &&
      a.previousDigest === b.previousDigest &&
      a.consistencyToken === b.consistencyToken;
  }

  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let difference = 0;
    for (let index = 0; index < a.length; index += 1) difference |= a[index]! ^ b[index]!;
    return difference === 0;
  }

  private async sha256Hex(bytes: Uint8Array): Promise<string> {
    const owned = new Uint8Array(bytes.byteLength);
    owned.set(bytes);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", owned));
    return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
}

/** Local-only factory. Live AWS writes require a separate reviewed qualification gate. */
export function createLocalDynamoDBWitnessProviderAdapter(
  config: AwsDynamoDBWitnessProviderConfig,
): AwsDynamoDBWitnessProviderAdapter {
  const parsed = new URL(config.endpointUrl);
  if (
    parsed.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "::1"].includes(parsed.hostname) ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) throw new Error("DynamoDB adapter factory permits only a plain loopback HTTP endpoint");
  if (!config.region || !config.tableName) throw new TypeError("DynamoDB region and table are required");
  const client = new DynamoDBClient({
    region: config.region,
    endpoint: config.endpointUrl,
    credentials: {
      accessKeyId: config.accessKeyId ?? "local",
      secretAccessKey: config.secretAccessKey ?? "local",
      ...(config.sessionToken ? { sessionToken: config.sessionToken } : {}),
    },
    requestHandler: createFetchDynamoDBRequestHandler(),
  });
  return new AwsDynamoDBWitnessProviderAdapter(client, config.tableName);
}


export interface AwsDynamoDBWitnessProviderProductionConfig {
  readonly region: string;
  readonly tableName: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly sessionToken?: string;
}

/**
 * AWS-only factory for the isolated provider Worker.
 *
 * Unlike the local factory above, this never accepts an endpoint override:
 * the SDK resolves the regional AWS DynamoDB endpoint. Callers must make the
 * explicit write-enable decision before invoking this factory. Credentials
 * are expected to come from Worker secrets, never checked-in vars.
 */
export function createAwsDynamoDBWitnessProviderAdapter(
  config: AwsDynamoDBWitnessProviderProductionConfig,
): AwsDynamoDBWitnessProviderAdapter {
  if (
    !config.region ||
    !config.tableName ||
    !config.accessKeyId ||
    !config.secretAccessKey
  ) throw new TypeError("AWS DynamoDB provider requires region, table and explicit credentials");
  const client = new DynamoDBClient({
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      ...(config.sessionToken ? { sessionToken: config.sessionToken } : {}),
    },
    requestHandler: createFetchDynamoDBRequestHandler(),
  });
  return new AwsDynamoDBWitnessProviderAdapter(client, config.tableName);
}
