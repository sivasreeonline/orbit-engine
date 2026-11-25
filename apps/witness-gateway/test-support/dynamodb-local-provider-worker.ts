import { WorkerEntrypoint } from "cloudflare:workers";
import {
  createLocalDynamoDBWitnessProviderAdapter,
  type AwsDynamoDBWitnessProviderAdapter,
} from "../src/provider/aws-dynamodb-witness-provider-adapter";
import type {
  StoredWitnessCheckpoint,
  WitnessCheckpoint,
  WitnessCheckpointReceipt,
  WitnessCheckpointScope,
  WitnessProviderAdapter,
} from "../src/provider/witness-provider-adapter";

interface Env {
  readonly FENCE_DDB_LOCAL_ENDPOINT: string;
  readonly FENCE_DDB_LOCAL_REGION: string;
  readonly FENCE_DDB_LOCAL_TABLE_NAME: string;
}

/**
 * Test-only RPC adapter. It can connect only through the local factory, whose
 * endpoint guard rejects AWS and non-loopback endpoints. No production secrets
 * or endpoint override are accepted by this Worker.
 */
export class DynamoDBLocalWitnessProvider
  extends WorkerEntrypoint<Env> implements WitnessProviderAdapter {
  private adapter: AwsDynamoDBWitnessProviderAdapter | undefined;

  private getAdapter(): AwsDynamoDBWitnessProviderAdapter {
    if (!this.adapter) {
      this.adapter = createLocalDynamoDBWitnessProviderAdapter({
        endpointUrl: this.env.FENCE_DDB_LOCAL_ENDPOINT,
        region: this.env.FENCE_DDB_LOCAL_REGION,
        tableName: this.env.FENCE_DDB_LOCAL_TABLE_NAME,
      });
    }
    return this.adapter;
  }

  appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expected: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt> {
    return this.getAdapter().appendIfCurrent(checkpoint, expected, idempotencyKey);
  }

  readLatest(scope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    return this.getAdapter().readLatest(scope);
  }

  readByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    return this.getAdapter().readByOperation(scope, operationId);
  }
}

export default {
  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  },
};
