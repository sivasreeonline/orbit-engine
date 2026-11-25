import { WorkerEntrypoint } from "cloudflare:workers";
import {
  createAwsDynamoDBWitnessProviderAdapter,
  type AwsDynamoDBWitnessProviderAdapter,
} from "./provider/aws-dynamodb-witness-provider-adapter";
import type {
  StoredWitnessCheckpoint,
  WitnessCheckpoint,
  WitnessCheckpointReceipt,
  WitnessCheckpointScope,
  WitnessProviderAdapter,
} from "./provider/witness-provider-adapter";

interface Env {
  /** Explicit opt-in; absent/false keeps all provider operations unavailable. */
  readonly WITNESS_DDB_WRITES_ENABLED?: string;
  readonly WITNESS_DDB_REGION?: string;
  readonly WITNESS_DDB_TABLE?: string;
  /** Configure as Worker secrets only after the external qualification gate. */
  readonly WITNESS_DDB_ACCESS_KEY_ID?: string;
  readonly WITNESS_DDB_SECRET_ACCESS_KEY?: string;
  readonly WITNESS_DDB_SESSION_TOKEN?: string;
}

/**
 * Private provider service. It has no public HTTP API; the gateway reaches this
 * class only through a Cloudflare service binding / Worker RPC entrypoint.
 *
 * This service owns the DynamoDB client and is the only Worker that receives
 * provider credentials. It remains inert until an operator explicitly enables
 * writes and supplies the required secrets and table configuration.
 */
export class WitnessProvider extends WorkerEntrypoint<Env> implements WitnessProviderAdapter {
  private adapterInstance?: AwsDynamoDBWitnessProviderAdapter;

  private getAdapter(): AwsDynamoDBWitnessProviderAdapter {
    const env = this.env;
    if (env.WITNESS_DDB_WRITES_ENABLED !== "true") {
      throw new Error("witness provider is disabled");
    }
    if (
      !env.WITNESS_DDB_REGION ||
      !env.WITNESS_DDB_TABLE ||
      !env.WITNESS_DDB_ACCESS_KEY_ID ||
      !env.WITNESS_DDB_SECRET_ACCESS_KEY
    ) throw new Error("witness provider configuration is unavailable");

    if (!this.adapterInstance) {
      this.adapterInstance = createAwsDynamoDBWitnessProviderAdapter({
        region: env.WITNESS_DDB_REGION,
        tableName: env.WITNESS_DDB_TABLE,
        accessKeyId: env.WITNESS_DDB_ACCESS_KEY_ID,
        secretAccessKey: env.WITNESS_DDB_SECRET_ACCESS_KEY,
        ...(env.WITNESS_DDB_SESSION_TOKEN
          ? { sessionToken: env.WITNESS_DDB_SESSION_TOKEN }
          : {}),
      });
    }
    return this.adapterInstance;
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
