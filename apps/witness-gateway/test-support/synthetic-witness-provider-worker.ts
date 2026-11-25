import { WorkerEntrypoint } from "cloudflare:workers";
import { SyntheticWitnessProviderAdapter } from "./synthetic-witness-provider-adapter";
import type {
  StoredWitnessCheckpoint,
  WitnessCheckpoint,
  WitnessCheckpointReceipt,
  WitnessCheckpointScope,
  WitnessProviderAdapter,
} from "../src/provider/witness-provider-adapter";

interface Env {
  /** One-shot provider fault injection for API recovery tests only. */
  readonly FENCE_TEST_PROVIDER_LOSE_NEXT_ACK?: string;
}

const provider = new SyntheticWitnessProviderAdapter();
let lostAckFaultConsumed = false;

/** Test-only in-memory provider. It receives no evidence-authority private key. */
export class SyntheticWitnessProvider
  extends WorkerEntrypoint<Env> implements WitnessProviderAdapter {
  appendIfCurrent(
    checkpoint: WitnessCheckpoint,
    expected: { readonly generation: number; readonly digest: string },
    idempotencyKey: string,
  ): Promise<WitnessCheckpointReceipt> {
    if (this.env.FENCE_TEST_PROVIDER_LOSE_NEXT_ACK === "true" && !lostAckFaultConsumed) {
      provider.loseNextAck = true;
      lostAckFaultConsumed = true;
    }
    return provider.appendIfCurrent(checkpoint, expected, idempotencyKey);
  }

  readLatest(scope: WitnessCheckpointScope): Promise<StoredWitnessCheckpoint | null> {
    return provider.readLatest(scope);
  }

  readByOperation(
    scope: WitnessCheckpointScope,
    operationId: string,
  ): Promise<StoredWitnessCheckpoint | null> {
    return provider.readByOperation(scope, operationId);
  }
}

export default {
  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  },
};
