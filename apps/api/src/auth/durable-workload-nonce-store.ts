import type { WorkloadNonceStore } from "../witness/workload-identity";

interface WorkloadNonceReplayStub {
  consumeNonce(
    callerId: string,
    nonce: string,
    expiresAt: number,
    trustedNow: number,
  ): Promise<boolean>;
}

/** Adapts the caller-scoped Durable Object namespace to the verifier contract. */
export class DurableWorkloadNonceStore implements WorkloadNonceStore {
  constructor(private readonly namespace: DurableObjectNamespace) {}

  async consumeNonce(
    callerId: string,
    nonce: string,
    expiresAt: number,
    trustedNow: number,
  ): Promise<boolean> {
    const id = this.namespace.idFromName(callerId);
    const stub = this.namespace.get(id) as unknown as WorkloadNonceReplayStub;
    return stub.consumeNonce(callerId, nonce, expiresAt, trustedNow);
  }
}
