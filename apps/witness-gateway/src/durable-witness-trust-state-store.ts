import type {
  TreeHeadAdvanceInput,
  TrustBundleAdvanceInput,
  WitnessTrustScope,
  WitnessTrustSnapshot,
  WitnessTrustWriteResult,
} from "./witness-trust-state-do";

export interface WitnessTrustStateStub {
  readSnapshot(scope: WitnessTrustScope): Promise<WitnessTrustSnapshot>;
  advanceTrustBundle(input: TrustBundleAdvanceInput): Promise<WitnessTrustWriteResult>;
  advanceTreeHead(input: TreeHeadAdvanceInput): Promise<WitnessTrustWriteResult>;
}

/** Maps each trust-domain/witness pair to one durable, serialized state object. */
export class DurableWitnessTrustStateStore {
  constructor(private readonly namespace: DurableObjectNamespace) {}

  private stub(scope: WitnessTrustScope): WitnessTrustStateStub {
    const id = this.namespace.idFromName(`${scope.trustDomainId}:${scope.witnessId}`);
    return this.namespace.get(id) as unknown as WitnessTrustStateStub;
  }

  readSnapshot(scope: WitnessTrustScope): Promise<WitnessTrustSnapshot> {
    return this.stub(scope).readSnapshot(scope);
  }

  advanceTrustBundle(input: TrustBundleAdvanceInput): Promise<WitnessTrustWriteResult> {
    return this.stub(input.scope).advanceTrustBundle(input);
  }

  advanceTreeHead(input: TreeHeadAdvanceInput): Promise<WitnessTrustWriteResult> {
    return this.stub(input.scope).advanceTreeHead(input);
  }
}
