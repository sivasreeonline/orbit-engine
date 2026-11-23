import type {
  WorkloadAuthenticationResult,
  WorkloadProof,
} from "./workload-identity";

export type WitnessEvidenceVerificationResult =
  | {
      readonly verified: true;
      readonly trustBundleGeneration: number;
      readonly trustBundleDigest: string;
      readonly treeHeadDigest: string;
      readonly treeSize: number;
      readonly receiptLeafHash: string;
    }
  | {
      readonly verified: false;
      readonly reason:
        | "malformed_request"
        | "workload_authentication_failed"
        | "trust_configuration_unavailable"
        | "trust_scope_denied"
        | "trust_bundle_invalid"
        | "receipt_invalid"
        | "tree_head_invalid"
        | "inclusion_invalid"
        | "consistency_invalid"
        | "trust_state_conflict"
        | "trust_state_unavailable";
    };

export type WitnessReplayCheckpointResult =
  | {
      readonly checkpointed: true;
      /** Canonical FENCE-001 evidence-verification request bytes returned by the gateway. */
      readonly canonicalEvidenceBody: Uint8Array;
    }
  | {
      readonly checkpointed: false;
      readonly reason:
        | "malformed_request"
        | "workload_authentication_failed"
        | "trust_scope_denied"
        | "provider_unavailable"
        | "append_conflict"
        | "ambiguous_commit"
        | "readback_mismatch";
    };

/** Typed RPC surface shared by the API caller and private gateway Worker. */
export interface WitnessGatewayRpc {
  authenticate(
    proof: WorkloadProof,
    body: Uint8Array,
  ): Promise<WorkloadAuthenticationResult>;

  verifyEvidence(
    proof: WorkloadProof,
    canonicalEvidenceBody: Uint8Array,
  ): Promise<WitnessEvidenceVerificationResult>;

  checkpointReplay(
    proof: WorkloadProof,
    canonicalCheckpointBody: Uint8Array,
  ): Promise<WitnessReplayCheckpointResult>;
}
