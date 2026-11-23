import type {
  WorkloadAuthenticationResult,
  WorkloadProof,
} from "./workload-identity";

/** Typed RPC surface shared by the API caller and private gateway Worker. */
export interface WitnessGatewayRpc {
  authenticate(
    proof: WorkloadProof,
    body: Uint8Array,
  ): Promise<WorkloadAuthenticationResult>;
}
