import type { Env } from "../env";
import type {
  WorkloadAuthenticationResult,
  WorkloadProof,
} from "./workload-identity";

export type WitnessGatewayCallResult =
  | WorkloadAuthenticationResult
  | { readonly authenticated: false; readonly reason: "gateway_unavailable" };

/** Invoke only through the configured private Service Binding RPC capability. */
export async function authenticateViaWitnessGateway(
  env: Pick<Env, "WITNESS_GATEWAY">,
  proof: WorkloadProof,
  body: Uint8Array,
): Promise<WitnessGatewayCallResult> {
  if (!env.WITNESS_GATEWAY) {
    return { authenticated: false, reason: "gateway_unavailable" };
  }
  try {
    return await env.WITNESS_GATEWAY.authenticate(proof, body);
  } catch {
    return { authenticated: false, reason: "gateway_unavailable" };
  }
}
