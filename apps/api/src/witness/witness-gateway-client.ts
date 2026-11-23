import type { Env } from "../env";
import type {
  WorkloadAuthenticationResult,
  WorkloadProof,
} from "./workload-identity";
import { createApiWorkloadProof } from "./workload-proof-signer";

export type WitnessGatewayCallResult =
  | WorkloadAuthenticationResult
  | {
      readonly authenticated: false;
      readonly reason:
        | "gateway_unavailable"
        | "caller_identity_unconfigured"
        | "caller_proof_signing_failed";
    };

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

/**
 * Sign and authenticate an API Worker operation. No private key is sent over
 * RPC; only the short-lived proof and exact body bytes cross the binding.
 */
export async function authenticateApiWorkerWithWitnessGateway(
  env: Pick<
    Env,
    | "WITNESS_GATEWAY"
    | "WORKLOAD_CALLER_ID"
    | "WORKLOAD_CALLER_KEY_ID"
    | "WORKLOAD_CALLER_PRIVATE_KEY_PKCS8"
  >,
  body: Uint8Array,
): Promise<WitnessGatewayCallResult> {
  if (!env.WITNESS_GATEWAY) {
    return { authenticated: false, reason: "gateway_unavailable" };
  }
  const created = await createApiWorkloadProof(
    {
      ...(env.WORKLOAD_CALLER_ID !== undefined
        ? { callerId: env.WORKLOAD_CALLER_ID }
        : {}),
      ...(env.WORKLOAD_CALLER_KEY_ID !== undefined
        ? { keyId: env.WORKLOAD_CALLER_KEY_ID }
        : {}),
      ...(env.WORKLOAD_CALLER_PRIVATE_KEY_PKCS8 !== undefined
        ? { privateKeyPkcs8: env.WORKLOAD_CALLER_PRIVATE_KEY_PKCS8 }
        : {}),
    },
    body,
  );
  if (!created.created) {
    return { authenticated: false, reason: created.reason };
  }
  return authenticateViaWitnessGateway(env, created.proof, body);
}
