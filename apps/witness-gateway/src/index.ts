import { WorkerEntrypoint } from "cloudflare:workers";
import {
  authenticateWorkloadCall,
  type TrustedWorkloadKey,
  type WorkloadAuthenticationResult,
  type WorkloadProof,
} from "../../api/src/witness/workload-identity";
import { DurableWorkloadNonceStore } from "../../api/src/auth/durable-workload-nonce-store";
import type { WitnessGatewayRpc } from "../../api/src/witness/witness-gateway-contract";

const AUDIENCE = "sky-high-witness-gateway";
const SCOPE = "witness:authorize";
const METHOD = "POST";
const PATH = "/rpc/authenticate";

export interface GatewayEnv {
  readonly WORKLOAD_NONCE_REPLAY: DurableObjectNamespace;
  readonly WITNESS_TRUST_STATE: DurableObjectNamespace;
  /** JSON array of pinned public-key records; never a private key. */
  readonly WORKLOAD_CALLER_KEYS?: string;
}

/** Parse the pinned public-key allowlist. Missing or malformed config fails closed. */
export function parseTrustedWorkloadKeys(
  serialized: string | undefined,
): readonly TrustedWorkloadKey[] | null {
  if (!serialized) return null;
  try {
    const parsed: unknown = JSON.parse(serialized);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    for (const entry of parsed) {
      if (
        !entry ||
        typeof entry !== "object" ||
        typeof entry.callerId !== "string" ||
        typeof entry.keyId !== "string" ||
        typeof entry.publicKeyBase64Url !== "string" ||
        !Array.isArray(entry.audiences) ||
        !entry.audiences.every((value: unknown) => typeof value === "string") ||
        !Array.isArray(entry.scopes) ||
        !entry.scopes.every((value: unknown) => typeof value === "string") ||
        !Number.isSafeInteger(entry.notBefore) ||
        !Number.isSafeInteger(entry.notAfter)
      ) {
        return null;
      }
    }
    return parsed as TrustedWorkloadKey[];
  } catch {
    return null;
  }
}

/**
 * Private RPC-only gateway. Its fetch surface is intentionally closed; API
 * Workers reach it through a Service Binding, but identity is still verified
 * cryptographically and replay-protected before an authorization result.
 */
export class WitnessGateway extends WorkerEntrypoint<GatewayEnv> implements WitnessGatewayRpc {
  async authenticate(
    proof: WorkloadProof,
    body: Uint8Array,
  ): Promise<WorkloadAuthenticationResult> {
    const trustedKeys = parseTrustedWorkloadKeys(this.env.WORKLOAD_CALLER_KEYS);
    if (!trustedKeys) {
      return { authenticated: false, reason: "unknown_key" };
    }
    if (!(body instanceof Uint8Array)) {
      return { authenticated: false, reason: "malformed_proof" };
    }

    return authenticateWorkloadCall(
      proof,
      {
        audience: AUDIENCE,
        scope: SCOPE,
        method: METHOD,
        path: PATH,
        body,
      },
      trustedKeys,
      Math.floor(Date.now() / 1_000),
      new DurableWorkloadNonceStore(this.env.WORKLOAD_NONCE_REPLAY),
    );
  }

}

export type { WitnessGatewayRpc } from "../../api/src/witness/witness-gateway-contract";
export { WorkloadNonceReplayDO } from "../../api/src/auth/workload-nonce-replay-do";
export { WitnessTrustStateDO } from "./witness-trust-state-do";

/** Default HTTP surface is deliberately inert; RPC uses the named entrypoint. */
export default {
  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  },
};