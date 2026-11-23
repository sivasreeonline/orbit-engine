import type { WitnessGatewayRpc } from "../../witness-gateway/src/index";

export interface HyperdriveBinding {
  readonly connectionString: string;
}

export interface Env {
  readonly HYPERDRIVE?: HyperdriveBinding;
  readonly CORS_ALLOWED_ORIGINS?: string;
  readonly APP_ENV?: string;
  readonly GOSSIP_REPLAY?: DurableObjectNamespace;
  readonly WORKLOAD_NONCE_REPLAY?: DurableObjectNamespace;
  /** Private Worker-to-Worker RPC; never exposed as a public URL. */
  readonly WITNESS_GATEWAY?: WitnessGatewayRpc;
  /** API Worker workload identity; private PKCS#8 material is a Worker secret. */
  readonly WORKLOAD_CALLER_ID?: string;
  readonly WORKLOAD_CALLER_KEY_ID?: string;
  readonly WORKLOAD_CALLER_PRIVATE_KEY_PKCS8?: string;
}
