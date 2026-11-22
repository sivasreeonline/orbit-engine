import type { GossipReplayStateDO } from "./gossip/gossip-replay-state-do";

export interface HyperdriveBinding {
  readonly connectionString: string;
}

export interface Env {
  readonly HYPERDRIVE?: HyperdriveBinding;
  readonly CORS_ALLOWED_ORIGINS?: string;
  readonly APP_ENV?: string;
  readonly GOSSIP_REPLAY: DurableObjectNamespace<GossipReplayStateDO>;
}
