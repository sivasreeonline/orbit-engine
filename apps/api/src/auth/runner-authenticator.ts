/**
 * Runner workload identity is a separate trust domain from human Sky High
 * identities. Implementations must derive this principal from verified
 * machine credentials plus a trusted runner registry, never request fields.
 */
export type RunnerScope =
  | "dispatch:claim"
  | "dispatch:receipt"
  | "dispatch:retry";

export interface RunnerPrincipal {
  /** Stable server-registered runner identity; never a client-supplied ID. */
  readonly runnerId: string;
  /** Server-assigned pool used to constrain which dispatches may be claimed. */
  readonly poolId: string;
  /** Stable subject from the verified machine-identity system. */
  readonly subject: string;
  /** Least-privilege operations granted to this runner identity. */
  readonly scopes: readonly RunnerScope[];
}

export type RunnerAuthenticationResult =
  | { readonly authenticated: true; readonly principal: RunnerPrincipal }
  | {
      readonly authenticated: false;
      readonly reason: "missing" | "invalid" | "provider_unavailable";
    };

/**
 * Validates a machine credential and resolves it to a registered runner.
 *
 * Implementations must fail closed on unknown identities, invalid credentials,
 * registry/key-service outages, expired credentials and revoked identities.
 * They must not infer runnerId, poolId or scopes from request headers/body.
 */
export interface RunnerAuthenticator {
  authenticate(request: Request): Promise<RunnerAuthenticationResult>;
}
