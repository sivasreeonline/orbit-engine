import type {
  RunnerAuthenticationResult,
  RunnerAuthenticator,
  RunnerPrincipal,
  RunnerScope,
} from "./runner-authenticator";

/**
 * Identity fields returned only after a provider adapter has verified the
 * credential's signature, issuer, audience, expiry and required claims.
 *
 * Implementations must never populate these fields from request headers,
 * query parameters or body fields.
 */
export interface VerifiedRunnerIdentity {
  readonly issuer: string;
  readonly subject: string;
}

export type RunnerCredentialVerificationResult =
  | { readonly verified: true; readonly identity: VerifiedRunnerIdentity }
  | {
      readonly verified: false;
      readonly reason: "missing" | "invalid" | "provider_unavailable";
    };

/** Provider-specific cryptographic verification; no registry lookup occurs here. */
export interface RunnerCredentialVerifier {
  verify(request: Request): Promise<RunnerCredentialVerificationResult>;
}

/** Resolves a verified provider identity to server-managed registry state. */
export interface RunnerIdentityResolver {
  findActivePrincipal(
    issuer: string,
    subject: string,
  ): Promise<RunnerPrincipal | null>;
}

/**
 * Composes provider credential verification with the trusted runner registry.
 * The provider verifier must validate the credential before returning issuer
 * and subject. Runner IDs, pools and scopes always come from the registry.
 */
export class RegistryBackedRunnerAuthenticator implements RunnerAuthenticator {
  constructor(
    private readonly verifier: RunnerCredentialVerifier,
    private readonly registry: RunnerIdentityResolver,
  ) {}

  async authenticate(request: Request): Promise<RunnerAuthenticationResult> {
    let verification: RunnerCredentialVerificationResult;
    try {
      verification = await this.verifier.verify(request);
    } catch {
      return { authenticated: false, reason: "provider_unavailable" };
    }

    if (!verification.verified) {
      return {
        authenticated: false,
        reason: verification.reason,
      };
    }

    const { issuer, subject } = verification.identity;
    if (
      typeof issuer !== "string" ||
      issuer.length < 1 ||
      issuer.length > 512 ||
      issuer !== issuer.trim() ||
      typeof subject !== "string" ||
      subject.length < 1 ||
      subject.length > 512 ||
      subject !== subject.trim()
    ) {
      return { authenticated: false, reason: "invalid" };
    }

    try {
      const principal = await this.registry.findActivePrincipal(issuer, subject);
      if (!principal) return { authenticated: false, reason: "invalid" };
      return { authenticated: true, principal };
    } catch {
      // Registry outages and integrity failures must not authenticate a runner.
      return { authenticated: false, reason: "provider_unavailable" };
    }
  }
}

/** Check a required operation against registry-derived least-privilege scopes. */
export function runnerHasScope(
  principal: RunnerPrincipal,
  requiredScope: RunnerScope,
): boolean {
  return principal.scopes.includes(requiredScope);
}
