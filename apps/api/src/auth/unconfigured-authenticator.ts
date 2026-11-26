import type { Authenticator, AuthenticationResult } from "../contracts";

/**
 * M1 deliberately fails closed until the Sky High identity provider contract
 * is connected. Never trust a client-supplied user or tenant header.
 */
export class UnconfiguredAuthenticator implements Authenticator {
  async authenticate(_request: Request): Promise<AuthenticationResult> {
    return {
      authenticated: false,
      reason: "provider_unavailable",
    };
  }
}
