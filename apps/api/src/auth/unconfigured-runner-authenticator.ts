import type {
  RunnerAuthenticationResult,
  RunnerAuthenticator,
} from "./runner-authenticator";

/**
 * Runner control-plane operations remain disabled until a machine identity
 * provider and trusted runner registry have been selected and configured.
 */
export class UnconfiguredRunnerAuthenticator implements RunnerAuthenticator {
  async authenticate(_request: Request): Promise<RunnerAuthenticationResult> {
    return {
      authenticated: false,
      reason: "provider_unavailable",
    };
  }
}
