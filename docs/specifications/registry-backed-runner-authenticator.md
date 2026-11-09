# Registry-Backed Runner Authenticator

Status: implementation foundation; provider-neutral and not production-enabled.

## Trust sequence

1. A provider-specific `RunnerCredentialVerifier` receives the HTTP request.
2. The verifier validates the machine credential using the provider's documented mechanism. For a JWT-based provider this includes signature verification against trusted keys, exact issuer and audience checks, expiry/not-before checks, and required subject/identity claims. Key rotation and provider outage behavior must be explicit.
3. Only after successful verification does the verifier return the verified issuer and subject.
4. `RegistryBackedRunnerAuthenticator` resolves that exact pair through `RunnerIdentityResolver`.
5. The registry supplies runner ID, pool ID and allowlisted scopes. The request cannot supply or override these values.
6. A route must check its required scope with `runnerHasScope` before performing the operation.

## Fail-closed behavior

- Missing credential: `missing`.
- Invalid credential or unknown/inactive registry identity: `invalid`.
- Provider verifier exception/outage, registry outage, or registry integrity failure: `provider_unavailable`.
- No registry lookup occurs after a missing or invalid credential.
- Raw credentials and provider error details are not returned or logged by this composition.
- The human-user authenticator remains a separate trust domain.

## Explicit non-goals

This composition does not implement JWT parsing, signature verification, JWKS retrieval, Cloudflare Access integration, service-token provisioning, mTLS, credential rotation, or revocation propagation. Those belong in a provider-specific verifier and deployment proof.

It does not register HTTP routes, consume Cloudflare Queue messages, retrieve source artifacts, or execute student code. The existing unconfigured runner authenticator and executor remain fail-closed until a provider and security gates are approved.

## Required provider adapter tests

Before enabling a provider adapter, prove:
- invalid signatures, wrong issuer/audience, expired and not-yet-valid credentials are rejected;
- key rotation and unknown key IDs fail closed without unsafe stale-key behavior;
- direct-origin/bypass requests cannot evade the intended edge policy;
- one unique provider identity maps to one registry row and runner;
- suspended/revoked identities and disabled pools are rejected promptly;
- route scopes are enforced from registry state, never request fields;
- secrets and credentials never appear in logs, traces, errors or queue messages.

## Validation boundary

Unit tests for the composition prove ordering and fail-closed behavior with injected verifier/registry doubles. They do not prove any real provider's cryptographic or deployment behavior.
