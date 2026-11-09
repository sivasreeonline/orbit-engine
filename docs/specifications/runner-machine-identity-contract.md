# Runner Machine Identity Contract

- Status: provider-neutral contract proposal; no authentication mechanism selected.
- Scope: trusted identity and authorization boundary for future Linux runner-agent control APIs.
- Depends on: runner-agent control API proposal and the provider-neutral human identity integration boundary.
- Implementation in this change: TypeScript interface plus a fail-closed default authenticator and tests only.

## 1. Separate trust domain

Runner agents are workloads, not Sky High users. They must not authenticate with student, trainer, TPO or platform-operator sessions. The existing human `Authenticator` and `Principal` remain unchanged.

The runner control plane will use a separate `RunnerAuthenticator` and `RunnerPrincipal`. No HTTP route is enabled by this contract.

## 2. Trusted runner principal

A successful authenticator returns:

| Field | Meaning | Authoritative source |
| --- | --- | --- |
| `runnerId` | Stable registered runner identity used by dispatch lease/receipt persistence | Server-side runner registry |
| `poolId` | Runner pool assignment | Server-side runner registry/policy |
| `subject` | Stable subject from the verified machine identity | Configured identity issuer |
| `scopes` | Narrow allowed operations | Server-side runner authorization policy |

Initial scope vocabulary:

- `dispatch:claim`
- `dispatch:receipt`
- `dispatch:retry`

A route must check the required scope before touching a repository. A claim operation must pass the principal's server-assigned pool and runner ID to persistence. A receipt/retry operation must derive runner ID from the principal and verify the active database lease token. Request-body or header values must never override the authenticated identity.

## 3. Authentication adapter requirements

A configured adapter must:

1. Validate a supported machine credential cryptographically or through a trusted introspection service.
2. Validate issuer, audience/resource, expiry, not-before, token/certificate status and allowed credential type as applicable.
3. Resolve the verified subject to an active registered runner and its pool/scopes.
4. Enforce bounded credential size, parsing work and provider/network timeouts.
5. Fail closed for missing, malformed, expired, revoked, unknown or unverifiable credentials.
6. Fail closed when issuer metadata, key rotation data, introspection or the runner registry is unavailable.
7. Never log credentials, raw authorization headers or sensitive token claims.
8. Bind each runner to the minimum required pool and operation scopes.

The interface deliberately does not prescribe JWT claims, certificate fields, header names, provider SDKs or key storage. Those depend on the selected mechanism and must not be guessed by a generic adapter.

## 4. Fail-closed default

`UnconfiguredRunnerAuthenticator` always returns `provider_unavailable`. It does not parse or trust `Authorization`, `X-Runner-ID`, `X-Runner-Pool` or `X-Runner-Scopes`. This remains the default until a provider-specific adapter, runner registry and operational rotation/revocation process are reviewed.

## 5. Provider decision remains open

Evaluate at least:

- Per-runner mutual TLS certificates with server-side certificate-to-runner mapping.
- Cloudflare Access service tokens or another gateway-issued workload identity, only after verifying how authenticated identity is securely conveyed to the Worker and cannot be spoofed by a direct request.
- Short-lived signed service assertions from an approved issuer, with strict issuer/audience/key-rotation validation.
- Provider-managed workload identity where supported by both the Cloudflare control plane and Linux runner environment.

Compare revocation latency, rotation, workload binding, Worker compatibility, private transport requirements, local development, observability and compromise blast radius. A shared static API key is not an acceptable production identity model.

No option is selected here. Provider selection requires a separate reviewed ADR and a non-production proof of identity propagation and revocation.

## 6. Required tests before exposing routes

- Missing and invalid credentials are rejected.
- Unknown, disabled and revoked runner identities are rejected.
- A runner cannot claim outside its registered pool.
- A runner lacking a required scope cannot claim, receipt or retry.
- Client-supplied runner ID, pool or scopes are rejected or ignored.
- Human user credentials cannot authenticate as a runner.
- Provider/registry outage fails closed with bounded timeouts.
- Key/certificate rotation and revocation behave as specified by the selected provider.
- No credential or sensitive claim appears in logs or error responses.
- Authentication failure never calls claim, receipt, retry or artifact repositories.

## 7. Explicit non-goals

This proposal does not select or configure a provider, add credentials/secrets, add runner registry tables, add HTTP routes/middleware, alter human authentication, expose dispatch operations, retrieve source artifacts, consume queues or enable execution. The runner executor remains fail-closed and gVisor M0 evidence remains a separate prerequisite.
