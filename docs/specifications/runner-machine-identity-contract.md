# Runner Machine Identity Contract

- Status: provider-neutral contract proposal; no authentication mechanism selected.
- Scope: trusted identity and authorization boundary for future Linux runner-agent control APIs.
- Depends on: runner-agent control API proposal and the provider-neutral human identity integration boundary.
- Implementation foundation in this PR stack: TypeScript interface, fail-closed default authenticator, provider-neutral runner registry migration and PostgreSQL acceptance tests. Provider-specific credential verification remains unimplemented.

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

The interface deliberately does not prescribe JWT claims, certificate fields, header names, provider SDKs or key storage. Those depend on the selected mechanism and must not be guessed by a generic adapter. Migration 0006 adds a provider-neutral registry mapping exact issuer/subject pairs to server-managed runner IDs, pools and scopes. It stores no credentials and does not itself authenticate requests; see [Runner Identity Registry Foundation](runner-identity-registry-foundation.md).

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

This proposal does not select or configure a provider, add credentials/secrets, add an authentication adapter or registry-management API, add runner HTTP routes/middleware, alter human authentication, expose dispatch operations, retrieve source artifacts, consume queues or enable execution. The provider-neutral registry schema is only a persistence foundation; it has no production registration workflow or configured resolver. The runner executor remains fail-closed and gVisor M0 evidence remains a separate prerequisite.


## 8. Cloudflare deployment fit — evidence-based candidate comparison

The following is a preliminary platform-fit assessment, not a provider decision. Documentation was checked on 2026-11-09.

| Candidate | Cloudflare fit | Operational strengths | Important caveats |
| --- | --- | --- | --- |
| Cloudflare Access service token + validated Access JWT | Strong candidate for a first non-production proof | Per-token identity, expiration, individual rotation/revocation, Service Auth policies and Access audit logs | The Worker must cryptographically validate the `Cf-Access-Jwt-Assertion` signature and claims. Never trust the presence/value of an Access header alone. Must prove direct-origin/bypass paths cannot reach protected handlers. |
| Inbound mTLS at the Worker hostname | Strong edge-authentication candidate | TLS handshake rejects clients without an accepted certificate; Workers expose client-certificate validation metadata | Must enforce certificate verification/revocation in Worker policy and map certificate identity to runner registry. Cloudflare-managed client-certificate quota is 100 active certificates per zone by default; BYOCA has Enterprise constraints. |
| Short-lived signed service assertion | Portable alternative | Can be independent of edge-specific service-token format; short expiry and audience binding can reduce replay window | Requires a trusted issuer, signing-key lifecycle/JWKS rotation, revocation strategy and careful validation in the Worker. No issuer is selected. |
| Worker mTLS binding | Not an inbound runner-auth mechanism | Useful when the Worker calls an external origin that requires client certificates | This binding presents a certificate on Worker-to-origin subrequests; it does not authenticate a Linux runner calling the Worker. |

### Evidence and implications

- Cloudflare Access service tokens consist of a Client ID and Client Secret, can be assigned an expiry, rotated with a grace period, disabled/revoked individually and constrained by Service Auth policies. For origin validation, Cloudflare sends a `Cf-Access-Jwt-Assertion`; the application should validate its signature using the account's Access public keys. Access signing keys rotate every six weeks by default. Therefore, a future Worker adapter must validate signature, issuer, audience, time claims and the service identity mapping; checking only that Access headers exist is insufficient.
- Cloudflare inbound client-certificate authentication validates the TLS client certificate at the edge and exposes validation details through `request.cf.tlsClientAuth`. A Worker can use that verified metadata to map the certificate to a registered runner. The route must reject missing, unverified or revoked certificates. This is distinct from the Workers mTLS binding, which is for the Worker presenting a client certificate to an external service.
- Neither mechanism removes the need for the Sky High runner registry, pool mapping, least-privilege scopes, per-runner revocation and PostgreSQL lease fencing.

Official documentation reviewed:

- Cloudflare Access service tokens: https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/
- Validate Access JWTs: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
- Cloudflare client certificates / inbound mTLS: https://developers.cloudflare.com/ssl/client-certificates/
- Worker client-certificate variables: https://developers.cloudflare.com/ssl/client-certificates/client-certificate-variables/
- Workers mTLS binding (outbound distinction): https://developers.cloudflare.com/workers/runtime-apis/bindings/mtls/

### Recommended next proof, not production selection

For the first non-production experiment, test **Cloudflare Access service tokens with one unique token per runner**, a narrowly scoped Service Auth policy, and explicit JWT assertion verification inside the Worker before mapping the verified service identity to a registered `runnerId` and `poolId`. Prove that direct/bypass requests cannot reach the internal route, key rotation works, and an individual token can be revoked without affecting other runners.

In parallel, measure inbound mTLS if the runner population or credential lifecycle justifies per-runner certificates. Do not treat the Workers outbound mTLS binding as a substitute for inbound client authentication.

No Access application, token, certificate, Worker binding, secret or route was configured by this change. The candidate must be validated in the actual Sky High Cloudflare account before an ADR can select it.
