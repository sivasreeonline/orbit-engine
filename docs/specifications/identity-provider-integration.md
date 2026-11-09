# Identity Provider Integration Contract

- Status: Proposed integration contract; provider selection is intentionally unresolved.
- Scope: API authentication and tenant-aware authorization for the M1 coding-judge control plane.
- Non-goal: This document does not configure a real identity provider or enable execution endpoints.

## 1. Security invariants

1. A request is anonymous until a configured `Authenticator` validates its credential.
2. The API derives `userId`, tenant membership and roles from verified identity-provider claims and/or a trusted server-side membership lookup.
3. `X-Tenant-ID`, `X-User-ID`, `X-User-Role`, query parameters and request-body fields are never identity sources.
4. The active tenant is selected only from memberships the authenticated user is authorized to use. A client may request a tenant context only if the server verifies membership and role in that tenant.
5. Missing, malformed, expired, wrong-issuer, wrong-audience, revoked (where supported) or unverifiable credentials fail closed.
6. Identity-provider/JWKS outages do not fall back to mock identity, cached unbounded credentials, or client-supplied identity.
7. Every data access and mutation is scoped by the authenticated principal and the resource's tenant/college/batch authorization.
8. Correlation IDs are observability metadata, not authentication or authorization credentials.

## 2. Provider adapter boundary

Keep the existing `Authenticator` interface as the API boundary:

- Input: the HTTP `Request`.
- Output: either a verified `Principal` or a typed unauthenticated result.
- The adapter owns token extraction, signature verification, issuer/audience checks, time-claim validation, key rotation handling and mapping to the platform principal.
- The API handler must not parse tokens or trust unverified JWT payloads.
- Provider SDKs and provider-specific claims stay inside the adapter module.

The provider must be selected before implementation. Required provider capabilities:
- OIDC/OAuth 2.0 standards-based integration.
- Signed access tokens or a supported server-side token introspection flow.
- Documented issuer and audience configuration.
- Key rotation/JWKS support, short-lived access tokens and secure session lifecycle.
- A stable subject identifier and a supported way to resolve college/tenant membership and roles.
- Operational controls for disabling users and revoking sessions/tokens.

Do not choose a provider based only on frontend convenience. Record the provider, trust model, token type, claims mapping and operational ownership in a separate ADR after review.

## 3. Principal mapping

The API's internal principal remains provider-neutral:

| Field | Meaning | Trust source |
| --- | --- | --- |
| `userId` | Stable Sky High user identifier | Trusted identity mapping |
| `tenantId` | Active college/tenant scope | Verified membership and server-side selection |
| `roles` | Roles within the active tenant | Trusted membership/authorization service |

Do not assume an email address is a stable identifier. Do not treat a role supplied by the browser as authoritative. If the provider subject differs from the Sky High user ID, maintain an explicit server-side identity mapping.

If a user belongs to multiple colleges, the selected tenant must be validated against active memberships for every request or against a cryptographically protected, short-lived server-issued tenant context. A raw tenant header is never sufficient.

## 4. Request processing order

1. Generate or validate the bounded correlation ID.
2. Apply origin/CORS policy; CORS is not authorization.
3. Resolve the route and reject unknown methods/paths.
4. Authenticate the access credential.
5. Resolve active tenant membership and roles.
6. Validate resource-level authorization (college, batch, ownership, trainer scope).
7. Validate request data and quotas.
8. Access tenant-scoped repositories.
9. Emit sanitized response and security audit event.

Health/liveness may remain unauthenticated. Readiness may check dependencies without exposing tenant data. All student, trainer and TPO data routes require an authenticated principal and explicit authorization.

## 5. Token validation requirements

For JWT-based access tokens, enforce:
- Exact configured issuer and API audience.
- Explicit algorithm allowlist; reject `none` and algorithm/key-type confusion.
- Signature validation using trusted issuer keys, including safe key rotation.
- Required subject and time claims; validate expiry and not-before with bounded clock skew.
- Token type/use appropriate for API access; do not accept ID tokens as access tokens.
- Reject unknown signing keys and malformed claims.
- Bound token size and parsing work.
- Never log bearer tokens, cookies, raw claims or authorization headers.

If opaque-token introspection is selected instead, require authenticated introspection, active status, expected audience/resource binding, bounded network timeout and fail-closed behavior.

## 6. Authorization model

Authentication establishes who the user is; authorization determines what they can access.

- Student: access own profile, attempts and submissions within active tenant; browse published problems visible to tenant.
- Trainer: access only assigned batches and authorized student progress within the same tenant.
- TPO/college administrator: access only explicitly granted college-level resources.
- Platform operator: privileged cross-tenant access only through a separate audited support path; never infer it from a tenant role.
- Service identity: separate machine principal and narrow service scopes for runner callbacks and outbox dispatch. Never reuse a student token for service-to-service calls.

Every repository method that reads tenant-owned data must receive trusted tenant context (or a typed authorized scope) from the service layer. Avoid repository methods that silently default to global scope.

## 7. Failure behavior

| Condition | API behavior |
| --- | --- |
| Missing/invalid/expired credential | 401, stable non-disclosing error |
| Valid identity but no active tenant membership | 403 |
| Valid identity but insufficient role/resource scope | 403 (or non-disclosing 404 where enumeration is a concern) |
| Provider/JWKS unavailable | 503, fail closed, bounded retry guidance |
| Malformed trusted identity mapping | 403 and security event |
| Unexpected internal error | Generic 500; no token, claim, SQL or provider detail |

Do not silently downgrade authentication. Do not create a local fallback user.

## 8. Required test matrix

- Missing, malformed, oversized, expired and not-yet-valid token.
- Wrong issuer, wrong audience, unsupported algorithm, invalid signature and unknown key ID.
- Key rotation: known old key during allowed overlap and new key after rotation.
- ID token presented where access token is required.
- Missing subject, missing mapping, disabled user and revoked session where supported.
- Provider timeout, DNS/TLS failure, 5xx and malformed provider response.
- Tenant A user attempting Tenant B access by changing headers, path, query and body.
- Multi-tenant user selecting a tenant without membership.
- Student attempting trainer/TPO endpoints and trainer attempting an unassigned batch.
- Cross-tenant repository access, including list, detail, status and timeline.
- No bearer token or sensitive claim in logs, traces or error bodies.

Tests must assert that repositories and runner dispatch are not called after authentication/authorization failure.

## 9. Rollout gates

1. Select provider and approve a provider-specific ADR.
2. Define canonical user/tenant/membership source and provisioning/deprovisioning lifecycle.
3. Implement provider adapter behind `Authenticator`; keep `UnconfiguredAuthenticator` as the default until configuration is valid.
4. Complete the test matrix with deterministic fixtures and provider integration tests.
5. Configure secrets/issuer/audience through deployment configuration, not source control.
6. Verify tenant isolation and audit events in a staging environment.
7. Only then enable protected read routes in a controlled pilot.

No production identity provider is selected by this proposal.
