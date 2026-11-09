# Runner Identity Registry Foundation

- Status: provider-neutral database foundation; no machine identity provider selected.
- Migration: `0006_runner_identity_registry.sql`.
- Depends on: PR #38 runner machine identity contract.
- Scope: persist server-managed runner identity-to-pool authorization mappings and lifecycle state.
- Not an authentication implementation: verified identity resolution and control-plane routes are not included.

## 1. Data model

### `runner_pools`

A named execution-agent pool with `ACTIVE` or `DISABLED` state. Pool keys are stable lowercase slugs. Disabling a pool is a fast server-side kill switch: future authentication resolution must require both an ACTIVE runner identity and an ACTIVE pool.

### `runner_identities`

One registered machine identity binding:

| Field | Purpose |
| --- | --- |
| `runner_id` | Stable Sky High runner identifier passed to fenced dispatch/receipt repositories |
| `pool_id` | Server-assigned pool; never supplied by the agent |
| `identity_issuer` + `identity_subject` | Provider-neutral exact identity key from a verified credential |
| `status` | ACTIVE, SUSPENDED or terminal REVOKED |
| `scopes` | Allowlisted dispatch operations only |
| `revoked_at` | Database-generated revocation timestamp |

The issuer/subject pair is unique. The runner ID is unique. The identity binding (runner ID, pool, issuer and subject) cannot be edited after registration. To change the identity provider subject or move a runner to another pool, revoke the old identity and register a new binding. Revocation is terminal; the row is retained rather than deleted.

The database stores no bearer token, Access client secret, private key, certificate private material or credential hash. A future adapter must validate the credential first, then resolve its trusted issuer/subject pair to this registry. It must never use an unverified token payload as the registry lookup result.

### `runner_identity_events`

Database triggers append registration, status-change and scope-change events. Event rows reject UPDATE and DELETE. Events deliberately do not claim an operator identity: there is no trusted administration API or operator attribution contract yet. Before production use, database grants must prevent the application role from directly inserting lifecycle events, and an authenticated administrative workflow must supply auditable actor attribution.

## 2. Invariants enforced by migration

- Unique runner ID and unique exact issuer/subject pair.
- Pool references cannot be orphaned; pool and identity records cannot be hard-deleted.
- Only `dispatch:claim`, `dispatch:receipt` and `dispatch:retry` are valid scopes.
- Identity bindings are immutable after registration.
- Identity state is ACTIVE, SUSPENDED or REVOKED; revoked identities cannot be reactivated.
- The database generates the revocation timestamp.
- Registration, status and scope changes append lifecycle events.
- Lifecycle event rows cannot be updated or deleted.
- Migration is idempotent and registered in `schema_migrations`.

## 3. Required resolver behavior (not implemented here)

A future authenticator adapter must:

1. Verify the selected provider credential (signature or introspection, issuer, audience, time claims, credential type and revocation behavior).
2. Resolve the verified exact issuer/subject pair to one `runner_id`, `pool_id`, status and scopes.
3. Accept only when identity status is ACTIVE and the linked pool status is ACTIVE.
4. Derive runner ID, pool and scopes exclusively from this trusted database result.
5. Require the route's exact scope before calling a dispatch repository.
6. Fail closed on missing, duplicate, disabled, revoked or unverifiable mappings and on database/provider outage.

No generic JWT claim names or Cloudflare Access subject fields are assumed by the schema. The adapter-specific mapping must be defined only after the provider proof and ADR.

## 4. Operational and security gaps still open

- No registration, suspension, revocation or pool-management API exists.
- No trusted operator attribution exists for lifecycle changes.
- Database role grants have not yet been split between control-plane runtime, migration owner and read-only audit access.
- `PostgresRunnerIdentityRepository` resolves an already-verified issuer/subject pair to an active runner principal, but it does not validate credentials and no configured `RunnerAuthenticator` uses it yet.
- No credential rotation/revocation integration exists.
- No route derives `runnerId` from the registry; no dispatch claim/receipt endpoint is exposed.
- No queue consumer, artifact retrieval or execution is enabled.
- gVisor M0 isolation evidence and the normative execution lifecycle remain separate gates.

This migration is a schema prototype in CI only. It has not been applied to any production database. The current default authenticator remains fail-closed.
