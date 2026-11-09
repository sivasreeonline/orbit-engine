# Transactional Execution Intake Prototype

- Status: Draft implementation; not wired to an HTTP route or queue publisher.
- Depends on the proposed migration in PR #28.
- This code is not a normative API contract and must not be deployed independently of the schema proposal.

## Transaction behavior

The repository prototype uses one PostgreSQL transaction for:
1. Acquiring a transaction-scoped advisory lock for the tenant/actor/action/idempotency-key tuple.
2. Looking up an existing idempotency reservation and comparing the deterministic request hash.
3. Resolving a published problem version within the authenticated tenant boundary.
4. Persisting the immutable source snapshot and execution attempt.
5. Creating the queued execution job.
6. Creating a metadata-only outbox event.
7. Creating the idempotency reservation and committing.

A matching replay returns the original attempt and execution identifiers. Reusing the same scoped key with a different request hash returns an explicit conflict. A transaction-scoped advisory lock serializes same-key requests; hash collisions can only serialize unrelated requests, not cross their data.

## Trust and safety boundary

- The principal is an input to this internal repository and must come from the configured authenticator and trusted membership layer. No HTTP handler currently calls it.
- Runtime version must be selected by trusted server policy.
- The outbox contains only execution/attempt identifiers and protocol version; source and hidden tests are not included.
- The code does not publish to a queue, execute user source, or expose a POST endpoint.
- The database source storage path is used in this prototype. Source-size thresholds, R2 selection, encryption, retention and deletion remain unapproved.

## Provisional decisions requiring review

- The request hash uses SHA-256 over a fixed-order JSON array of action, problem slug, language, server-selected runtime version and exact source text. This is a testable prototype canonicalization, not an approved public contract.
- The advisory-lock scope encoding and PostgreSQL function require review against the target Postgres deployment.
- Error mapping, replay response semantics and the eventual result DTO must align with the approved API contract before route integration.
- No claim is made about concurrent behavior until the acceptance tests run against PostgreSQL.
