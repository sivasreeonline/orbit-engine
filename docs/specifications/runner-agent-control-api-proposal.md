# Runner Agent Control API — Proposal

- Status: non-normative interface proposal; not approved for implementation.
- Scope: define the smallest control-plane API needed for an authenticated Linux runner agent to claim and durably accept dispatch work.
- Depends on: runner transport evaluation, runner-dispatch lease prototype, normative runner request/result contract, identity-provider decision and execution job state-machine decision.

## 1. Current implementation boundary

The repository currently has PostgreSQL repositories for dispatch-intent creation and fenced dispatch leases. It does not have:
- A machine-to-machine authenticator or registered runner identities.
- HTTP routes for claiming, renewing or acknowledging runner dispatch leases.
- A durable runner-side acceptance journal or receipt contract.
- An artifact manifest/retrieval endpoint.
- A normative execution request/result DTO or terminal job state machine.
- A configured executor; `UnconfiguredExecutor` remains fail-closed.

The existing end-user `UnconfiguredAuthenticator` must not be repurposed for runner service identities. User authentication and runner workload authentication are separate trust domains.

## 2. Proposed API surface

All routes are internal service operations under `/internal/v1/runner`. They are not public student APIs and must not be enabled until machine authentication and authorization are configured.

### 2.1 Claim dispatch work

`POST /internal/v1/runner/dispatch-claims`

Request:

```json
{
  "maxItems": 2
}
```

Rules:
- The authenticated service principal, not the request body, determines `runnerId`, runner pool and allowed capabilities.
- `maxItems` is a hint bounded by server policy; initial prototype cap should be small (for example, 1–5) and never exceed the repository's hard maximum.
- The API calls the PostgreSQL fenced claim operation with a server-derived worker identity.
- The API never accepts tenant ID, user ID, role, worker ID, runtime image, resource limits or test-bundle policy from the agent.
- Empty claims return HTTP 200 with an empty array; no long-running request is required.

Proposed response:

```json
{
  "claims": [
    {
      "dispatchId": "uuid",
      "executionId": "uuid",
      "attemptId": "uuid",
      "protocolVersion": "v1",
      "correlationId": "opaque-correlation-id",
      "leaseToken": "opaque-fencing-token",
      "leaseExpiresAt": "2026-11-09T12:00:00Z"
    }
  ]
}
```

The response contains opaque identifiers and the dispatch lease only. It does not contain student source, hidden tests, expected output, artifact URLs, credentials or database connection details. The lease token is a secret: return it only over authenticated TLS and never log it.

### 2.2 Confirm durable runner acceptance

`POST /internal/v1/runner/dispatch-claims/{dispatchId}/receipt`

Request:

```json
{
  "executionId": "uuid",
  "attemptId": "uuid",
  "protocolVersion": "v1",
  "leaseToken": "opaque-fencing-token",
  "receiptId": "runner-generated-opaque-id",
  "acceptedAt": "2026-11-09T12:00:00Z"
}
```

Rules:
- The API derives runner identity from the authenticated service principal.
- The API verifies dispatch ID, execution ID, attempt ID, protocol, runner identity, lease token and unexpired lease against PostgreSQL.
- A successful receipt means the runner has durably recorded responsibility for the execution and can recover it after process restart. It does **not** mean compilation started, execution completed or the student received an accepted verdict.
- Only after the receipt is durably persisted may the dispatch outbox transition to `DELIVERED`.
- Repeating the same receipt must be idempotent. A conflicting receipt for the same dispatch must be rejected and audited.
- A stale or expired lease must not be accepted merely because the runner still possesses its token.

**Schema gap:** the current `runner_dispatch_outbox` prototype stores delivery state and fencing fields but does not persist a receipt ID or receipt digest. A separate receipt record or reviewed columns with a unique dispatch constraint are needed before an idempotent receipt endpoint can be implemented. Do not pretend the current `markDelivered()` boolean alone proves replay identity.

### 2.3 Release a dispatch lease for retry

`POST /internal/v1/runner/dispatch-claims/{dispatchId}/retry`

This route is optional for the first API slice. If provided:
- It must be fenced by authenticated runner identity, dispatch ID and lease token.
- The runner may report a bounded retryable failure code, but it must not choose an arbitrary retry timestamp or dead-letter threshold.
- The server owns retry classification, backoff, maximum attempts and dead-letter policy.
- Permanent failures and malformed dispatch records require operator-visible quarantine; never silently discard them.

If the agent cannot determine whether the receipt transaction committed, it must not assume success. It should retry the same receipt with the same receipt ID; the API must return the existing durable outcome or a safe conflict.

### 2.4 Execution manifest and artifacts

No manifest or artifact route is specified as implementable yet. The future design must:
- Require an active dispatch lease or a durable accepted receipt, according to the chosen execution lifecycle.
- Derive all problem, tenant, language, runtime, immutable image digest, comparison policy and resource limits from trusted database/policy state.
- Return only an immutable manifest pinned to the execution attempt and source digest.
- Authorize each artifact retrieval against the exact execution, attempt, runner identity and lease/state.
- Verify source SHA-256 and byte length before staging.
- Keep hidden test material away from the browser, Queue messages, API logs and student process. The trusted test harness may receive only the test material required to evaluate the submission.
- Never expose database URLs, storage credentials or long-lived storage secrets. Use a narrowly scoped, short-lived retrieval capability or an authenticated artifact broker after a separate threat-model review.

## 3. Machine identity and authorization

No provider or credential mechanism is selected by this proposal.

Required properties:
- Distinct runner service identity; never reuse student, trainer, TPO or human bearer tokens.
- Authenticated TLS for every request.
- Short-lived, rotatable credentials or workload identity with revocation.
- Server-side mapping from verified identity to a stable runner ID and allowed runner pool.
- Least-privilege scopes: claim only from an assigned pool; receipt/release only claims owned by that runner identity.
- Rate limits and bounded request bodies.
- Replay resistance through short credential lifetime, request binding and the PostgreSQL lease fence.
- Credential material must not enter student sandbox environment, mounts, process arguments, logs or crash dumps.
- Fail closed when identity validation, key rotation metadata, clock validation or authorization is unavailable.

Candidate mechanisms to evaluate separately:
1. Mutual TLS with per-runner certificates and server-side certificate-to-runner mapping.
2. Cloudflare Access service tokens or another workload-identity gateway in front of the Worker, if the exact Worker routing and identity propagation model is validated.
3. Short-lived signed service assertions with issuer/audience/key-rotation validation, if an approved identity provider supports machine clients.

Do not select a mechanism based only on ease of setup. Compare revocation, rotation, workload binding, Worker compatibility, observability, local development and compromise blast radius. A shared static API key is not an acceptable production identity design.

## 4. Lease and execution lifecycle separation

The dispatch lease is a **handoff lease**, not the execution-duration lease.

- A dispatch lease protects the short claim-to-durable-receipt operation.
- The runner must durably journal an accepted execution before returning its receipt.
- The control plane marks the dispatch intent delivered only after the authenticated, idempotent receipt is committed.
- The execution job lifecycle then needs its own explicit claim/running/heartbeat/cancel/terminal transitions. Do not hold a short dispatch lease for a multi-minute compilation or test run.
- The existing execution-job repository does not reclaim expired RUNNING work. Runner crash recovery and cancellation semantics remain unresolved and must be designed before enabling student execution.
- A runner must deduplicate by execution ID across restart. A repeated dispatch for the same execution returns the existing receipt/state and must not start a second logical execution.
- If durable runner-side journaling is not available, do not acknowledge dispatch as durably accepted. Keep the control-plane dispatch recoverable instead.

## 5. Error semantics (proposal)

| Condition | Proposed behavior |
|---|---|
| Missing/invalid machine identity | 401, generic response |
| Authenticated runner lacks pool permission | 403, generic response |
| Invalid JSON, unknown fields, oversized body | 400 or 413; no claim mutation |
| No pending dispatch | 200 with empty claims |
| Lease conflict/stale token | 409 or a non-disclosing stale-lease outcome |
| Unknown dispatch identifier | 404 without cross-tenant or cross-pool disclosure |
| Database unavailable | 503 with retryable stable error code |
| Same receipt replay | 200 with the original accepted outcome |
| Conflicting receipt for dispatch | 409 and security audit event |

Do not return SQL errors, token details, hidden-test data or cross-tenant existence information.

## 6. Required tests before route implementation

- Unauthenticated and invalidly authenticated requests cannot claim or acknowledge dispatches.
- A valid runner identity can claim only its authorized pool.
- Client-supplied runner ID, tenant ID, user ID, role, runtime, resource policy or image digest is ignored or rejected.
- Two runners cannot claim the same active dispatch lease.
- Expired lease is reclaimed with a new token; stale runner cannot receipt, retry or dead-letter.
- Receipt identity and dispatch/execution/attempt/protocol binding are validated.
- Same receipt replay is idempotent; conflicting receipt is rejected.
- Crash after durable runner journal commit but before HTTP response is recovered by replaying the same receipt.
- Crash before durable runner journal commit does not result in a successful receipt.
- Runner restart recovers accepted but unfinished work without duplicate execution.
- Artifact access is denied without the exact authorized claim/receipt context.
- No service credential or hidden test material enters student sandbox environment, logs or process arguments.
- API response sizes, batch sizes, timeouts and concurrency are bounded.
- Database outages and unknown commit outcomes fail closed and preserve retryability.

## 7. Decisions required before implementation

1. Select machine identity and authorization provider/mechanism.
2. Approve normative request/result DTOs and protocol versioning.
3. Approve the execution job state machine, including RUNNING lease renewal, cancellation and terminal recovery.
4. Define durable runner journal technology, retention and crash recovery.
5. Add a durable, idempotent runner receipt schema and migration.
6. Define runner-pool registration, capability policy and credential rotation/revocation operations.
7. Approve artifact broker and source/hidden-test delivery threat model.
8. Define retry/backoff/dead-letter/operator replay policy.
9. Complete gVisor M0 isolation evidence before enabling student-code execution.

## Explicit non-goals

- This proposal does not add HTTP routes, middleware, credentials, migrations or runner code.
- It does not select an identity provider or machine-authentication mechanism.
- It does not define the normative execution result contract.
- It does not enable artifact retrieval, queue consumption or execution.
- It does not change `UnconfiguredAuthenticator` or `UnconfiguredExecutor`.
- It does not authorize deployment or production database access from the runner.
