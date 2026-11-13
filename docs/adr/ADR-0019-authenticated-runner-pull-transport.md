# ADR-0019: Authenticated runner pull transport

- **Status:** Proposed — design review required before implementation or provisioning
- **Date:** 2026-11-13
- **Scope:** Control-plane to isolated Go runner transport

## Context

The current execution path now has:
1. Authenticated API intake that transactionally persists the immutable source snapshot, attempt, queued job, intake outbox and idempotency reservation.
2. An at-least-once intake outbox publisher.
3. A Cloudflare Queue consumer that validates metadata-only messages and persists a durable runner-dispatch outbox intent.
4. Fair per-student dispatch leases with fencing tokens.
5. A Go runner contract skeleton that exposes health/readiness only and always fails execution closed.

The Go runner is intentionally not an execution service yet. It has no execution endpoint, no authenticated machine transport, no source/test artifact reader and no configured sandbox executor. The current queue consumer does not claim dispatch leases or execute code.

## Decision drivers

- No student source code or hidden tests in Cloudflare Queue messages.
- No execution of untrusted code inside Workers, Durable Objects, the API process or the browser.
- No publicly reachable unauthenticated runner endpoint.
- Avoid inbound firewall openings on runner hosts where possible.
- Authenticate each runner independently and support key rotation/revocation.
- Make delivery idempotent and reject stale leases/receipts.
- Preserve the existing fair per-student scheduler and append-only evidence model.
- Support local-first protocol tests without pretending a fake runner proves sandbox isolation.
- Do not provision paid resources without explicit approval.

## Options considered

### A. Control-plane pushes jobs to runner

The Worker calls a runner-host HTTP endpoint.

**Advantages:** simple control-plane scheduling and immediate dispatch.

**Disadvantages:** runner host needs reachable ingress or a tunnel; larger inbound attack surface; Worker-to-host network topology and firewall operations become deployment dependencies.

### B. Runner pulls jobs from the control plane

A runner agent initiates outbound HTTPS requests to claim work, acknowledge durable acceptance, retrieve assigned artifacts and submit lifecycle/results.

**Advantages:** no public runner ingress required; runner can stop polling when local capacity is full; the API remains authoritative for fair scheduling and lease fencing; works with isolated private Linux hosts.

**Disadvantages:** requires runner machine identity, signed request replay protection, polling/backoff and lease recovery semantics.

**Recommendation:** Option B, runner-initiated pull.

## Proposed machine identity

Each runner receives a unique machine identity and a key pair. The control plane stores only the public key and key metadata; the private key remains on the runner host.

A signed request should bind:
- HTTP method and canonical path;
- request timestamp;
- cryptographically random nonce;
- SHA-256 digest of the exact request body;
- runner key identifier.

The control plane must reject invalid signatures, expired timestamps, revoked keys and reused nonces. Nonce consumption and the protected operation must be coordinated so replay cannot claim a second job. Key rotation should allow a short overlap window with explicit revocation.

**Algorithm compatibility gate:** evaluate Ed25519 support in the Cloudflare Workers Web Crypto runtime and Go standard library together before locking the wire format. Do not substitute a shared global secret or invent an algorithm fallback if compatibility is incomplete. P-256 is the fallback candidate only after a tested cross-runtime signing/verification spike.

No runner identity table, keys, certificates, secrets or accounts are created by this ADR.

## Proposed protocol lifecycle

1. **Claim:** runner sends a signed request for one available slot (or a bounded number of slots no greater than its measured free capacity). API authenticates the runner, then uses `claimFairBatch` to lease eligible work. Runner identity and lease owner come from the verified machine identity, never from an unsigned body field.
2. **Dispatch envelope:** API returns the dispatch ID, execution/attempt IDs, protocol version, lease token/expiry, and a server-assembled execution request. It resolves problem version, action, language, pinned runtime, source artifact ID/hash, hidden test-bundle ID and server-controlled resource limits from authoritative records. Queue message fields are not authoritative for these values.
3. **Durable acceptance:** runner validates the envelope and durably records acceptance in its own idempotency store before returning a signed receipt. The receipt binds runner ID, dispatch ID, execution ID, attempt ID, request digest and lease identity.
4. **Accept receipt:** API verifies signature, runner identity, active unexpired lease and request digest. In one database transaction it fences the lease, records the acceptance receipt, advances the execution lifecycle to the appropriate claimed state and appends the corresponding lifecycle event. A stale or duplicate receipt cannot advance state twice.
5. **Start and result:** runner reports started and terminal result events through separately authenticated, idempotent endpoints. Result persistence remains append-only and is the authoritative source for the student-facing verdict.
6. **Artifact access:** runner retrieves source and hidden test artifacts only through a private machine-authenticated artifact interface scoped to the assigned dispatch. It receives no broad R2 credentials. Source bytes and hidden tests are never returned to student-facing APIs.

## Lease and recovery semantics

- A claim creates a time-bounded lease with a unique fencing token.
- Only the current runner identity and unexpired token may accept or progress that dispatch.
- A runner crash before acceptance allows lease expiry and a later fair claim.
- A crash after durable acceptance must be resolved by runner idempotency and the control-plane receipt; it must not create a second execution attempt.
- A stale worker/runner cannot mark a newer lease delivered.
- Retry policy, lease duration and polling intervals must be measured; no arbitrary ETA or concurrency promise is introduced here.

## Required implementation slices

1. Cross-runtime signing compatibility spike (Go runner ↔ Cloudflare Worker).
2. Runner identity/key registry, revocation and nonce replay protection.
3. Authenticated claim endpoint using the existing fair scheduler.
4. Authenticated acceptance receipt and atomic lifecycle transition.
5. Private artifact reader for source snapshots and hidden test bundles.
6. Runner start/cancel/result endpoints with idempotent append-only persistence.
7. Local integration tests with a fake transport and PostgreSQL; then Linux/gVisor adversarial acceptance tests on an approved host.

## Acceptance criteria before enabling student execution

- Unauthenticated, revoked, replayed, expired and wrong-runner requests are rejected.
- No cross-tenant or unassigned artifact retrieval is possible.
- Queue redelivery and duplicate runner receipts are idempotent.
- Expired lease tokens cannot accept or mutate work.
- Source/test bytes are absent from queue messages and ordinary logs.
- Runner acceptance and lifecycle events are durable and auditable.
- Cancellation, timeout, OOM, PID/output limits and cleanup are tested in gVisor.
- Java 25 and Python 3.14 runtime images are pinned by patch version and digest.
- Hidden tests and expected outputs never reach the browser or untrusted API response.

## Consequences and non-goals

This is a proposed transport architecture, not an approved deployment. It does not implement machine identity, create runner infrastructure, open network ingress, connect R2, or enable code execution. The AWS M0 host evaluation remains a separate proposal requiring explicit approval. The 500-online-student target remains a load-test acceptance target; it is not a claim of 500 concurrent executions.
