# FENCE-001 external witness provider adapter conformance contract

**Status:** Provider-neutral adapter contract and executable test harness. No provider is selected or qualified by this document.  
**Harness:** `scripts/validate_m0_witness_provider_adapter_conformance.py`  
**CI interpretation:** The checked-in in-memory reference adapter validates the harness itself. Only a separately pinned real adapter, run against its actual provider and independently collected evidence, can enter provider qualification.

## Required adapter surface

An implementation under evaluation must provide three operations:

- `append_if_current(checkpoint, expected_generation, expected_digest, idempotency_key)`
- `read_latest(scope)`
- `read_by_operation(scope, operation_id)`

The API shape is intentionally small. It does not dictate HTTP, SQL, KV, object storage or a specific vendor SDK.

### Atomic append

The provider must atomically compare the exact current high-water generation and digest with the caller's expected predecessor and append exactly one immutable successor. The append must reject:
- stale or forked predecessor digest;
- generation gaps or non-monotonic generation;
- operation-ID reuse for different checkpoint content;
- scope changes within a witness history;
- idempotency-key reuse with different canonical checkpoint bytes.

A successful append returns a receipt bound to the exact scope, generation, operation ID, checkpoint digest and predecessor digest. The consistency token is provider-defined and opaque here. A non-empty token is only a structural minimum, not proof of consistency.

### Idempotency and ambiguous outcomes

A timeout can occur after the provider committed but before the caller received the receipt. The caller must retry the *identical checkpoint bytes with the identical idempotency key*. The provider must return the original receipt without creating a second generation. Reusing the key for different bytes must fail permanently.

The caller must not respond to an ambiguous outcome by inventing a new operation ID, new idempotency key or a new generation. It must reconcile using the same idempotency key and exact operation lookup.

### Read semantics

`read_latest` must be strongly consistent with successful writes: after append returns success—or an exact idempotent retry recovers the receipt—a subsequent latest read must return that commit or a later valid successor. It must never return a stale replica value as current.

`read_by_operation` must return the exact immutable record for that operation, including after later successors. A missing operation lookup after a successful append is a provider conformance failure. If the provider offers only eventual consistency, it does not satisfy this contract without a separately qualified consistency mechanism.

### Concurrency and linearization

Two writers presenting the same expected predecessor cannot both succeed. The provider must serialize compare-and-append at one linearization point: exactly one successor wins; every conflicting writer receives a conflict and must reconcile. A client-side mutex is not sufficient evidence of provider atomicity.

## Executable test suite

The harness checks 12 contract cases:
1. atomic genesis append and immediate latest readback;
2. exact idempotent retry;
3. lost acknowledgement and retry recovery;
4. idempotency key cannot be rebound to different content;
5. operation-ID uniqueness across phases;
6. stale predecessor and fork rejection;
7. generation-gap rejection;
8. immutable operation lookup;
9. latest-read successor visibility;
10. concurrent compare-and-append with exactly one winner;
11. receipt-to-checkpoint field binding and non-empty consistency token.

The suite uses an in-memory reference adapter by default to validate its own test logic and CI wiring. A provider implementation can expose a zero-argument factory returning an object that satisfies `WitnessAdapter`, then run the exact same suite by setting:

```sh
FENCE_WITNESS_ADAPTER_FACTORY=package.module:create_adapter python scripts/validate_m0_witness_provider_adapter_conformance.py
```

The configured factory is imported by the harness; provider SDK dependencies and credentials must be installed/provided by the external qualification environment, never committed to this repository. The harness wraps the supplied adapter to inject a lost acknowledgement after a successful append call, then retries the exact same bytes and idempotency key. This exercises provider idempotency through the same adapter surface.

The fixture is not durable, is not distributed, does not prove network partitions, and cannot demonstrate independent failure-domain separation. CI runs only the in-memory fixture unless a separately governed qualification job explicitly supplies a real adapter factory and evidence collector.

## Evidence required for real provider qualification

A candidate adapter qualification run must pin all of:
- provider, service, account/project, region and exact deployment configuration;
- adapter source repository, immutable commit, dependency lock and build artifact digest;
- witness identity and trust-domain identity;
- test runner identity and independent evidence collector/verifier identities;
- timestamped raw request/response evidence, provider request IDs, exact operation IDs and immutable evidence object versions;
- provider documentation and contractual guarantees for conditional writes, idempotency, read consistency, durability, retention, restore and failure-domain behavior.

The evidence package must include:
- lost-ack injection after provider commit and exact-key retry;
- concurrent append race from independent clients, not a shared process mutex;
- read-after-write and operation lookup through separately established sessions/endpoints;
- stale replica/cache attempts and partition/recovery behavior;
- provider outage during append, readback and retry;
- process termination between provider commit and local acknowledgement persistence;
- restore/failover with provider high-water ahead of local PostgreSQL;
- proof that monitor identities, operators, accounts, credentials, control planes and failure domains are independent from the authority and from one another.

Each result must retain raw signed receipts and provider evidence, hash every artifact, and be independently re-verifiable. A synthetic test, local mock, provider marketing statement or self-authored assertion cannot be marked as external evidence.

## Fail-closed qualification gates

The provider adapter is not qualified unless all required tests pass against the real provider, every evidence artifact is immutable and independently verified, and provider semantics match the contract. Any ambiguous or unavailable consistency guarantee blocks qualification. An eventual-consistency read is not silently promoted to strongly consistent. A successful cryptographic receipt verification does not override an append/read consistency failure.

This harness does not alter production admission or execution authorization. Production approval remains false until the full FENCE-001 qualification record is independently reviewed and every mandatory trust boundary is satisfied.


## AWS DynamoDB adapter implementation

The first concrete provider adapter is `scripts/aws_dynamodb_witness_adapter.py`. It implements the existing `WitnessAdapter` interface and writes four distinct records in one DynamoDB transaction: the new immutable generation, the operation-ID lookup, the durable idempotency-key binding and the current high-water record. The head item uses conditional writes to make the predecessor compare-and-append decision atomic.

Authoritative reads use strongly consistent base-table `GetItem` calls. The adapter intentionally avoids GSI/stream reads for the witness high-water. It checks the durable idempotency item before a retry and deliberately omits the optional 10-minute native transaction-token cache. Long-lived retry safety comes from the idempotency record, operation record and conditional high-water update committed atomically.

The local test path uses AWS-published DynamoDB Local. It can validate SDK wiring and the contract against the local API implementation. It is not evidence that the managed AWS service, IAM policies, failure domains, durability or production controls are qualified. Only the separately approved live account run and independently verified evidence can satisfy external FENCE-001 qualification.
