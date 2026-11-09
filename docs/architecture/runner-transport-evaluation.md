# Runner Transport Evaluation — Outbound Pull vs Private Dispatch

- Status: evidence-backed architecture evaluation; proposed direction only, not an approved ADR.
- Scope: choose how the Linux Go runner receives work from the Cloudflare/PostgreSQL control plane.
- Current implementation: the API-to-Cloudflare Queue publisher exists as a prototype; PostgreSQL runner-dispatch handoff and fenced leases exist as prototypes. No queue consumer, runner transport, artifact retrieval or execution endpoint is enabled.
- Depends on: ADR-0006 (Cloudflare Queues), PR #35 durable handoff design, PR #36 dispatch-intent and lease foundation.

## Executive recommendation

**Prefer an outbound-pull Linux runner agent for the first integration prototype.** Evaluate Cloudflare Queues' native HTTP pull consumer first because Cloudflare explicitly supports HTTP pull from infrastructure outside Workers. Keep the runner host free of inbound public ports. The agent should acknowledge a queue message only after the control plane confirms that the authoritative PostgreSQL handoff transaction has committed.

This is a preferred prototype direction, not approval to implement or deploy. The native pull option has a material credential-scope concern: Cloudflare documents a bearer API token requiring both account Queues read and write permissions. The write permission is needed to acknowledge messages. Before selecting it, verify whether the intended account/token can be restricted sufficiently; if not, isolate the queue in a dedicated Cloudflare account or prefer the authenticated control-plane pull API described below.

Do not put the Cloudflare token, control-plane credentials, artifact credentials or database credentials in the student-code sandbox or its environment.

## Current trust and delivery boundaries

1. The API transaction persists an immutable attempt, execution job and metadata-only intake outbox event.
2. The scheduled Worker publishes an `EXECUTION_REQUESTED` message to Cloudflare Queues.
3. The consumer treats the message as an untrusted wake-up/routing hint. It validates the envelope and asks the control plane to verify authoritative job and attempt identity.
4. The control plane commits one `runner_dispatch_outbox` intent transactionally and returns an idempotent handoff result.
5. Only after that commit does the consumer acknowledge the Queue message.
6. A runner agent obtains a fenced dispatch lease from the control plane, fetches only the authorized source artifact and policy-selected test bundle, and invokes the executor.
7. Result submission remains blocked until the normative result contract, state machine, authentication and M0 sandbox evidence are approved.

The Queue message and dispatch intent contain opaque identifiers and protocol/correlation metadata only. They must never contain source bytes, hidden test inputs, expected output, credentials, database URLs or signed artifact URLs.

## Candidate A — Cloudflare Queues native HTTP pull consumer on the Linux host

Cloudflare documents HTTP pull consumers for external infrastructure and programming languages. The client uses the Cloudflare Queues REST API to pull bounded batches and acknowledge or retry individual messages.

### Advantages

- Native, documented Cloudflare-to-external-infrastructure delivery; no custom public runner callback is required.
- The Linux host initiates outbound HTTPS requests. No inbound firewall rule or public runner listener is needed.
- The runner can pull only when it has available capacity, matching long-running execution workloads.
- Queue visibility leases and explicit acknowledgements support crash recovery and competing consumers.
- Existing Cloudflare Queue producer and metadata-only envelope can be retained.
- The same Go agent can run the pull loop, handoff client and separately isolated executor supervisor.

### Constraints and risks

- Cloudflare requires an API bearer token with both Queues read and write permissions; write is needed for acknowledgements. The documentation describes optional account scoping, not a queue-specific scope. Treat the credential as potentially able to affect other queues in that account until a real token policy is verified.
- The pull API uses short polling, not long polling. An empty pull returns immediately; the agent needs bounded polling backoff with jitter and must not spin.
- The documented default visibility timeout is 30 seconds and maximum is 12 hours; batch size defaults to 5 and maxes at 100. Select a visibility timeout for the handoff transaction, not for the entire student execution.
- **Late acknowledgements are permissive:** Cloudflare documents that an acknowledgement using a lease ID may still be accepted after visibility timeout expiry, even if the message was delivered to another consumer in the meantime. Therefore a Queue lease is not an exclusive fencing token and cannot establish which consumer owns the logical work. A stale consumer may acknowledge after redelivery; PostgreSQL unique handoff identity and worker/token/expiry fencing must remain authoritative.
- The pull-consumer guide says to create a token with both account Queues read and write permissions and describes optional account scoping. The current Pull Queue Messages API reference lists accepted permissions as Queues Write or Workers Scripts Write. This documentation difference must be resolved against the actual account token configuration and tested before choosing the native pull option; do not assume queue-specific token scoping or rely on the narrower API reference wording without validation.
- The Queue API does not provide a durable execution state machine. PostgreSQL remains authoritative.
- A pull consumer must decode the Queue content type correctly. External consumers cannot decode the Workers-specific `v8` content type; publish a supported `json`, `text` or `bytes` format and test its encoding.
- Queue retry exhaustion can delete a message if no dead-letter queue is configured. Configure and test a DLQ, and keep the database handoff idempotent.

### Required safe sequence

1. Pull only a small batch bounded by available handoff capacity.
2. Strictly decode a bounded message; reject malformed, unknown-version and unknown-field envelopes.
3. Call an authenticated control-plane handoff operation. The API must verify the execution, attempt, protocol and allowed job state against PostgreSQL and insert the unique dispatch intent transactionally.
4. If the control plane confirms a new or exact duplicate committed intent, acknowledge the Queue message.
5. If the control plane is unavailable or the transaction outcome is unknown, do not acknowledge; allow visibility expiry or explicitly retry with bounded delay.
6. After acknowledgement, claim work through the control plane's fenced PostgreSQL dispatch lease API. Never treat a Queue lease as permission to execute.
7. Fetch source and test artifacts through a separately authenticated, narrowly scoped artifact path. Verify digest and size before use.
8. Run student code only inside the approved isolated executor. The queue-pull agent and its credentials remain outside the sandbox.

### Credential containment

- Use a dedicated Cloudflare API token for the runner agent and rotate it.
- Verify the token's actual resource scope before production. If it cannot be constrained to the intended queue/account, isolate the queue in a dedicated Cloudflare account or do not use this option.
- Store the token in the host's secret manager or root-readable secret file; never in source control, image layers, command-line arguments or logs.
- Do not pass it as an environment variable to student processes. Do not mount host secret paths into the sandbox.
- Separate the privileged agent/supervisor process from the untrusted executor child. The child receives only the minimum execution-specific files and resource limits.

## Candidate B — Linux agent pulls fenced dispatch leases from a control-plane HTTPS API

The Linux agent initiates outbound HTTPS requests to an authenticated Worker/API endpoint. The API owns PostgreSQL access and returns bounded dispatch leases using the existing `runner_dispatch_outbox` fencing model.

### Advantages

- No Cloudflare Queue API token is stored on the runner host.
- Database access remains exclusively inside the API/control plane.
- The API can issue a dedicated runner identity, scope it to a runner pool and enforce lease/concurrency policy centrally.
- The existing PostgreSQL lease owner/token/expiry model maps naturally to the agent's pull cycle.
- No inbound listener is required on the Linux host.

### Constraints and risks

- Requires a new authenticated machine-to-machine identity and API contract; the current `UnconfiguredAuthenticator` is fail-closed and is not that identity system.
- Requires lease-claim, heartbeat/renewal, receipt and result endpoints plus bounded polling/backoff.
- A public HTTPS Worker endpoint is not a private network merely because the runner calls it outbound. Authenticate every request, rate-limit it and bind each credential to a runner identity/pool.
- The API must never return source or hidden-test data to a caller that has not successfully claimed the exact dispatch lease.
- The endpoint must preserve fencing semantics across lease expiry, retries and stale agents.

### Required safe sequence

1. Agent authenticates with a dedicated machine identity using a reviewed credential mechanism.
2. API claims a bounded dispatch batch in PostgreSQL and returns lease tokens with expiry.
3. Agent fetches the exact execution envelope and authorized artifacts only after the lease is granted.
4. Agent reports a receipt using the same lease fence.
5. API rejects stale, expired or mismatched worker/token pairs.
6. Result persistence follows the separately approved result contract and state machine.

## Candidate C — Cloudflare Worker dispatches to a private Linux endpoint through Workers VPC and Cloudflare Tunnel

Cloudflare documents Workers VPC routing from a Worker to private services through Cloudflare Tunnel. The tunnel daemon establishes outbound connections from the Linux network, so the runner does not need a public IP or inbound firewall rule.

### Advantages

- The control plane initiates dispatch while the Linux service remains on a private network.
- Tunnel connectivity avoids a directly exposed public runner endpoint.
- Can support a request/response transport if a push model is operationally preferable.

### Constraints and risks

- Workers VPC is documented as Beta in the current navigation and introduces additional platform configuration, permissions and operational dependencies.
- The tunnel requires a running `cloudflared` daemon; the Workers VPC documentation specifies QUIC and outbound UDP port 7844.
- A tunnel provides connectivity, not application authorization. The runner endpoint still needs strong service authentication, replay protection, request bounds and idempotency.
- Tunnel/VPC health becomes part of dispatch availability and incident response.
- Do not assume Worker mTLS bindings work unchanged through a proxied Cloudflare hostname; Cloudflare documents a limitation for mTLS requests to proxied zones. Select and test the exact authentication path.

## Comparison

| Criterion | A: Queue HTTP pull | B: Control-plane API pull | C: Workers VPC push |
|---|---|---|---|
| Runner inbound public port | Not required | Not required | Not required |
| Runner initiates connection | Yes | Yes | No; tunnel daemon initiates tunnel, Worker sends request |
| Native Cloudflare feature | Yes, Queues pull consumer | Uses Worker/API plus custom agent protocol | Workers VPC + Tunnel |
| Runner needs Cloudflare Queue token | Yes | No | No |
| Runner needs machine identity to API | Yes, for handoff/artifact/lease APIs | Yes | Runner endpoint identity required |
| Database access on runner | No | No | No |
| Queue lease and PostgreSQL lease both needed | Yes, separate purposes | No Queue pull lease in runner; PostgreSQL lease is primary | Queue push ack + PostgreSQL dispatch lease |
| Operational complexity | Medium | Medium-high | High |
| Main risk | Queue token scope and duplicate delivery | New machine-auth and lease API | Beta/private-network dependency and endpoint hardening |

## Proposed direction and decision gates

1. Prototype Candidate A only after confirming token scope and creating an isolated non-production queue/account. If the token scope is too broad, stop and use Candidate B.
2. Keep PostgreSQL as the source of truth. Queue delivery is at-least-once wake-up; unique handoff records and fenced DB leases govern logical execution.
3. Do not let the Linux agent connect directly to Neon/PostgreSQL. All state transitions go through authenticated control-plane operations.
4. Keep the pull agent, artifact broker and sandbox executor as separate trust roles/process boundaries. The sandbox receives no queue, API, database, Cloudflare or artifact credentials.
5. Do not implement the consumer until the request/result contract and state machine are approved. In particular, stale RUNNING recovery, cancellation, runner receipt semantics and result idempotency are unresolved.
6. Do not deploy a runner or enable execution until M0 gVisor isolation evidence is complete and reviewed.

## Prototype acceptance tests

- Empty pull uses bounded jittered backoff; no tight polling loop.
- Concurrent pull consumers receive distinct initial deliveries, but tests must also demonstrate that an expired lease can be acknowledged late by the old consumer after redelivery; PostgreSQL idempotency/fencing must still prevent duplicate logical work.
- Malformed, oversized, duplicate-key, unknown-field and unsupported content-type messages are rejected safely.
- Queue delivery replay creates exactly one PostgreSQL handoff intent.
- Queue acknowledgement occurs only after the handoff transaction is confirmed committed.
- Token scope and the current pull-consumer guide/API-reference permission discrepancy are verified in a dedicated non-production account before native pull is approved.
- Crash after commit but before acknowledgement is recovered by redelivery and exact duplicate detection.
- Control-plane outage or unknown transaction outcome does not cause premature acknowledgement.
- Queue retry exhaustion routes to a configured DLQ and produces an operator-visible alert.
- A stale Queue lease cannot bypass the PostgreSQL dispatch lease fence.
- A stale PostgreSQL worker token cannot claim, renew, acknowledge or complete another worker's lease.
- Runner identity cannot access unrelated tenant jobs or artifacts.
- Queue/API credentials are absent from sandbox environment, filesystem mounts, process arguments, logs and crash dumps.
- Student source and hidden tests never appear in Queue messages or control-plane logs.
- Artifact digest and size are verified before sandbox input staging.
- Agent restart, host reboot, queue outage and control-plane outage do not strand a job without a durable recovery path.

## References

- Cloudflare Queues pull consumers: https://developers.cloudflare.com/queues/configuration/pull-consumers/
- Cloudflare Queues overview: https://developers.cloudflare.com/queues/
- Cloudflare Workers VPC with Tunnel: https://developers.cloudflare.com/workers-vpc/configuration/tunnel/
- Cloudflare Workers mTLS: https://developers.cloudflare.com/workers/runtime-apis/bindings/mtls/
- Cloudflare Hyperdrive connection pooling: https://developers.cloudflare.com/hyperdrive/concepts/connection-pooling/

## Explicit non-goals

- This evaluation does not approve a transport for production.
- It does not implement a Queue consumer, machine identity, lease HTTP API, artifact endpoint, runner HTTP endpoint or result callback.
- It does not create Cloudflare resources or secrets.
- It does not authorize a production database connection from the runner.
- It does not change `UnconfiguredExecutor`; student-code execution remains fail-closed.
- It does not satisfy the gVisor M0 evidence gate.
