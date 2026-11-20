# Authenticated Runner Lifecycle

**Status:** Claim, durable acceptance and start control-plane transitions implemented; process execution remains disabled.

## Lifecycle

The control plane exposes three authenticated runner operations. Every request is signed with the registered runner's Ed25519 private key. The API verifies the signature against the registered public key, enforces a short timestamp window, and consumes a one-time nonce after signature verification.

### 1. Claim

`POST /internal/v1/runner/claim`

Request:

```json
{ "requestedSlots": 2 }
```

The control plane enforces at most two active leases per runner, independent of the requested slot count. A successful response contains dispatch, execution and attempt IDs, protocol/correlation metadata, delivery attempt, lease token and expiry.

It does not contain student source, hidden tests, expected outputs, credentials or executable artifacts.

### 2. Durable acceptance

`POST /internal/v1/runner/accept`

The runner first writes a `PREPARED` receipt to its local append-only journal and fsyncs it. Only then does it send the signed five-field receipt:

```json
{
  "acceptanceId": "uuid",
  "dispatchId": "uuid",
  "executionId": "uuid",
  "attemptId": "uuid",
  "leaseToken": "uuid"
}
```

The control plane verifies that the same registered runner owns the active dispatch and execution-job lease. It appends `RUNNER_ACCEPTED` and persists a durable acceptance receipt transactionally. The runner confirms the receipt in its local journal only after receiving the matching acknowledgement.

A retry uses the same acceptance ID and body with a fresh signed nonce. The API returns the existing acknowledgement for an identical replay.

### 3. Start

`POST /internal/v1/runner/start`

The runner sends the exact dispatch identity and fencing token:

```json
{
  "dispatchId": "uuid",
  "executionId": "uuid",
  "attemptId": "uuid",
  "leaseToken": "uuid"
}
```

The server derives runner identity and key ID from the signed request; they are never accepted from the JSON body.

The start transaction requires:
- the registered runner/key is still active;
- dispatch and job refer to the same execution and attempt;
- both lease records carry the same runner and unexpired fencing token;
- a durable acceptance receipt exists for the exact dispatch and lease generation;
- the execution job is still `CLAIMED`.

On success, one database transaction:
1. changes `execution_jobs` from `CLAIMED` to `RUNNING`;
2. preserves the same lease owner/token/expiry as the fencing identity;
3. appends the immutable `RUNNER_STARTED` event;
4. inserts an immutable start receipt bound to the exact accepted dispatch/lease.

The start receipt is idempotent for the same lease generation. Conflicting runner/key/attempt identity, missing acceptance, expired lease or invalid state fails closed. The response does not echo the lease token.

### 4. Lease heartbeat

`POST /internal/v1/runner/heartbeat`

After a successful start, the runner renews the exact same lease generation using a fresh signed request and a stable heartbeat ID:

```json
{
  "heartbeatId": "uuid",
  "dispatchId": "uuid",
  "executionId": "uuid",
  "attemptId": "uuid",
  "leaseToken": "uuid"
}
```

The API derives runner and key identity from the Ed25519 signature. A heartbeat is accepted only if:
- the runner/key remains active;
- the exact dispatch and job lease still belong to that runner and share the same fencing token;
- both current expiries are still in the future and match one another;
- the job is `RUNNING`;
- the exact lease generation has both durable acceptance and start receipts.

The API extends both dispatch and job expiries together by a server-controlled 120 seconds and records an immutable heartbeat receipt. The expiry is calculated by PostgreSQL wall-clock time. The heartbeat ID is an idempotency key: retrying the same request after a lost acknowledgement returns the original recorded expiry and does not perform another renewal.

A heartbeat cannot revive an expired lease, start an unstarted dispatch, switch runner identity, or change the fencing token. A stale lease is rejected and must not continue to execute.

Heartbeats are operational lease records, not student-learning evidence events. They do not contain source code, hidden tests, output or program data.

### 5. Terminal completion

`POST /internal/v1/runner/complete`

The runner submits only aggregate, allowlisted result metadata. The body includes the dispatch/execution/attempt IDs, lease token, infrastructure and compilation status, verdict, cleanup status, test counts, duration, runner version, result digest and timestamps. It does not accept source, hidden test contents, stdout, stderr, stack traces or arbitrary diagnostics.

The API derives runner/key identity from the signed Ed25519 request. The database transaction requires the exact active, unexpired dispatch and job lease; the current registered machine key; and matching durable acceptance and start receipts.

One transaction:
1. closes the dispatch lease;
2. transitions the execution job to `COMPLETED` or `FAILED_INFRASTRUCTURE`;
3. writes the immutable aggregate result record;
4. appends the terminal evidence event;
5. stores an immutable completion receipt bound to the dispatch, lease token, runner, key, event and result digest.

The completion receipt is idempotent for the same exact lease generation and result digest. A conflicting digest, runner/key identity or terminal state fails closed. Completion does not accept a result after the lease expires.

### 6. Expired RUNNING lease recovery

The scheduled API Worker performs an expiry sweep before publishing new outbox work. It locks expired dispatch/job pairs with `FOR UPDATE SKIP LOCKED`, so competing sweepers cannot make duplicate recovery decisions.

Default policy:
- up to two requeues after the initial lease;
- exponential retry delay starting at 5 seconds, capped at 60 seconds;
- a fresh lease token is generated by the normal fair dispatcher for every subsequent claim;
- each expired lease generation gets one immutable recovery receipt.

For a retryable expiry, the same execution returns to `QUEUED`, both dispatch/job lease identities are cleared, the start timestamp is reset, and `RETRY_SCHEDULED` evidence records `RUNNER_LEASE_EXPIRED`. The next runner must durably accept and start the new lease token. Start receipts are append-only per lease generation; they are no longer unique per execution.

After the retry budget is exhausted, recovery marks the job `FAILED_INFRASTRUCTURE`, dead-letters the dispatch, writes an immutable infrastructure-failure result with verdict `NOT_EVALUATED`, appends `INFRASTRUCTURE_FAILED` evidence, and stores the final recovery receipt. A runner timeout is never counted as a wrong answer.

The recovery sweep does not claim that a killed process was cleaned up. Cleanup remains `UNKNOWN` until a trusted sandbox cleanup attestation can be recorded. No process execution is enabled by recovery itself.

## State and safety invariants

- Claiming, accepting and starting are separate durable lifecycle checkpoints.
- The runner's request nonce is one-time and bound to the registered key.
- Heartbeat renewal extends both lease rows together under the same fencing identity; it never revives an expired lease.
- Replaying a heartbeat ID returns its original acknowledgement without extending the lease again.
- Completion is an atomic, lease-fenced terminal checkpoint.
- Every expired lease generation receives at most one recovery decision; subsequent retries use a fresh fencing token.
- Exhausted runner retries become infrastructure failure, never a student wrong-answer verdict.
- Lease tokens fence stale or competing runner instances.
- Acceptance and start receipts are append-only.
- Event IDs and receipt identities make retry responses stable without duplicating logical lifecycle evidence.
- No source code or hidden tests are sent in claim, acceptance or start requests.
- A durable `RUNNER_STARTED` event proves only that the control plane accepted the start transition; it does not prove that a process actually executed or that a student verdict exists.

## Current non-goals

This lifecycle does not yet provide:
- private artifact retrieval scoped to the accepted execution/attempt;
- runner liveness detection beyond lease expiry;
- recovery of expired `RUNNING` jobs;
- execution completion, cancellation or result submission endpoints;
- sandbox process startup or Java/Python execution.

The Go runner remains loopback-only and health-only, with `UnconfiguredExecutor`. No student program is executed by these control-plane transitions. The next engineering gates are artifact authorization and lease lifecycle/recovery, followed by Linux/gVisor sandbox qualification and end-to-end runner tests.