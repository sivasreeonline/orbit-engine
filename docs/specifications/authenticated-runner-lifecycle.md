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

## State and safety invariants

- Claiming, accepting and starting are separate durable lifecycle checkpoints.
- The runner's request nonce is one-time and bound to the registered key.
- Lease tokens fence stale or competing runner instances.
- Acceptance and start receipts are append-only.
- Event IDs and receipt identities make retry responses stable without duplicating logical lifecycle evidence.
- No source code or hidden tests are sent in claim, acceptance or start requests.
- A durable `RUNNER_STARTED` event proves only that the control plane accepted the start transition; it does not prove that a process actually executed or that a student verdict exists.

## Current non-goals

This lifecycle does not yet provide:
- private artifact retrieval scoped to the accepted execution/attempt;
- lease heartbeat/renewal or runner liveness;
- recovery of expired `RUNNING` jobs;
- execution completion, cancellation or result submission endpoints;
- sandbox process startup or Java/Python execution.

The Go runner remains loopback-only and health-only, with `UnconfiguredExecutor`. No student program is executed by these control-plane transitions. The next engineering gates are artifact authorization and lease lifecycle/recovery, followed by Linux/gVisor sandbox qualification and end-to-end runner tests.