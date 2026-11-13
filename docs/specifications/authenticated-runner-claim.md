# Authenticated runner claim endpoint

**Status:** Implementation slice; runner acceptance and execution remain disabled.

## Endpoint

`POST /internal/v1/runner/claim`

Content type: `application/json`

Body schema (no additional fields):

```json
{"requestedSlots":1}
```

The request is authenticated with the Ed25519 machine headers defined in `runner-machine-authentication.md`. The signature covers the exact raw body bytes, method, path/query, timestamp and nonce. The API verifies timestamp freshness, key validity, machine status and signature, then atomically consumes the nonce before claiming work.

## Capacity policy

- Requested slots must be an integer from 1 to 4.
- The server caps the effective request at 2 slots.
- A runner may hold at most 2 unexpired active dispatch leases across all of its keys.
- Lease duration is currently 120 seconds.
- The repository serializes the short fair-scheduler transaction with a PostgreSQL advisory lock so concurrent runner hosts observe committed lane cursors in a deterministic order.
- It also acquires a per-runner advisory lock and reads that runner's active-lease count in a separate READ COMMITTED statement, preventing concurrent polls from spending the same remaining capacity.
- Eligible jobs are selected through the existing fair per-student scheduler, with at most one job per student lane in a claim batch.

These are conservative initial control-plane limits, not measured execution throughput. They must be revisited after local integration and load testing.

## Response

The runner and execution-job lease owner is the authenticated runner machine ID. The shared lease token is subsequently required by the start/result lifecycle, so the execution-job repository and dispatch scheduler cannot drift into separate lease identities.

Each returned dispatch contains only:
- dispatch ID;
- execution ID and attempt ID;
- protocol version and correlation ID;
- delivery attempt count;
- lease fencing token and expiry.

No source bytes, source text, hidden tests, expected outputs, database credentials or private diagnostics are returned.

## Recovery and retries

- Duplicate/previously consumed signed request nonces are rejected.
- The runner should create a fresh timestamp and nonce for every poll.
- A lease expires after 120 seconds if not renewed/accepted by a later protocol stage.
- A lost response may leave a lease active until expiry; a subsequent poll cannot exceed the active lease cap.
- The next protocol slice must define a durable acceptance receipt and lifecycle event before runner work is considered accepted.

## Not implemented by this endpoint

This endpoint only leases dispatch metadata. It does not authenticate a durable runner acceptance receipt, retrieve source or hidden-test artifacts, renew leases, report start/cancel/result events, invoke gVisor, or execute Java/Python. The Go runner remains health-only. No Cloudflare queue, paid infrastructure or deployment is created by this change.
