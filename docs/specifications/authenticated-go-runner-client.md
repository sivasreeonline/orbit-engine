# Authenticated Go runner claim and acceptance client

**Status:** Client library implemented; process polling and execution remain disabled.

## Scope

The Go runner now has a reusable outbound HTTP client for the existing control-plane endpoints:

- `POST /internal/v1/runner/claim`
- `POST /internal/v1/runner/accept`

The client uses the existing canonical Ed25519 request signer and registered runner key ID. It does not add inbound runner endpoints, register keys, provision credentials, retrieve artifacts, start processes, or enable Java/Python execution.

## Claim contract

The client sends a signed JSON body containing only `requestedSlots` (1–4). The current control plane caps effective claims at two active leases per runner and uses 120-second leases.

The response is parsed strictly. Unknown fields, inconsistent claim counts, a capacity-policy mismatch, duplicate dispatch IDs, invalid identifiers, incomplete metadata, and expired leases fail closed. The current response contains dispatch metadata only:

- dispatch ID;
- execution ID and attempt ID;
- protocol version and correlation ID;
- delivery attempt;
- lease fencing token and expiry.

It does not contain student source, hidden tests, expected answers, or executable artifacts.

## Durable acceptance sequence

For a newly claimed dispatch:

1. Look for a local receipt keyed by dispatch ID and lease token.
2. If absent, generate an acceptance ID and append a `PREPARED` journal event.
3. Fsync the journal; do not send unless this succeeds.
4. Send the exact five-field acceptance body with a fresh signed request timestamp and nonce.
5. Validate the API acknowledgement against dispatch ID and acceptance ID.
6. Append the returned evidence event ID as a `CONFIRMED` journal event and fsync.

For a network error or lost response, the prepared receipt remains pending. On restart, `RetryPending` resends the same receipt identity and body with a fresh nonce. The server-side receipt endpoint supplies durable idempotency.

## Transport safeguards

- HTTPS is required for non-loopback hosts; HTTP is permitted only for localhost/loopback development.
- Credentialed URLs, URL paths, query strings and fragments are rejected.
- Signed requests are never redirected.
- Responses are limited to 64 KiB and decoded with unknown-field rejection.
- The HTTP client has a 10-second default timeout; callers should also pass operation-specific contexts.
- The private key remains supplied by runtime configuration and is never logged or persisted by this client.

## Current non-goals and next gates

- The client is a library and is not yet wired into `cmd/runner` as a continuous polling loop.
- No runner private key or machine identity is provisioned by this change.
- No artifact retrieval or `RUNNER_STARTED` endpoint exists in this slice.
- No sandbox process is started. The executor remains unconfigured and readiness remains false.
- Before process integration, add a reviewed key-loading/permission strategy, graceful shutdown, bounded poll/backoff, lease-expiry handling, and cross-process ownership for the journal.
- Before student execution, complete private artifact authorization and the Linux/gVisor M0 security proof.

## Tests

The client tests cover signature verification, bounded claim metadata, malformed/expired response rejection, write-ahead receipt ordering, restart recovery after a temporary API failure, fresh request nonce on retry, strict response parsing, and redirect rejection. Exact-head CI results are authoritative; local execution is not inferred from source inspection.
