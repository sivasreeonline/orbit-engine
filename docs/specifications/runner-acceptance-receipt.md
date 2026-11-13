# Authenticated runner acceptance receipt

**Status:** Implemented receipt persistence and API boundary; the Go runner still does not call it.

## Endpoint

`POST /internal/v1/runner/accept`

Content type: `application/json`

Body (no additional fields):

```json
{
  "acceptanceId": "runner-generated-uuid",
  "dispatchId": "claimed-dispatch-uuid",
  "executionId": "execution-uuid",
  "attemptId": "attempt-uuid",
  "leaseToken": "current-fencing-token"
}
```

The request uses the per-runner Ed25519 headers and signs the exact raw body bytes. The API validates timestamp freshness, key status, signature and nonce replay protection before persisting the receipt.

## Durable acceptance transaction

The repository performs one PostgreSQL transaction:

1. Rechecks and locks the active runner machine/key, including revocation and validity.
2. Locks the dispatch and execution-job rows.
3. Checks for an existing receipt for this exact dispatch and lease token. An identical acceptance ID, runner identity and body digest is returned as an idempotent replay; conflicting content is rejected.
4. For a first receipt, verifies dispatch and execution-job owners, lease tokens, states and expiries all match the authenticated runner and remain active.
5. Appends an immutable `RUNNER_ACCEPTED` evidence event with actor kind `RUNNER`.
6. Inserts the immutable receipt, including runner ID, key ID, dispatch/execution/attempt IDs, lease token, acceptance ID and SHA-256 digest of the exact signed body.
7. Commits before returning accepted.

A new lease generation can have a new acceptance record because receipt uniqueness is scoped to `(dispatch_id, lease_token)`. An old lease cannot mutate a newer lease.

## Idempotency and failure behaviour

- The signed-request nonce prevents HTTP replay of the same signed request.
- `acceptanceId` and the body digest provide durable receipt idempotency if the runner retries with a fresh signed nonce after a lost response.
- Exact duplicates return `replayed: true`.
- Different receipt content for the same dispatch/lease returns a conflict.
- Revoked/unknown keys are rejected.
- Expired or mismatched leases are rejected.
- Database failures fail closed and return a retryable infrastructure error.
- No source code, hidden tests, expected outputs or private diagnostics are part of the receipt.

## Important boundary

The API can prove that an authenticated runner signed and submitted a receipt and that the control plane durably recorded it. It cannot by itself prove that the runner wrote its local acceptance journal before sending. The Go runner must implement that write-before-send ordering and local idempotency store before this becomes an end-to-end durable acceptance guarantee.

This endpoint does not retrieve source/test artifacts, start a process, renew leases, execute code or report results. The Go runner remains health-only and execution-disabled.
