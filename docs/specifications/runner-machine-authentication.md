# Runner machine identity and replay protection

**Status:** Proposed implementation slice; not yet wired to a network endpoint.

## Identity model

- `runner_machines` represents a registered runner host/agent.
- `runner_machine_keys` stores a unique key ID and exactly 32 raw Ed25519 public-key bytes.
- Only public keys are stored in PostgreSQL. Private keys remain on the runner host.
- A runner can have multiple active keys during a controlled rotation overlap.
- Machine and key status, validity windows and explicit revocation are checked on every authentication.
- No self-service runner registration endpoint exists in this slice.

## Signed request headers

- `X-SkyHigh-Runner-Key-Id`
- `X-SkyHigh-Runner-Timestamp` (10-digit Unix seconds)
- `X-SkyHigh-Runner-Nonce` (32 random bytes, canonical unpadded base64url)
- `X-SkyHigh-Runner-Signature` (64-byte Ed25519 signature, canonical unpadded base64url)

The signature covers the canonical request format defined in `runner-ed25519-request-signature.md`, including the exact body bytes.

## Authentication order

1. Validate required headers and raw body size.
2. Reject timestamps outside the ±30-second clock-skew window.
3. Load an active, non-revoked key whose validity window includes the current time and whose machine is active.
4. Verify the Ed25519 signature over method, path/query, timestamp, nonce and exact body digest.
5. Atomically consume the nonce under the key ID.
6. Return the authenticated runner ID and key ID to the protected handler.

Nonce consumption occurs only after signature verification. Concurrent duplicate requests race on a database primary key; exactly one can consume the same nonce.

## Nonce retention

Consumed nonces are unique per key ID. Expired nonce rows for that key are deleted in the same transaction before a new nonce is inserted. The current retention period is five minutes, longer than the 30-second timestamp freshness window. Replaying a request after nonce cleanup still fails the timestamp check.

## Failure behaviour

- Unknown, revoked, expired or not-yet-valid keys are rejected.
- Invalid signatures, stale timestamps and reused nonces are rejected.
- Database/key-registry outages propagate as infrastructure errors; they are not converted into successful authentication.
- No private key, signature body, source code or test data is logged.

## Not enabled yet

This slice provides the registry, repository and authenticator primitive. It does not create production runner identities, add a registration/rotation administration workflow, wire authentication to a claim endpoint, consume runner work, accept receipts, retrieve artifacts or execute code. The API remains student-facing only; the Go runner remains health-only.
