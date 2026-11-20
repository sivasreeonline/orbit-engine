# Go runner local acceptance journal

**Status:** Implemented local persistence primitive; not yet connected to network transport.

## Purpose

The API's acceptance receipt endpoint records a runner-signed receipt in PostgreSQL. To make the runner side durable too, the runner must write its acceptance intent locally before sending the receipt.

## Write-before-send sequence

1. Receive an authenticated dispatch assignment with its lease token.
2. Generate an `acceptanceId` once for that dispatch/lease generation.
3. Append a `PREPARED` JSONL event to the local journal and call `fsync` via `File.Sync()`.
4. Only after `Prepare` succeeds, send the signed acceptance body to `POST /internal/v1/runner/accept`.
5. After a successful durable API response, append a `CONFIRMED` event containing the returned evidence event ID and fsync again.
6. On process restart, enumerate `Pending()` and retry every prepared-but-unconfirmed receipt with the same acceptanceId and body, but a fresh signed HTTP timestamp and nonce.

The API stores the exact body digest and treats a matching acceptanceId/body/lease as an idempotent replay.

## Journal guarantees

- Append-only versioned JSONL events: `PREPARED` and `CONFIRMED`.
- Owner-only file permissions (0600); parent directory is created with 0700 permissions.
- Fsync after every append before the method reports success.
- Stable identity is `(dispatchId, leaseToken)`; one acceptanceId cannot be reused for another lease.
- Exact prepare retries return the original durable record.
- Confirmation retries with the same API event ID are idempotent.
- On restart, complete records are replayed. An incomplete trailing line is truncated; malformed complete records fail closed.
- Unknown fields, unsupported versions, invalid UUIDs, conflicting records and missing receipt references are rejected.
- The initial journal has a 64 MiB size ceiling and no automatic compaction/deletion.

## Operational boundary

A single runner process must own a journal file. Multi-process file locking, journal archival/rotation, encryption-at-rest policy and disk-full alerting remain deployment concerns to settle before production. The journal contains lease tokens and must remain on a private runner filesystem.

## Not yet proven

The journal package is not yet called by the runner claim loop or HTTP client. No runner HTTP polling, signed acceptance request, API response retry loop or gVisor execution is enabled. The runner remains loopback-only and health-only.
