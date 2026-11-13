# Authenticated execution intake API

**Status:** Proposed implementation slice  
**Route:** `POST /api/v1/executions`

## Request contract

Headers:
- `Authorization`: supplied by the configured Sky High identity provider.
- `Content-Type: application/json`.
- `Idempotency-Key`: 1–128 characters from `A-Z a-z 0-9 . _ ~ -`.
- Optional `X-Correlation-ID`: accepted only when it matches the API correlation-ID allowlist; otherwise the API generates one.

JSON body has exactly four fields:
- `action`: `RUN` or `SUBMIT`.
- `problemSlug`: published problem slug.
- `language`: `java` or `python`.
- `sourceCode`: non-empty source string, maximum 200 KiB after UTF-8 encoding.

Client-supplied tenant IDs, student IDs, runtime versions, test bundles, expected outputs and other fields are rejected. Tenant/student ownership comes only from the authenticated principal. Runtime versions are selected from trusted server configuration (Java 25 and Python 3.14 in the current local configuration).

The JSON request is bounded to 256 KiB while being read, not merely checked after buffering.

## Acceptance and idempotency

The API calls the existing transactional intake repository. It persists the immutable source snapshot, attempt, queued job, intake outbox event and idempotency reservation in one database transaction.

A successful response is HTTP 202 and includes the execution ID, attempt ID, action, accepted indicator, replay indicator and status URL. The response does not assert a current execution state because an idempotent replay may refer to work that has already advanced. The client should use the status URL to read the current state. Repeating the same idempotency key with the same request returns the original execution; reusing it for a different request returns 409.

The intake outbox publisher remains an at-least-once publisher. Consumers must remain idempotent. A 202 means the request is durably accepted into the database; it does not mean a runner has started or code has executed.

## Failure behaviour

- Missing/invalid idempotency key: 400.
- Invalid body, unsupported fields or source language/action: 400.
- Request body over 256 KiB or source over 200 KiB: 413.
- Unsupported content type: 415.
- Unpublished problem: 404.
- Idempotency conflict: 409.
- Database outage: retryable 503.
- Missing intake/runtime configuration: 503.

## Security boundaries

- Authentication runs before body parsing.
- Request-supplied identity and runtime fields are never trusted.
- The intake repository derives tenant/student ownership from the principal and enforces it in database constraints.
- Source code is stored as immutable evidence and is never copied into the outbox message.
- Error responses never return database driver messages or source code.

## Not proven by this slice

The default authenticator is still unconfigured, so production student authentication is not enabled. This endpoint persists requests but does not itself execute code. The Cloudflare queue producer is configured; an authenticated queue consumer/runner transport and isolated Java/Python execution still need separate implementation and validation. No 500-online load capacity or 500 concurrent execution capacity is claimed.
