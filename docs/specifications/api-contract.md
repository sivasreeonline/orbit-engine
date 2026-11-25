# API Contract — v1

All endpoints are versioned under `/api/v1`. The canonical target schema is
`docs/api/openapi-v1.yaml`; this document explains its trust and lifecycle
rules. The OpenAPI operations describe the target contract and do not imply
that every operation is currently implemented.

## Endpoints

- GET /problems — browse published problems.
- GET /problems/{problemId} — fetch sanitized problem details.
- POST /problems/{problemId}/runs — create a Run attempt.
- POST /problems/{problemId}/submissions — create an official Submit attempt.
- GET /submissions/{submissionId} — status and sanitized result.
- GET /submissions/{submissionId}/timeline — attempt history.
- GET /submissions/{submissionId}/feedback — advisory feedback when available.
- GET /students/me/skill-profile — future profile endpoint; do not fabricate mastery metrics.
- Trainer endpoints require trainer role and batch/college scope and are not part of this v1 OpenAPI operation set.

## Authentication and tenant context

Mutation and student-data operations require platform authentication and
tenant-aware authorization. The tenant ID and user ID come from the verified
server-side principal, never from request-body fields or caller-controlled
headers. The bearer token is a credential and must not be logged.

## Run and Submit request

The JSON body contains only:

- `problemVersionId`
- `language` (`java` or `python`)
- `runtimeVersion`
- `sourceCode` (maximum 200,000 characters)

The client supplies an `Idempotency-Key` header; it is not a JSON body field.
The server determines action from the endpoint and chooses the authorized test
bundle, immutable runtime image, comparison policy, tenant context, and resource
limits. The client cannot select hidden tests, expected output, runtime image
digest, cancellation reference, or trusted resource policy.

Run uses public tests. Submit uses the server-selected official test suite.
Both operations return HTTP 202 with `submissionId`, `executionId`, `QUEUED`
state, `statusUrl`, and `correlationId`. Request handlers enqueue work; they
never execute student source synchronously.

## Correlation and idempotency

The optional `X-Correlation-ID` header is for bounded tracing only. The server
replaces malformed or oversized values and returns the effective ID in the
response header and error/accepted payload. It is not an authentication token
or tenant selector.

Require `Idempotency-Key` on Run and Submit. Scope the key by authenticated
tenant, student, and operation. Repeating the same key with the same normalized
request returns the same logical operation. Reusing the key with a different
request returns HTTP 409. A retry must never create a second logical attempt.

## Status response and disclosure

Status responses may include state, timestamps, terminal verdict, public-test
aggregate, bounded runtime/memory metrics, and sanitized diagnostics. Never
return hidden input, expected output, hidden-test stdout/stderr, private test
bundle contents, host paths, environment variables, credentials, or raw
sandbox diagnostics. Public-test output is returned only when explicitly
authorized and independently byte-capped.

The immutable attempt timeline records source snapshot identity and lifecycle
events. Student-facing timeline data must not expose internal host details or
hidden-test evidence.

## Error model

Errors use a stable machine-readable code, safe human-readable message,
`correlationId`, and `retryable` boolean. Validation, authentication,
authorization, and quota errors are not automatically retried. Infrastructure
failures are distinct from student verdicts and use bounded retry rules.

## Implementation status

The current API implements only health/readiness and problem-catalog GET
routes. Run, Submit, submission status, timeline, and feedback operations are
target contract definitions, not live endpoints. The frontend mock adapter is
not a production execution path. The Go runner remains fail-closed until the
separate M0 sandbox gates are evidenced and approved.
