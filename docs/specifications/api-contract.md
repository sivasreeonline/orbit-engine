# API Contract — v1

All endpoints are versioned under /api/v1. Require platform authentication and tenant-aware authorization. Validate request size, language, problem version, source encoding and idempotency key.

## Endpoints
- GET /problems — browse published problems.
- GET /problems/{problemId} — fetch sanitized problem details.
- POST /problems/{problemId}/runs — create a Run attempt.
- POST /problems/{problemId}/submissions — create an official Submit attempt.
- GET /submissions/{submissionId} — status and sanitized result.
- GET /submissions/{submissionId}/timeline — attempt history.
- GET /submissions/{submissionId}/feedback — advisory feedback when available.
- GET /students/me/skill-profile — initial profile placeholder; do not fabricate mastery metrics.
- Trainer endpoints require trainer role and batch/college scope.

## Run and Submit request
Fields: problemVersionId, language, runtimeVersion, sourceCode, idempotencyKey.
The server determines action from endpoint and test suite. Client must not select hidden test cases, test bundle, runtime image digest or resource limits.
Return 202 Accepted with submissionId/executionId, QUEUED state, status URL and correlation ID.

## Status response
Include state, createdAt, updatedAt, terminal verdict when available, public test aggregate, runtime/memory aggregate and sanitized output. Never include hidden input/expected output or internal secrets.

## Error model
Stable machine-readable code, human-readable message, correlationId and retryable boolean.
Validation/auth/quota errors are not retried automatically. Infrastructure errors have separate status and bounded retry rules.

## Idempotency
Require an idempotency key for mutation requests. Scope by tenant, student and endpoint. Repeated same key and same payload returns the same logical operation. Same key with a different payload returns conflict.
