# OpenAPI Contract Scope

The canonical API schema is to be maintained in docs/api/openapi-v1.yaml. API implementation must match that schema.

Minimum operation set:
- GET /api/v1/problems
- GET /api/v1/problems/{problemId}
- POST /api/v1/problems/{problemId}/runs
- POST /api/v1/problems/{problemId}/submissions
- GET /api/v1/submissions/{submissionId}
- GET /api/v1/submissions/{submissionId}/timeline
- GET /api/v1/submissions/{submissionId}/feedback

All mutation operations require authentication, authorization, payload validation, idempotency and correlation IDs. Run and Submit return HTTP 202. No synchronous code execution in request handlers. Hidden test payloads must never be included in API schemas exposed to students.

## Implementation status (main branch)

This document and `docs/api/openapi-v1.yaml` describe the **target M1 contract**. They do not imply that every operation is already implemented or deployable.

| Operation | Current implementation status |
| --- | --- |
| `GET /api/v1/problems` | Handler and repository path implemented; requires a configured trusted identity provider and database. |
| `GET /api/v1/problems/{problemId}` | Handler and repository path implemented; requires a configured trusted identity provider and database. |
| `POST /api/v1/problems/{problemId}/runs` | Not implemented. |
| `POST /api/v1/problems/{problemId}/submissions` | Not implemented. |
| `GET /api/v1/submissions/{submissionId}` | Not implemented. |
| `GET /api/v1/submissions/{submissionId}/timeline` | Not implemented. |
| `GET /api/v1/submissions/{submissionId}/feedback` | Not implemented. |

The current API exposes liveness/readiness plus the problem-catalog GET routes. The identity adapter remains fail-closed until configured. The frontend Run/Submit flow uses a mock adapter; no API route dispatches source code to the Go runner. The Go runner remains fail-closed through `UnconfiguredExecutor`.

When an operation is implemented, update this status table in the same change that adds the handler and its tests. A frontend mock response, OpenAPI operation, or successful deployment dry-run is not evidence that a real execution endpoint exists.
