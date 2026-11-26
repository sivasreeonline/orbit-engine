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
