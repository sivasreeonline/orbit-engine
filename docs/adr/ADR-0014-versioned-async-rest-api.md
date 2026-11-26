# ADR-0014: Versioned Asynchronous REST API

- Status: Accepted
- Decision: Expose versioned APIs under /api/v1. Run and Submit return an execution/submission identifier and queued/accepted status; clients retrieve status and result asynchronously.
- Consequences: Use idempotency keys, request validation, stable error codes, correlation IDs and explicit state transitions. Do not hold open an HTTP request for compilation and test execution.
