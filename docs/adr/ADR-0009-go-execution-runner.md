# ADR-0009: Go Execution Runner

- Status: Accepted
- Decision: Implement the runner agent and lifecycle orchestration in Go.
- Responsibilities: authenticate dispatch, claim execution, prepare ephemeral sandbox, invoke runtime, collect bounded output and metrics, enforce deadlines, clean up, and report structured results.
- Constraints: context cancellation, bounded concurrency, structured logs, no secrets in student containers, tests for every termination path.
