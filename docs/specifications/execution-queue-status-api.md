# Execution queue status API

**Status:** Proposed implementation slice  
**Route:** `GET /api/v1/executions/{executionId}/status`

## Purpose

Let an authenticated student refresh the lifecycle state of one execution after Run or Submit intake. This endpoint is a read model only; it does not claim, dispatch, start, cancel or retry work.

## Ownership and privacy

- The execution is resolved through `execution_jobs` → `execution_attempts`.
- Both `tenant_id` and `actor_user_id` come from the authenticated principal and are mandatory SQL predicates.
- An unknown execution and an execution owned by another student produce the same non-disclosing 404 response.
- The response contains lifecycle metadata only: execution ID, attempt ID, Run/Submit action, execution state, runner-dispatch delivery state, submitted timestamp and last-updated timestamp.
- It never returns source code, source bytes, source hashes, hidden tests, expected outputs, compiler/runtime diagnostics, private runner payloads or credentials.
- Responses are `no-store`.

## State semantics

- `executionState` is the authoritative `execution_jobs.state`: QUEUED, CLAIMED, RUNNING, EVALUATING or a terminal state.
- `dispatchState` is the durable runner-dispatch outbox state: PENDING, DELIVERED, DEAD_LETTER, or null before a runner-dispatch handoff exists.
- A PENDING dispatch is not proof that a runner has started. RUNNING and terminal execution states are driven by the execution lifecycle, not inferred from queue delivery.
- Run and Submit remain distinct via the immutable attempt action.

## Queue position

This slice intentionally does not return a numeric queue position. Fair dispatch is lane-based (one eligible item per student per batch), concurrent workers may claim lanes, and leased work changes eligibility. A simple FIFO count would therefore be misleading. A future position/ETA must be defined against the actual scheduler policy and measured service capacity; it must not be fabricated from raw pending-row counts.

## Failure behaviour

- Invalid execution IDs return 400.
- Missing or non-owned executions return the same 404.
- Missing status-store configuration or database outage fails closed with retryable 503.
- Unexpected failures return a generic 500 without driver details.

## Not proven by this slice

This endpoint does not establish real runner transport, real Java/Python execution, queue wait-time guarantees, 500-online load capacity or 500 concurrent execution capacity. Authentication remains dependent on the configured identity provider; the current default authenticator is still unconfigured.
