# Testing and Release Gates

## Unit tests
- API request validation and authorization.
- Problem version and test selection policy.
- State machine transitions.
- Comparator rules.
- Idempotency and outbox behavior.
- Runner protocol validation and result classification.

## Integration tests
- API -> database -> outbox -> queue -> mock runner -> report -> API.
- Real runner integration after M0.
- Java compile/run and Python run.
- Public vs hidden test sanitization.
- Retry, duplicate queue delivery and runner restart.

## Security tests
- Infinite loop, memory exhaustion, fork bomb, output flood.
- Filesystem traversal and host mount inspection.
- Network egress, DNS and metadata endpoint attempts.
- Non-root identity, dropped capabilities and read-only base filesystem.
- Timeout/cancel kills process tree and cleans workspace.
- Hidden tests and secrets absent from client response and logs.
- Queue replay and authorization bypass.

## Performance and reliability
Test concurrent submission levels progressively (10, 25, 50, 100, 200) on selected host; these are test stages, not capacity claims. Record queue wait, startup, compile, execution, evaluation and end-to-end latency. Measure CPU, memory, failure rate and cleanup leakage.

## CI gates
- Typecheck, lint, unit tests and frontend build.
- Go fmt check, go vet and go test.
- Dependency and secret scanning.
- Migration validation and API schema validation.
- Integration/security suites for relevant changes.

## Release approval
M0 passing proof permits controlled integration testing, not automatically production use. Production requires threat review, operational runbook, host patching, monitoring, backup/recovery, retention/privacy policy and security sign-off.
