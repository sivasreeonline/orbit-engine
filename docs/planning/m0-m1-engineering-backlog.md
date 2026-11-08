# M0/M1 Engineering Backlog

## Parallel tracks

### Track A — M0 runner proof
1. Select Linux host architecture and provider.
2. Provision patched Linux host and private runner network.
3. Install OCI runtime and evaluate gVisor/runsc.
4. Build minimal Go runner service and protocol types.
5. Build pinned Java 25 and Python 3.14 runtime images.
6. Implement ephemeral sandbox lifecycle.
7. Enforce CPU, memory, PID, wall-clock, filesystem and output limits.
8. Disable network and test DNS/metadata denial.
9. Implement cancellation, cleanup, idempotency and structured results.
10. Run adversarial and concurrency tests; write operational runbook.

### Track B — M1 product with mock adapter
1. Scaffold Vite + React + TypeScript frontend.
2. Establish API Worker project and request validation.
3. Add PostgreSQL migrations and seed problem data.
4. Implement problem catalog and immutable problem versions.
5. Implement submission/attempt/job state model.
6. Define execution adapter interface and deterministic mock adapter.
7. Implement Run and Submit routes returning 202.
8. Implement status polling and result UI.
9. Add attempt timeline and source snapshot hashes.
10. Add trainer problem authoring and review view.
11. Replace mock adapter with M0 runner after security gate.

## First vertical slice
Student opens a seeded Two Sum console-mode problem, writes a Java solution, clicks Run, sees sample test output, submits, receives an asynchronous verdict, and can reopen the exact source snapshot and result.

## Working agreements
- Every ticket has a testable acceptance criterion.
- Feature branches; no direct commits to main.
- Mock adapter must be visibly marked non-production.
- Real runner is not enabled until M0 gates pass.
- Keep integration contracts stable between parallel tracks.
