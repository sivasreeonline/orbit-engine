# Repository Engineering Instructions

These instructions apply to every contributor and AI coding agent in this repository.

## Product and architectural invariants
- Product scope: Intelligent Coding Judge, initial scope B.
- Execution strategy: hybrid. Sky High owns APIs, job orchestration, assessment, evidence, data model and UX; execution is delegated through a stable adapter to isolated Linux runners.
- Judge0 is explicitly excluded. Do not add Judge0 packages, services, URLs or deployment dependencies.
- Do not execute submitted source code inside Cloudflare Workers, Durable Objects, the API process, or the frontend.
- Keep the existing Sky High stack: Vite + React + TypeScript, Cloudflare Pages, Cloudflare Workers, Durable Objects, Neon PostgreSQL, Cloudflare R2, Cloudflare Queues.
- Runner implementation is Go on separate Linux infrastructure.
- Sandbox candidate is gVisor/runsc over an OCI runtime; production approval requires M0 evidence.
- Initial languages: Java 25 and Python 3.14. Pin patch versions and runtime image digests. Do not silently upgrade runtimes.
- M1 initial problem contract is console-style stdin/stdout. Function-style judge adapters are deferred pending pilot confirmation.
- Run and Submit are distinct actions and both must create immutable attempt evidence.
- Verdicts are deterministic and derived from runner/test results. AI analysis is advisory and cannot change verdicts.
- Hidden test inputs and expected outputs never reach the browser or untrusted runner response.

## Working style
- Prefer small, complete vertical slices over broad unfinished scaffolding.
- Reuse maintained, compatible open-source components after checking license, security posture, maintenance, dependency health and platform fit.
- Avoid premature microservices. Keep application domains modular; keep the runner independently deployable.
- Do not create new infrastructure or dependencies without recording why they are needed.
- Do not modify frozen decisions without proposing an ADR change and explaining migration impact.
- Surface uncertainty instead of inventing a value or claiming a test passed when it did not.

## Required engineering practices
- TypeScript strict mode; validate all request payloads at boundaries.
- Go: gofmt, go vet, unit tests, explicit context deadlines and structured logs.
- Use parameterized SQL and migrations. Never rely on manual production schema edits.
- Use stable IDs, UTC timestamps, idempotency keys and correlation/execution IDs.
- Use outbox-based queue publishing; expect at-least-once message delivery.
- Make job claims, result persistence and retries idempotent.
- Keep secrets out of source control, logs, prompts, snapshots and runner payloads.
- Never log full hidden test data or unrestricted student source in production logs.
- Enforce CPU, memory, wall-clock, PID, filesystem and output limits in the sandbox.
- Disable sandbox network access by default; no application credentials in the sandbox.
- Treat compiler output, stdout, stderr, source code and AI output as untrusted.
- Add tests for success, failure, timeout, output limit, cancellation, duplicate delivery and infrastructure failure.
- Keep user-facing verdict separate from infrastructure status.

## Before changing code
1. Inspect relevant code, tests, package scripts and local instructions.
2. State the proposed file changes and acceptance criteria.
3. Preserve existing behavior unless the task explicitly changes it.
4. Avoid unrelated formatting or refactoring.

## Before declaring a task complete
1. Run relevant tests, lint, typecheck, build and Go checks where applicable.
2. Report exact commands and outcomes.
3. Identify skipped tests and unresolved risks.
4. Update docs/ADRs when architecture or contracts change.
5. Never claim deployment, isolation, performance or security has been verified without evidence.

## Git workflow
- Do not commit directly to main.
- Use focused branches: docs/*, feat/*, fix/*, test/*, infra/*.
- Use conventional commit messages.
- Keep pull requests focused and include tests/evidence.
- Never force-push unless the repository owner explicitly instructs it.
