# Sky High Coding Judge

Secure, evidence-driven coding assessment for the Sky High platform.

## Product direction
Sky High Coding Judge is an intelligent coding assessment service. Its initial release provides a reliable Java/Python execution judge, reproducible verdicts, test-case evaluation, and immutable coding-attempt history. Code quality and advisory intelligence build on top of authoritative execution results.

## Non-goals for M0/M1
- Do not build a general-purpose microservice fleet.
- Do not execute untrusted code in Cloudflare Workers.
- Do not integrate Judge0.
- Do not expose hidden test inputs or expected outputs to clients.
- Do not let AI determine authoritative verdicts.
- Do not add LeetCode-style function execution until the console-mode contract is proven and the pilot requirements are confirmed.

## Selected platform baseline
- Frontend: Vite + React + TypeScript; Cloudflare Pages.
- API/control plane: Cloudflare Workers.
- Coordination: Durable Objects where coordination or live state is needed.
- Database: Neon PostgreSQL; authoritative transactional store.
- Object storage: Cloudflare R2 for larger artifacts.
- Queue: Cloudflare Queues with transactional outbox and idempotent consumers.
- Runner: Go service on separately hosted Linux infrastructure.
- Sandbox candidate: OCI containers with gVisor/runsc, subject to M0 security validation.
- Initial runtimes: Java 25 and Python 3.14, pinned to approved patch versions and immutable image digests.

## Development principles
1. Ship vertical slices quickly, but do not weaken sandbox security.
2. Keep a modular monolith for application logic until measured scale justifies extraction.
3. Preserve the selected Sky High platform stack.
4. Treat execution output as untrusted data.
5. Preserve every Run and Submit attempt as immutable evidence.
6. Make queue processing idempotent and observable.
7. Keep authoritative evaluation deterministic; AI feedback is advisory.
8. Record unresolved decisions and use explicit decision gates.

## Start here
- Repository rules: AGENTS.md
- Claude Code guidance: CLAUDE.md
- Architecture baseline: architecture-baseline.yaml
- ADRs: docs/adr/
- M0 and M1 specifications: docs/specifications/
- Open decisions: docs/decisions/decision-register.md
- Implementation backlog: docs/planning/m0-m1-engineering-backlog.md

## Current milestones
- M0: Prove isolated, resource-limited Java/Python execution on Linux.
- M1: Deliver the first functional coding judge using a mock adapter in parallel with M0, then integrate the approved runner.


## First M1 web workspace

The initial student workspace lives in `apps/web`.

```powershell
cd apps/web
npm install
npm run dev
```

This first slice is a **UI preview only**. Its mock execution adapter does not execute source code, does not produce verdicts, does not persist attempts and does not call a remote service. Real execution remains blocked until the M0 isolated Linux runner and authenticated API integration pass their release gates.

See `apps/web/README.md` for details.
