# ADR-0016: Frontend Workspace and Code Editor

- Status: Accepted for M1 initial slice
- Decision: Build the student workspace as a Vite + React + TypeScript SPA under apps/web. Use CodeMirror 6 through the React wrapper for in-browser editing, with Java and Python language extensions.
- Context: M1 needs a usable editor quickly while keeping the established Cloudflare Pages frontend direction.
- Consequences: The web app is independently buildable and deployable. The editor is only a source-editing surface; it is not an execution sandbox.
- Preview boundary: The first slice uses a mock adapter that returns NOT_CONNECTED. It must not execute, transmit, persist, score or judge source code.
- Runtime baseline: React 19.3.1, Vite 8.3.6, TypeScript 7.0.2, Java 25 and Python 3.14 are pinned in the initial package manifest. Dependency lockfile must be generated locally and committed before production CI promotion.
- Security: Avoid unsafe HTML rendering, remote code execution, secrets in Vite environment variables, and browser-side compilation/execution. Review all dependencies and lockfile updates.
- Revisit: Evaluate Monaco or another editor only if measured accessibility, performance, language tooling or feature needs justify replacement.
