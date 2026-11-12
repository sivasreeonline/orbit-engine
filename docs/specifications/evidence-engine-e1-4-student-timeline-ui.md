# Evidence Engine E1.4 — Student coding journey interface

## Purpose

Expose the authenticated E1.3 attempt timeline in the student workspace, with explicit read-only access to immutable historical source and controlled comparison of two attempts.

## Student workflow

1. Open the editor's Output panel and select History.
2. The UI requests the problem-scoped attempt timeline using the current authenticated browser session.
3. Each Run and Submit appears as its own timeline entry, newest first.
4. The student may expand safe lifecycle event metadata for an attempt.
5. The student may explicitly open that attempt's original source snapshot in a read-only viewer.
6. The student may select two attempts and request a source diff. The older attempt is the base and the newer attempt is the target; equal timestamps use attempt ID as a deterministic tie-breaker.

## API calls

- Timeline: `GET /api/v1/problems/{problemSlug}/timeline?limit=50`
- Source: `GET /api/v1/attempts/{attemptId}/source` (only after explicit user action)
- Diff: `GET /api/v1/attempts/{targetAttemptId}/diff?baseAttemptId={baseAttemptId}` (only after explicit selection and comparison action)

All calls are GET requests with `credentials: include` and `cache: no-store`. The browser sends no student or tenant identifier; the API derives those from the authenticated principal.

## UI safety and correctness

- Opening a historical snapshot never writes into or replaces the active CodeMirror editor buffer.
- Source code is not fetched until the student explicitly selects Open saved code.
- The diff is not requested until two attempts are selected and Compare attempts is activated.
- The backend remains authoritative for ownership, attempt compatibility, source integrity and diff size limits.
- Only the backend allowlisted event metadata is displayed; hidden tests, expected outputs and raw compiler/runner diagnostics are not requested or rendered.
- Run and Submit are visibly distinct and retain their original semantics.
- Timeline, snapshot and diff requests are never cached by the browser.
- The UI handles unavailable API, authentication and empty-history states without fabricating attempts.

## Local development

Vite proxies `/api` to the Wrangler Worker at `http://127.0.0.1:8787`. Start `apps/api` and `apps/web` in separate terminals. The Worker currently uses `UnconfiguredAuthenticator` and placeholder local database bindings; therefore end-to-end authenticated history cannot be demonstrated until identity and database configuration are supplied.

For deployed Pages, set `VITE_API_BASE_URL` to the API origin. Cross-origin credentialed access requires an explicit allowed-origin and identity-cookie CORS design; this UI change does not loosen API CORS policy.

## Implemented

- Attempt timeline component with refresh, loading, empty and API-error states.
- Run/Submit cards with execution summary and safe event expansion.
- Explicit read-only source snapshot viewer.
- Two-attempt comparison with chronological base/target ordering and line-level insert/delete/equal display.
- Vite local API proxy and `VITE_API_BASE_URL` example.
- Local setup and security-boundary documentation.

## Exclusions

- Does not connect Run/Submit controls to the API.
- Does not enable actual code execution.
- Does not configure an identity provider, session cookie, cross-origin credentialed CORS or production API origin.
- Does not expose historical source in the active editable buffer.
- Does not implement timeline pagination beyond the existing bounded limit of 50.
- Does not add autosave or keystroke capture.

## Validation

The implementation is committed to the stacked draft PR. Web/API CI must pass on the latest head before this slice is considered validated. End-to-end authenticated UI testing remains blocked until identity and database bindings are configured.
