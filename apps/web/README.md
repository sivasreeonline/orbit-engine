# Sky High Coding Judge — Web Workspace

This is the first M1 student-workspace slice, built with Vite, React and TypeScript.

## Local development

Requires Node.js >= 22.12.0 and npm.

Run the API and web workspace in separate terminals.

**Terminal 1 — API Worker**

```powershell
cd apps/api
npm install
npm run dev
```

Wrangler listens on `http://127.0.0.1:8787` by default.

**Terminal 2 — web workspace**

```powershell
cd apps/web
npm install
npm run dev
```

Open the local URL printed by Vite. Its `/api` requests are proxied to the Wrangler Worker.

## Available commands

- `npm run dev` — local development server.
- `npm run typecheck` — strict TypeScript check.
- `npm test` — unit tests.
- `npm run build` — typecheck, tests and production bundle.
- `npm run preview` — preview the production bundle locally.

## Current implementation boundary

The current workspace includes:
- Two Sum console-mode problem statement and sample fixtures.
- Java 25 and Python 3.14 source templates.
- CodeMirror 6 editor with Java/Python syntax support.
- Language switching and starter-code reset.
- Run and Submit controls connected to a deliberately non-executing mock adapter.
- A result panel that clearly reports that no code was executed.
- An authenticated coding-journey history view backed by the API timeline read model.
- Explicit, owner-scoped historical source retrieval in a read-only viewer; opening an old snapshot never replaces the active editor buffer.
- Selection and comparison of two historical attempts using the bounded immutable source-diff API.
- Timeline and source reads use credentialed GET requests only; the mock Run/Submit adapter still does not transmit source code, execute code, or create attempts.

**No real execution exists in this slice.** The mock adapter does not execute source code, call a server, calculate a verdict, or record a score. Do not replace this boundary with browser-side execution or an insecure shell endpoint.

## Integration sequence

1. Implement authenticated API contracts and persistence.
2. Complete M0 isolated Linux runner and security acceptance gates.
3. Connect the frontend to the asynchronous Run/Submit API.
4. Remove the mock adapter only after integration and security tests pass.

## Coding journey API configuration

The History tab reads:
- `GET /api/v1/problems/{problemSlug}/timeline`
- `GET /api/v1/attempts/{attemptId}/source` only after the student explicitly opens a saved snapshot.
- `GET /api/v1/attempts/{targetAttemptId}/diff?baseAttemptId={baseAttemptId}` only after the student explicitly selects two attempts and requests comparison.

All requests use `credentials: "include"` and `Cache-Control: no-store`. The API derives tenant and student scope from the authenticated session; the browser does not send a student ID or tenant ID. The source view is read-only and does not modify the current editor.

For local development, the Vite server proxies `/api` to Wrangler at `http://127.0.0.1:8787`. Start the API Worker separately before using History. Copy `.env.example` to `.env.local` only when you need to set `VITE_API_BASE_URL` to a deployed API origin. A cross-origin deployment must configure credentialed CORS and the identity provider correctly.

The current API authenticator is not yet connected to a real identity provider, and the local Wrangler configuration still has placeholder database bindings. Until those are configured, the history view will show the API's authentication/configuration response rather than fabricated student records. The timeline UI and read-only source/diff flows are implemented, but end-to-end student-session verification remains blocked on identity and database configuration.

## Deployment

The intended frontend host is Cloudflare Pages. The app builds to `dist` using `npm run build`. Do not deploy to production until the API origin, authentication, security headers, environment bindings and Cloudflare project configuration have been reviewed.
