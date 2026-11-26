# Sky High Coding Judge — Web Workspace

This is the first M1 student-workspace slice, built with Vite, React and TypeScript.

## Local development

Requires Node.js >= 22.12.0 and npm.

```powershell
npm install
npm run dev
```

Open the local URL printed by Vite.

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
- Local component state only; no source, attempt or student data is persisted or transmitted.

**No real execution exists in this slice.** The mock adapter does not execute source code, call a server, calculate a verdict, or record a score. Do not replace this boundary with browser-side execution or an insecure shell endpoint.

## Integration sequence

1. Implement authenticated API contracts and persistence.
2. Complete M0 isolated Linux runner and security acceptance gates.
3. Connect the frontend to the asynchronous Run/Submit API.
4. Remove the mock adapter only after integration and security tests pass.

## Deployment

The intended frontend host is Cloudflare Pages. The app builds to `dist` using `npm run build`. Do not deploy to production until the API origin, authentication, security headers, environment bindings and Cloudflare project configuration have been reviewed.
