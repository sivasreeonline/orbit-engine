# M1 Frontend Workspace

## Location and responsibility
The student React SPA lives under apps/web. Its initial role is problem presentation, source editing, language selection, sample fixture inspection and asynchronous execution status display.

## Technology
- Vite + React + TypeScript.
- CodeMirror 6 React wrapper.
- Java and Python syntax extensions.
- Cloudflare Pages target; build output dist.

## Trust boundary
The browser is untrusted. It must never execute submitted code, select hidden test bundles, set authoritative resource limits, or calculate final verdicts. All source input is client-side state only in the initial preview. The mock adapter does not transmit or persist it.

## First problem contract
The initial fixture is Two Sum in console stdin/stdout format. The examples describe the exact input/output format, and language starter templates use Java 25 and Python 3.14.

## Execution state
Until the authenticated API and M0 runner exist:
- Run/Submit return state NOT_CONNECTED.
- No Accepted/Wrong Answer or numeric score may be fabricated.
- Sample fixtures are labelled reference-only, not execution output.
- Submission history is explicitly unavailable.
- The app must display that source code was not executed.

## Future integration
Replace MockExecutionAdapter with a typed API adapter. API requests return 202 and an execution ID. The UI retrieves status asynchronously. Authentication and tenant authorization are handled by the platform; no secret is stored in Vite client variables.
