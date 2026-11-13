# Security Policy

Sky High Coding Judge treats student-submitted source code as hostile input.

## Reporting
Please do not publish details of a suspected vulnerability in a public issue. Use GitHub private vulnerability reporting for this repository if it is enabled. Otherwise, contact the repository maintainer privately through GitHub.

## Security invariants
- Never execute student code in the browser, Cloudflare Workers, Durable Objects or the application API process.
- Never expose hidden test input or expected output to clients.
- Never place server secrets in Vite `VITE_*` variables or static frontend bundles.
- Never treat AI output as an authoritative verdict.
- Do not connect production execution until M0 security gates pass.
- Treat source code, compiler output, stdout, stderr and uploaded files as untrusted.
- Keep execution infrastructure private and isolated.

## Dependency and change review
Review dependency ownership, licensing, maintenance, advisories and lockfile diffs before adoption or upgrades. Run automated checks and relevant tests on every pull request.
