# ADR-0002: Preserve the Sky High Platform Stack

- Status: Accepted
- Decision: Use Vite + React + TypeScript, Cloudflare Pages, Workers, Durable Objects, Neon PostgreSQL, R2 and Cloudflare Queues. Use Go for the independently deployed runner.
- Context: Sky High already selected this platform stack. A second application stack increases operational complexity.
- Consequences: Platform-facing APIs and UI use the existing stack. Only the untrusted execution boundary is separately hosted on Linux.
- Revisit when: a measured platform limitation cannot be solved within this stack.
