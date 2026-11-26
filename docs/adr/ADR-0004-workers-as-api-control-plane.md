# ADR-0004: Workers Are the API and Control Plane

- Status: Accepted
- Decision: Cloudflare Workers handle authentication integration, validation, orchestration, status reads and signed artifact operations. They never compile or execute arbitrary student code.
- Rationale: Workers are resource constrained and are not the isolation boundary for hostile programs.
- Consequences: Code execution is dispatched to separately hosted Linux runners using an authenticated asynchronous protocol.
