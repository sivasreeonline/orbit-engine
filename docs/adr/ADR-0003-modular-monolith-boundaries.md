# ADR-0003: Modular Monolith Boundaries

- Status: Accepted
- Decision: Keep domain logic in a modular application backend; independently deploy the execution runner.
- Domains: identity/authorization integration, problem catalog, submissions, attempts, jobs, assessment, code analysis and reporting.
- Consequences: Clear module APIs and ownership; avoid splitting into network services before scale or team boundaries justify it.
