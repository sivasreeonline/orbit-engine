# ADR-0005: Neon Is the Authoritative Database

- Status: Accepted
- Decision: Neon PostgreSQL is the source of truth for problems, submissions, attempts, jobs, evaluation reports and metadata.
- Consequences: Use migrations, foreign keys, transaction boundaries, indexes and parameterized queries. Database state is authoritative over queue messages and live UI state.
- Open: select connection method and pooling strategy for Workers and runner services after connectivity testing.
