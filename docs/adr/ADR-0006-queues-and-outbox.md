# ADR-0006: Queues and Transactional Outbox

- Status: Accepted
- Decision: Use Cloudflare Queues for asynchronous execution dispatch and a PostgreSQL transactional outbox to bridge committed jobs to queue publication.
- Rationale: Queue delivery is at-least-once, so duplicate messages are expected.
- Consequences: Every job has a stable execution ID; consumers claim idempotently; result persistence is idempotent; failures use bounded retries and dead-letter handling.
