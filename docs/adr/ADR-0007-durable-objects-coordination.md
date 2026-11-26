# ADR-0007: Durable Objects for Coordination

- Status: Accepted with constrained use
- Decision: Use Durable Objects only where single-object coordination, rate limiting, or live status fan-out is valuable.
- Consequences: PostgreSQL remains authoritative. Do not mirror the entire database into Durable Objects or introduce them merely for fashion.
- Open: prove the exact live-status requirement before adding the first object.
