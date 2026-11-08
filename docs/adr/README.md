# Architecture Decision Records

ADRs capture decisions that constrain implementation. A decision marked Proposed or Conditional is not a production approval.

| ADR | Decision | Status |
|---|---|---|
| ADR-0001 | Product scope B | Accepted |
| ADR-0002 | Preserve Sky High platform stack | Accepted |
| ADR-0003 | Modular monolith boundaries | Accepted |
| ADR-0004 | Workers are API/control plane only | Accepted |
| ADR-0005 | Neon is authoritative database | Accepted |
| ADR-0006 | Queues plus transactional outbox | Accepted |
| ADR-0007 | Durable Objects only for coordination/live state | Accepted |
| ADR-0008 | gVisor OCI sandbox candidate | Conditional on M0 |
| ADR-0009 | Go execution runner | Accepted |
| ADR-0010 | Java 25 and Python 3.14 runtime families | Accepted; patch pins required |
| ADR-0011 | R2 for larger artifacts | Accepted |
| ADR-0012 | Immutable attempt evidence | Accepted |
| ADR-0013 | Deterministic verdicts; advisory analysis | Accepted |
| ADR-0014 | Versioned asynchronous REST API | Accepted |
| ADR-0015 | Console-mode problem contract for M1 | Accepted for initial slice |
| ADR-0017 | Layered automated security scanning | Accepted |

Review a decision before introducing a dependency or implementation that contradicts it.
