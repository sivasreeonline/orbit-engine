# ADR-0011: R2 for Larger Artifacts

- Status: Accepted
- Decision: Use Cloudflare R2 for larger source artifacts, bounded logs and diagnostic artifacts when object storage is justified.
- Consequences: PostgreSQL stores metadata, object keys, hashes and retention state. Small records may remain in PostgreSQL to avoid needless object churn.
- Security: private buckets, scoped access, short-lived authorization, retention policies and no public hidden-test objects.
