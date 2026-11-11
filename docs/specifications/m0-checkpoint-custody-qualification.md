# M0 checkpoint custody qualification evidence

## Purpose

This specification defines schema version 1.1 of a machine-readable qualification manifest for a future durable checkpoint-custody adapter. It is intended to turn the storage contract in [the custody and retention specification](m0-checkpoint-custody-and-retention.md) into provider-specific, reproducible evidence requirements.

The catalog contains 12 stable scenarios:

| ID | Qualification area | Required outcome |
|---|---|---|
| CUSTODY-001 | Atomicity | Checkpoint and receipt commit together or neither does |
| CUSTODY-002 | Compare-and-store | Valid successor advances from the exact expected predecessor |
| CUSTODY-003 | Concurrency | At most one writer wins a shared expected-head race |
| CUSTODY-004 | Fork rejection | Same-sequence replay or alternate fork is rejected |
| CUSTODY-005 | Receipt binding | Receipt/checkpoint mismatch is rejected atomically |
| CUSTODY-006 | Lost acknowledgement | Reconciliation recovers the original committed pair |
| CUSTODY-007 | Retention lock | Unauthorized overwrite/deletion before expiry is denied |
| CUSTODY-008 | Retention policy | Ordinary writers cannot shorten the accepted horizon |
| CUSTODY-009 | Backup/restore | Restore of a stale prefix is detected against an independent checkpoint |
| CUSTODY-010 | Availability | Unqualified fallback and fabricated acknowledgements are rejected |
| CUSTODY-011 | Custodian independence | Same-principal or untrusted custodian receipt is rejected |
| CUSTODY-012 | Cross-domain recovery | Independent domain proves the same latest checkpoint and ledger epoch |

The Go catalog validator enforces exact membership and uniqueness. JSON Schema enforces the 12-record shape and common fields, but schema validation alone does not prove catalog completeness.

## Manifest contents

Each manifest records:
- actual provider, product, API/SDK version, account/tenant scope, region, storage class, and retention mode;
- OS, kernel, architecture, endpoint, encryption, versioning, replication, and exact retention configuration;
- each scenario's status, run ID, exact command, start/completion times, and one or more evidence references; scenarios CUSTODY-011 and CUSTODY-012 additionally require separate independent-witness evidence;
- independent review status, reviewer identity, timestamp, and attestation evidence reference;
- for CUSTODY-011 and CUSTODY-012, a detached Ed25519 witness attestation bound to the qualification ID, exact scenario/run metadata, witness identity/key, observation time, decision, and sorted SHA-256 set of the independent witness evidence files.

Evidence references contain confined relative paths, SHA-256 digests, and media types. The structural validator rejects absolute paths, traversal, Windows drive paths, backslashes, NUL bytes, malformed digests, missing evidence, duplicate or unknown scenario IDs, invalid timestamps, and incomplete provider/environment identity. Schema 1.1 requires both independent-witness evidence files and a separate signed witness-attestation artifact for CUSTODY-011 and CUSTODY-012.

## Readiness rule

A manifest is structurally valid only when all 12 scenario IDs appear exactly once and all required metadata/evidence references are present. It is qualification-ready only when every scenario is PASS and the review status is APPROVED.

BLOCKED and SKIPPED are not PASS. A structurally valid manifest with a pending review or any non-PASS scenario is not ready.

## Evidence integrity and trust boundaries

The evidence verifier reads and hashes the referenced artifacts, verifies the final reviewer attestation, and verifies the detached Ed25519 witness attestations for CUSTODY-011 and CUSTODY-012 against externally supplied witness keys. Each witness signature binds the exact scenario/run metadata and the complete sorted digest set of the witness evidence files. It rejects stale/future witness observations, revoked or out-of-validity keys, unknown fields, duplicate JSON keys, non-canonical envelopes, and witness identities that equal the final reviewer identity.

Cryptographic verification still does not establish organizational independence, prove the provider account or region, validate a WORM setting, or establish that a retention lock was enforced. A manifest is not evidence that its claims are true.

A real qualification must independently retrieve provider configuration and audit events, verify each evidence digest and provenance, perform the destructive/fault-injection scenarios in a dedicated non-production account, and have an independent reviewer attest to the actual results. Test fixtures are synthetic and do not represent a provider qualification.

## Explicit gates

No provider or adapter is selected. No durable storage adapter, cloud account access, WORM/object-lock configuration, backup job, replication, production key, host deployment, privileged execution, Phase A/B, or student workload execution is implemented or authorized.
