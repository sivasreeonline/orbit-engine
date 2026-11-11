# FENCE-001 external witness qualification protocol

**Status:** Required qualification contract; provider-neutral and not evidence of a qualified provider.  
**Applies to:** Any external witness implementation proposed for FENCE-001 production use.  
**Current disposition:** BLOCKED / NOT QUALIFIED. No provider, witness, monitor, key custodian, account, region or production key has been selected.

## 1. Purpose and security boundary

The cryptographic receipt profile proves that a trusted key signed a specific receipt payload. It does not prove that the provider durably stored the checkpoint, returned a linearizable latest value, retained one append-only history, or showed the same history to every reader.

This protocol defines the evidence required to qualify those external properties. It does not select a provider or imply that a generic database, object store, CAS endpoint, signed response, or successful CI fixture satisfies them.

The qualification record is machine-readable at `docs/templates/m0-fence-witness-qualification-record.json`; its structural schema is `docs/schemas/m0-fence-witness-qualification-record.schema.json`. The validator checks the exact mandatory test inventory and evidence separation rules. A passing local validator is repository hygiene, not provider qualification.

## 2. Required provider contract

A candidate adapter must expose semantics equivalent to all of the following. The provider's marketing terms are not evidence; the candidate must document and demonstrate the actual API and failure semantics.

### 2.1 Atomic append / compare-and-append

An append request must atomically bind the expected predecessor (or expected generation) to the new checkpoint. For two concurrent appenders using the same predecessor, at most one distinct successor may commit. The loser must receive an unambiguous conflict or recover the exact winning operation; it must not overwrite, fork, or silently rebase.

The operation identity and request digest must be idempotent. Repeating the exact operation after a lost acknowledgement must return the same durable checkpoint and receipt. Reusing the operation identity with changed bytes, phase, scope or predecessor must hard-fail.

Evidence must include provider API semantics, concurrent independent-client tests, raw request/response traces, and durable post-failure readback. An in-memory mock or single-process mutex is insufficient.

### 2.2 Strongly consistent latest read

The read used to authorize a transition must be linearizable with successful appends, or the provider must expose an equally strong, formally documented consistency token/proof that the adapter verifies. A read from a lagging replica, cache, stale regional endpoint or operation-index alone is not a latest-state proof.

The evidence must identify read routing, replica behavior, consistency mode, failover behavior, token/proof semantics, and the exact conditions under which a read can return stale state. If the provider cannot establish the latest committed high-water state, the authority must quarantine and refuse the transition.

### 2.3 Acknowledgement means durable commit

A successful append acknowledgement must have a documented durability meaning. The candidate must survive process restart, node loss, replica failover and the provider's documented durability boundary. Tests must distinguish a committed append whose acknowledgement is lost from an append that never committed.

Readback must be performed through an independently established path, not merely by echoing the append response. Durability claims must state the actual failure domains covered; no claim of power-loss, regional or multi-region durability may be inferred from a container restart test.

## 3. Independent monitor and anti-equivocation contract

At least two independently operated observation paths are required for production qualification. They must not share the authority's credentials, administrative identity, deployment control plane, or sole failure domain. Independence must be demonstrated from account ownership, IAM, network, region/provider, deployment and operational evidence—not asserted by naming two processes.

Each monitor must persist its own high-water observation outside the authority database restore domain. It must periodically retrieve signed witness heads, validate identity and signature, and compare each new head with its previously accepted head.

A signed head must bind, at minimum:

- profile and protocol version;
- trust-domain and witness identity;
- authority and host scope (or an explicitly defined aggregate scope);
- monotonically increasing tree size / generation;
- root or checkpoint digest;
- predecessor relation or the data needed to obtain a consistency proof;
- timestamp with defined trusted-time semantics;
- signing key ID and signature.

A signature authenticates the head bytes; it does not prove append-only history. The provider must supply verifiable inclusion and consistency proofs, or an equivalently strong append-only proof system with independently reviewed algorithms and vectors. If RFC 9162 Merkle transparency is selected, the adapter must verify the signed tree head, inclusion proof and consistency proof exactly as specified by that protocol. The selected proof format and cryptographic suite must be versioned; do not treat an opaque non-empty token as a proof.

Monitors must compare signed heads through an independent gossip/exchange channel. If two validly signed heads exist for the same witness scope and incompatible history, or a monitor observes a rollback, missing predecessor, invalid proof, or unexplained head divergence, the authority is quarantined. Never select the locally preferred fork. A detector that receives two conflicting observations is useful, but it does not prove that all monitors will receive them.

Monitor polling cadence, maximum detection delay, alert delivery, on-call ownership, evidence retention and quarantine response must be explicit and tested. An unobserved fork is not disproved by the absence of an alert.

## 4. Restore, rollback and recovery

The authority database and the witness are separate histories. Restoring the authority database to an older backup must not roll back the witness or the verifier's protected high-water mark. The highest accepted witness generation/digest and trust-bundle/revocation generations must be persisted outside the authority database's ordinary backup/restore domain.

After restore:
1. Keep admission and execution disabled.
2. Load the independently protected witness and trust high-water marks.
3. Read the current witness head using the qualified strong-read path.
4. Verify signatures, proof chain, identity, generation, predecessor and revocation freshness.
5. Reconcile local intent/checkpoint rows against the witness history without deleting or rewriting either history.
6. If the witness is ahead, recover only through an exact, verified reconciliation procedure; do not issue a new checkpoint until the authority state is reconciled.
7. If the local authority claims a state ahead of the witness, the witness rolls back, proof is missing, or histories conflict, quarantine and require independent review.

A successful backup restore, database migration, or process restart alone is not witness recovery evidence. Tests must include stale snapshots, restore to an earlier authority generation, witness-ahead recovery, missing witness, unavailable witness, stale revocation data and contradictory monitor observations.

## 5. Mandatory qualification tests

The qualification record must contain exactly these IDs. A test may be marked PASS only when its evidence is immutable, independently acquired, scoped to the exact provider/adapter version and verified by a person distinct from the evidence collector.

| ID | Required proof |
|---|---|
| WIT-001 | Atomic compare-and-append; concurrent same-predecessor writers produce at most one successor |
| WIT-002 | Linearizable latest read, including replica routing and failover |
| WIT-003 | Acknowledgement durability and independent readback after restart/failure |
| WIT-004 | Lost-acknowledgement recovery and exact idempotent replay; changed digest conflicts |
| WIT-005 | Signed-head identity, scope, key lifecycle and trusted-time validation |
| WIT-006 | Inclusion and append-only consistency proof verification |
| WIT-007 | Two independently operated monitors and cross-monitor head gossip/equivocation detection |
| WIT-008 | Rollback resistance across authority database restore and protected high-water recovery |
| WIT-009 | Trust-bundle and revocation freshness, rotation, revocation and unavailable-root behavior |
| WIT-010 | Stale replica/cache/read-token behavior fails closed |
| WIT-011 | Network partition, provider outage, timeout and ambiguous append outcomes fail closed |
| WIT-012 | Retention, backup, deletion, replication and declared durability/failure-domain guarantees |
| WIT-013 | Witness-ahead and authority-ahead reconciliation, including contradictory history quarantine |
| WIT-014 | Evidence integrity, independent acquisition, exact version pinning and reviewer separation |

## 6. Evidence rules

Every PASS record must include one or more evidence objects with:
- stable immutable object reference and object version;
- SHA-256 digest and byte count;
- acquisition method and timestamp;
- collector identity;
- independent verifier identity, distinct from the collector;
- exact provider, region/account and adapter build/version scope;
- redaction declaration and, where applicable, reproducible test procedure.

Evidence must be acquired from the actual candidate provider or independently controlled monitor environment. Design documents, screenshots of marketing claims, local unit tests, synthetic fixtures, in-memory test doubles, CI status, or a provider's self-reported timestamp cannot by themselves pass provider behavior controls.

The evidence set must include raw concurrency outcomes, append/readback traces, proof bytes, monitor observations, restore/reconciliation results, provider configuration and the relevant contractual/API documentation. Secrets and private keys must be redacted; redaction must not remove fields needed to verify integrity or semantics.

## 7. Fail-closed decision and approvals

The candidate status may progress from NOT_STARTED to EVIDENCE_PENDING and then READY_FOR_INDEPENDENT_REVIEW only when all mandatory tests are PASS and all required evidence is present. Any FAIL, missing test, missing evidence, identity collision, stale high-water, invalid proof or unresolved divergence keeps the candidate BLOCKED.

Even READY_FOR_INDEPENDENT_REVIEW is not production approval. Production approval requires a separate signed decision by an independent security reviewer and explicit authorization for the selected provider, adapter build, trust roots, key custody, monitor topology and operational response. The qualification record's `productionApproval` remains false in this repository template; no validator or CI job can grant it.

Until that separate decision exists, FENCE-001 must not enable host admission, epoch issuance based on an unqualified witness, privileged supervisor startup, guest execution, student execution or production execution.
