# FENCE-001 durable authority storage and recovery proposal

**Status:** Provider-neutral protocol proposal; not an implementation, approved migration, or qualification result.  
**Scope:** Durable host-epoch authority records, idempotent issuance, external anti-rollback checkpointing, crash recovery, and exact response delivery.  
**Safety:** No authority database, external witness, provider API, cryptographic library, KMS/HSM, or host agent is selected. This proposal does not authorize privileged implementation, Phase A, Phase B, student execution, or production execution.

## 1. Authority boundaries

The epoch authority is the sole logical issuer for one stable enrolled-host identity. Its durable transactional store owns the operational record and append-only issuance history. A separately administered external witness owns the monotonic anti-rollback checkpoint. The provider remains authoritative for provider-instance identity and effective predecessor fencing.

| Fact | Authoritative source | Authority-store responsibility |
|---|---|---|
| Stable host enrollment | Independently governed enrollment authority | Serialize one record per stable host identity |
| Predecessor inventory and effective fence | Provider plus independently acquired evidence | Verify exact evidence before issuance |
| Epoch allocation and operation/nonce identity | External epoch authority | Commit transactionally; never reuse identities |
| Anti-rollback high-water mark | External witness outside the authority-store restore domain | Advance and read back a monotonic checkpoint |
| Guest acceptance | Exact target instance and durable readback | Record independently verified receipt |
| Provider power-off/isolation | Provider control plane and independent observation | Track operation IDs and evidence; do not equate DB commit with fencing |

Neon is an application-ledger candidate, not the external epoch authority or provider fencing authority. A database row, object version, signed response, or passing synthetic validator cannot establish provider fencing or host isolation.

## 2. Durable authority record

Maintain one serializable aggregate per stable enrolled-host identity containing:

- authority, environment and stable host identities;
- current accepted epoch, provider-instance identity and monotonically increasing record version;
- at most one successor issuance in a nonterminal state;
- append-only issuance, acceptance and revocation event sequence and digest chain;
- nonce-digest index mapping each consumed nonce to exact request digest, operation ID, response ID and response-byte digest;
- operation-ID index mapping each operation ID to exact nonce digest, request digest, response ID and response-byte digest;
- immutable exact response bytes and canonicalization/protocol version;
- predecessor-set digest and immutable fence-evidence references;
- witness generation, previous checkpoint digest, checkpoint artifact digest and anchor status;
- recovery/quarantine state and durable audit references.

Require uniqueness for (host identity, nonce digest), (host identity, operation ID), (host identity, epoch), and (authority identity, response ID). Nonce and operation indexes are permanent anti-replay tombstones for the host identity unless an independently reviewed bounded replay horizon proves safe compaction. Compaction must preserve non-reusable identities and historical response resolution.

Canonicalize a request once before transaction entry. Its digest covers protocol version, authority/environment, stable host identity, expected record version, operation ID, nonce digest, target provider instance, predecessor-set digest, immutable fence-evidence references and requested transition. Retries reuse the exact canonical bytes and digest.

## 3. Issuance protocol: durable commit, anchor, publish

Issuance is a recoverable multi-resource protocol, not a distributed ACID transaction. Provider fencing, authority database commit and external witness update are separate operations.

### Phase A — preflight and idempotency resolution

1. Authenticate and authorize the caller.
2. Canonicalize the complete request and compute its digest.
3. Resolve both nonce and operation indexes before allocating an epoch.
4. If both indexes identify the same prior operation and digest, return exact stored response bytes only when the issuance is externally anchored and publishable. Otherwise continue reconciliation; never allocate another epoch.
5. If either identity exists with a different counterpart or digest, reject as a hard conflict and append an audit event.
6. Verify current authority state against the latest external checkpoint. Missing, stale, unavailable or mismatched witness state fails closed.

### Phase B — predecessor fencing and evidence pinning

1. Require complete predecessor/clone/snapshot enumeration.
2. Require independently verified per-predecessor evidence that compute, storage-write and privileged-control paths are fenced.
3. Pin the exact immutable aggregate bundle reference, object version and digest; read back the same version and verify exact bytes.
4. Reconcile provider operation IDs after ambiguous responses. A timeout or control-plane acknowledgement is not proof of effective fencing.
5. No epoch is admissible while predecessor evidence is incomplete or ambiguous.

Provider side effects remain outside the database transaction. Persist provider operation identity and evidence provenance so recovery can query provider truth rather than blindly repeat a non-idempotent side effect.

### Phase C — serializable durable issuance commit

Within one database transaction, serialize on stable enrolled-host identity and:

1. Lock the host authority aggregate and compare the exact expected record version.
2. Re-check that no unaccepted successor exists and predecessor-set maximum epoch equals the current authority epoch.
3. Enforce unique nonce, operation ID, response ID and successor epoch constraints.
4. Allocate exactly one strictly greater epoch and construct canonical response bytes.
5. Persist exact response bytes, response digest, all request bindings, and immutable nonce/operation index entries.
6. Append ISSUANCE_COMMITTED_UNANCHORED and increment aggregate version.
7. Persist a deterministic checkpoint intent containing the next witness generation, previous checkpoint digest, new authority-state digest, epoch high-water mark, record version, operation ID and response digest.
8. Commit all records atomically.

The database commit is durable local issuance, but is not permission to publish an admissible response. The single pending successor blocks every different successor until this issuance is externally anchored and accepted or explicitly quarantined/revoked through a separately reviewed transition.

Unique constraints are final concurrency guards; application prechecks are insufficient. Serialization/deadlock retries reuse the exact request identity and digest.

### Phase D — external checkpoint advance

1. Read the current checkpoint from the independently administered witness.
2. Verify witness identity, authority/environment, generation, previous digest and monotonic high-water marks.
3. Submit the deterministic checkpoint intent with an idempotent operation ID and compare-and-swap against the exact prior generation/digest.
4. The witness rejects generation gaps, forks, replay, identity changes, epoch/sequence regression and a second successor from the same predecessor checkpoint.
5. Read back the exact checkpoint artifact and independently verify authentication, generation, predecessor digest, checkpoint digest, state digest and high-water marks.
6. In a second authority-store transaction, mark the issuance ANCHORED only if the exact checkpoint receipt matches the committed intent and the aggregate has not changed.
7. Only then may the exact response bytes be delivered as an anchored issuance result.

The checkpoint binds the authority-state digest and high-water marks; it cannot replace the durable authority log or exact response bytes. The witness must be outside the combined database, object-store, guest and provider-account restore/failure domain. Its quorum, anti-equivocation, key custody, availability and recovery behavior require independent review.

### Phase E — exact response delivery and acceptance

1. Deliver only exact stored response bytes associated with the anchored operation.
2. Resolve lost delivery acknowledgement by operation ID and nonce digest; retries return byte-identical bytes and never allocate another epoch.
3. The exact target instance durably persists the response and epoch, reads it back, and emits an acceptance receipt bound to response ID/digest, target instance, epoch and durable-record digest.
4. Verify the receipt independently and append ACCEPTED under compare-and-swap.
5. Identical acceptance is idempotent. A different response, instance, epoch or durable-record digest conflicts.
6. Historical retry returns historical bytes without changing current authority state.

ISSUED/ANCHORED is not ACCEPTED. Delivery or client acknowledgement does not prove durable guest acceptance. Admission remains denied until the separate host-readiness contract verifies exact-instance durable acceptance and all other controls.

## 3.1 Acceptance is a second lifecycle checkpoint

Acceptance must not be treated as a flag folded into the original issuance checkpoint. It is a new authority transition with its own immutable event and checkpoint intent:

1. Verify the exact retained response bytes, response digest, target instance, issued epoch, pending operation and the already-anchored issuance checkpoint.
2. In one durable authority transaction, append the immutable acceptance event and update the host aggregate to reflect that acceptance.
3. Compute the post-acceptance authority-state digest and append a new acceptance checkpoint intent. Its generation must follow the latest issuance or acceptance checkpoint, and its predecessor link must identify the preceding checkpoint.
4. Commit the acceptance event and intent atomically. Until the new checkpoint is acknowledged by the independent witness, the transition is **checkpoint-pending**; a local acceptance row alone is not sufficient to declare the lifecycle transition fully anchored.
5. On retry after a lost acknowledgement, resolve the same operation and exact acceptance identity. Return the existing acceptance only after the exact acceptance checkpoint receipt is verified; otherwise continue reconciliation of the same intent. Never append a second acceptance or allocate another generation for the retry.
6. Do not permit a later successor issuance while the latest acceptance checkpoint remains unacknowledged. Revocation remains a separately serialized terminal transition and must preserve the accepted history.

The disposable PostgreSQL fixture now has a separate acceptance-checkpoint intent/receipt pair and an acceptance wrapper that models this ordering. Its receipt table remains in the same disposable database and is only a test double. The fixture does not prove independent witness durability, cryptographic guest readback, or production admission. A future implementation must place acceptance and issuance checkpoints in one unified append-only chain with an independently administered witness and independently verified predecessor digest.

## 3.2 Checkpoint records form one cryptographically linked sequence

Issuance and acceptance checkpoints share one per-host generation sequence. Each immutable checkpoint record binds:

- Host authority identity.
- Monotonic generation and lifecycle phase.
- Operation identity.
- Exact predecessor checkpoint digest.
- Canonical post-transition authority-state digest.
- Exact response digest.

The checkpoint-record digest is computed over a canonical structured envelope, not delimiter-concatenated caller-controlled strings. The next transition references the preceding checkpoint-record digest, not merely the preceding state digest. Publication, acceptance and retry reconciliation must recompute the record digest and compare the exact receipt against the full record identity.

The disposable PostgreSQL prototype now models this digest envelope and verifies the issuance → acceptance → next-issuance predecessor links, including rejection of a deliberately forked checkpoint digest. Its receipt remains local test data. This is not proof of witness anti-equivocation, independently retained high-water state, signatures, or provider fencing; those remain separate gates.

## 3.3 Privilege-separated authority entrypoints

The authority database role model must separate application transitions from operator control and must not expose direct table mutation to either role:

- The application role may invoke only the guarded issuance, publication and checkpoint-aware acceptance entrypoints.
- The operator role may invoke the separately authorized revocation entrypoint; it cannot issue epochs or accept guest state.
- Neither role receives direct SELECT/INSERT/UPDATE/DELETE privileges on authority aggregates, immutable issuance records, replay indexes, acceptance events, checkpoint intents or witness receipts.
- Low-level acceptance mutation and internal digest/concurrency helpers are not PUBLIC-executable.
- Privileged entrypoints must execute with a tightly controlled owner and a fixed safe search path. Any implementation must additionally prove the owner is not an application identity, the search path cannot be shadowed, and all dynamic SQL is safe.

The disposable PostgreSQL prototype now creates separate NOLOGIN application/operator roles, revokes PUBLIC function execution, grants only the intended entrypoints, checks that direct table privileges are absent, and exercises issuance/publication/acceptance as the application role plus revocation as the operator role. This is a prototype privilege test, not a production role migration or independent security review.

## 4. Crash-point and recovery matrix

| Crash or uncertainty point | Durable facts that may exist | Required recovery |
|---|---|---|
| Before predecessor enumeration | No issuance | Restart discovery; no admission |
| During enumeration/fencing | Partial provider operations; incomplete evidence | Reconcile provider state; quarantine ambiguity |
| Provider fence succeeded, caller timed out | Provider may be fenced; no authority commit | Resolve same provider operation ID and independently verify; do not blindly repeat |
| Before authority commit | No committed epoch or replay-index entry | Roll back; retry exact operation only after proving no commit |
| Authority commit succeeds, DB acknowledgement lost | Issuance, response bytes, indexes and checkpoint intent committed | Resolve by operation ID/nonce/digest; continue checkpoint reconciliation |
| DB commit outcome unknown | Commit may or may not exist | Query by both idempotency identities; quarantine if unavailable or contradictory |
| After DB commit, before witness update | Committed but unanchored issuance | Retry exact witness CAS; do not publish or issue successor |
| Witness update succeeds, acknowledgement lost | Witness may contain exact checkpoint | Query by checkpoint operation ID/digest; exact match is idempotent |
| Witness advances, local anchor-status update lost | External anchor ahead of local projection | Verify exact intent and durable log; repair projection or quarantine |
| Witness advances but authority record/log unavailable | Witness binds a digest whose full record is missing | Quarantine; restore exact record from separately protected log or require reviewed re-enrollment; never lower witness |
| Authority store restored behind witness | Store generation/digest/epoch stale | Read-only quarantine; restore forward from verified log |
| Authority store appears ahead of witness | Unanchored or forged local state possible | Deny publish/admission; reconcile exact intent |
| Response delivered, guest persistence unknown | Anchored issuance; acceptance absent/uncertain | Redeliver exact bytes to exact target; verify durable readback |
| Guest write interrupted | Partial or absent acceptance | RECOVERY_ONLY; accept only complete matching readback |
| Guest commit succeeds, acknowledgement lost | Durable acceptance may exist | Query by response ID/digest; identical receipt is idempotent |
| Revocation races acceptance | Both transitions contend | Serialize; revoke-first denies acceptance; acceptance-first is followed by terminal revocation and separately verified disable |
| Newer epoch accepted before old retry | Historical response remains indexed | Return historical bytes only; never roll back current epoch |
| Witness unavailable during startup/recovery | Current high-water mark unknown | Remain quarantined/read-only; no local fallback |

## 5. Recovery algorithm

Recovery is an explicit authority operation and must run before issuance becomes writable:

1. Enter RECOVERY_ONLY and deny new issuance, acceptance and response publication.
2. Read the latest independently authenticated witness checkpoint and predecessor linkage.
3. Read the durable authority aggregate, append-only event log, immutable responses, nonce/operation indexes and pending checkpoint intents.
4. Independently recompute canonical event/state digests and verify exact response bytes and index bindings.
5. Compare authority/environment identity, witness generation, checkpoint predecessor digest, ledger sequence, state digest, epoch high-water mark, pending operation, response digest, nonce/operation index digests and revocation generation.
6. If local state exactly matches the witness, reconcile only the same deterministic transition.
7. If the witness is ahead and the exact committed authority record is available from the independently protected append-only log, restore forward and verify before reopening. Never reconstruct facts from a guest snapshot.
8. If local state is ahead, witness unavailable, a fork observed, or any record/index/response is missing or contradictory, remain quarantined. Never decrement a high-water mark, mint a replacement epoch, delete tombstones or accept operator-supplied state as witness evidence.
9. Reopen only after independent verification records exact checkpoint and recovered-state digests and a separate policy authorizes the operation.

A digest-only witness cannot reconstruct lost response bytes; a database backup alone cannot prove it is the newest state. Witness and durable log must be recoverable independently.

## 6. Required implementation-level conformance tests

A disposable environment must exercise:

- two independent sessions racing from the same record version; exactly one distinct successor commits;
- same nonce/same digest and same operation/same digest return byte-identical response bytes;
- nonce-to-operation and operation-to-nonce rebinding both conflict;
- termination before commit leaves no epoch, response, index or checkpoint intent;
- true lost-COMMIT-acknowledgement through a controlled network proxy resolves the original transaction exactly once;
- termination after commit but before witness advance recovers the same checkpoint intent;
- lost witness acknowledgement resolves by exact checkpoint operation ID and digest;
- witness CAS rejects stale generation, fork, replay, gap and high-water regression;
- restore of authority rows, response bytes, nonce index, operation index, event chain or acceptance state to an older snapshot is detected;
- witness-ahead recovery restores forward from independently protected log or remains quarantined;
- authority-store-ahead and unavailable-witness cases remain non-publishable;
- acceptance/revocation races serialize and no post-revocation admission is possible;
- exact historical response replay after a newer epoch never mutates current epoch;
- role/privilege tests prevent API callers from rewriting/deleting issuance, replay, event or checkpoint-intent records;
- backup/restore and key rotation/revocation are tested across independent failure domains.

Preserve transaction traces, request/response bytes and digests, operation IDs, witness receipts, snapshots, fault-injection points and independent verifier output. Timing-only stress is supplementary; deterministic barriers and controlled crash boundaries are required.

## 7. Non-goals and approval gates

This proposal creates no SQL, migration, database role, witness integration, provider adapter, signing key, host agent or runtime endpoint. It does not claim Neon, Cloudflare R2 or any provider already satisfies the required semantics.

Before implementation approval, independently review the authority and witness trust domains; witness anti-equivocation/quorum and key lifecycle; canonical encoding and cryptographic envelopes; durable log/response retention; database isolation and uniqueness constraints; provider operation idempotency and predecessor discovery; exact-instance guest acceptance; crash/restore fault injection; role separation; and the full evidence acquisition/verification chain.

The existing FENCE-001 authority conformance model remains synthetic. The authorization transaction proposal and its PostgreSQL CI fixtures concern the application authorization ledger and do not qualify this external epoch authority. These contracts must be reviewed together without treating one as proof of another.

**Qualification remains blocked** until a selected authority/witness/provider combination passes implementation-level tests and independent review using independently acquired evidence. No provider or host is selected by this proposal.
