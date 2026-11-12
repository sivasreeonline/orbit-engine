# FENCE-001 monitor gossip envelope v1

**Status:** Provider-neutral message contract proposal; not a deployed transport or approved production key profile.  
**Schema:** `docs/schemas/m0-fence-monitor-gossip-envelope-v1.schema.json`  
**Test vectors:** `docs/test-vectors/fence-monitor-gossip-v1.json`

## Envelope

Every point-to-point message carries:
- protocol profile and one of four message types;
- unique message ID;
- sender and recipient monitor identities, including monitor signing-key IDs;
- monotonically increasing sender sequence scoped to sender/recipient;
- issue and expiry timestamps;
- unpredictable nonce;
- exact trust-domain/witness/authority/host scope;
- type-specific body;
- detached Ed25519 signature over the canonicalized envelope excluding the signature field.

The proposed signature input is:

`UTF8("SKY-HIGH-FENCE-001-MONITOR-GOSSIP-V1\\0") || JCS(envelope_without_signature)`

The sender identity key is distinct from the witness signing key. The monitor identity trust bundle must be independently rooted, versioned, revocable and protected from rollback. The profile proposal uses RFC 8785 JCS and Ed25519, but this PR validates only envelope shape and semantic bindings; it does not implement or approve cryptographic verification.

## Message types

| Type | Required body | Purpose |
|---|---|---|
| `HEAD_ADVERTISEMENT` | One signed witness head | Share the monitor's current authenticated witness view |
| `CONSISTENCY_PROOF_REQUEST` | Exact older and newer head references plus request nonce | Request proof binding those two tree sizes and roots |
| `CONSISTENCY_PROOF_RESPONSE` | Exact head references, proof nodes, originating request ID and nonce | Return the proof to the exact outstanding request |
| `EQUIVOCATION_ALERT` | Two signed heads | Preserve portable evidence of two distinct validly signed roots at the same scope and generation |

Every signed head in an envelope must match the envelope scope. A consistency proof response must bind to the exact request ID and nonce, and its proof must be verified against the exact from/to tree heads. An equivocation alert is meaningful only when both signatures and their trust paths independently verify.

## Replay, ordering and expiry requirements

The receiving monitor must persist replay state outside the authority database restore domain, keyed by sender identity, recipient identity and sequence:
- exact duplicate message ID and exact bytes are idempotent and must not repeat side effects;
- same sequence with different canonical bytes is a sender equivocation event and quarantines that sender relationship;
- a sequence below the persisted high-water is rejected as replay;
- a higher sequence may be accepted even if there is a gap, but the gap must be recorded and the monitor must continue polling/reconciliation so message suppression cannot silently establish agreement.

Responses must consume a one-time request nonce and match both request ID and nonce. Expired messages, unknown/revoked sender keys, stale trust bundles, invalid signatures, scope substitution, or untrusted time block or quarantine according to the security policy. A receiver must not infer trusted time from the message's own timestamp.

## Operational requirements

- Use authenticated point-to-point transport; do not assume transport security replaces message signatures.
- Persist sender sequence high-water, message-ID deduplication and consumed nonces durably.
- Keep monitor keys, credentials, operators, accounts, deployment control planes and failure domains independent from the authority and from each other.
- Record raw signed envelopes and proof bytes in tamper-evident evidence storage.
- Enforce a bounded maximum message lifetime and a documented clock-skew policy using a trusted time source.
- Alert on sequence equivocation, unexplained gaps, replay, expired responses, stale monitor polls and unresolved proof requests.
- A gossip exchange never authorizes host admission by itself. The monitor set must independently converge on the same head and the separate FENCE-001 qualification decision must remain satisfied.

RFC 9162 defines signed tree heads and consistency proofs but explicitly leaves gossip as an active research area rather than a complete interoperable protocol. This envelope therefore defines Sky High's application-level message binding; it must receive independent protocol and cryptographic review before production adoption.

## Validation boundary

`scripts/validate_m0_fence_monitor_gossip_envelope.py` validates JSON Schema Draft 2020-12, strict duplicate-member rejection, scope bindings, message-type invariants, bounded expiry, proof range ordering, equivocation payload distinction and fixture sequence uniqueness. The fixture signatures are placeholders. A passing validator is not signature verification, trusted time, replay protection implementation, durable delivery or evidence of independent monitor deployment.
