# FENCE-001 monitor gossip replay-state reference model

**Status:** Test-only receiver state-machine model; not a deployed message receiver or durable replay database.

## State that must survive restart and restore

For each authenticated sender/recipient relationship, the receiver persists:
- highest accepted sender sequence;
- accepted sequence-to-message/digest bindings;
- message-ID-to-sequence/digest deduplication bindings;
- outstanding consistency-proof request IDs, nonces and expirations;
- consumed one-time response nonces;
- missing sequence numbers observed when gaps are accepted.

This state must live outside the authority database restore domain and be protected against rollback. A restore below an independently protected sequence high-water quarantines the sender relationship. The reference model does not provide the actual durable store or trusted high-water service.

## Receiver outcomes

| Outcome | Meaning |
|---|---|
| `ACCEPTED` | Valid new message accepted and replay state advanced |
| `ACCEPTED_WITH_GAP` | Message accepted, but missing sequence numbers remain explicitly visible |
| `DUPLICATE` | Exact previously accepted message; no side effect may be repeated |
| `BLOCKED` | Trust unavailable, message expired, stale replay or sequence gap exceeds resynchronization bounds |
| `QUARANTINE` | Invalid signature, identity/scope substitution, message-ID or sequence equivocation, nonce reuse, malformed time or state rollback |

Sequence gaps may be accepted within a bounded window, but they remain recorded. A later out-of-order message may fill a missing sequence; the gap is resolved only when every missing sequence is received or an independently authenticated resynchronization procedure reconciles the sender state. A large gap is blocked and requires resynchronization.

## Request/response binding

A consistency-proof request creates one outstanding request ID and a fresh nonce. A response must match both values and arrive before the originating request expires. The nonce is consumed exactly once. An exact duplicate response is idempotent because message-ID/digest deduplication is evaluated before request side effects; a different response reusing the same request or nonce is quarantined.

## Validation boundary

`scripts/validate_m0_monitor_gossip_replay_state.py` models the receiver policy and exercises 25 cases. Signature verification, trusted time, scope authorization, durable transactions, cross-process concurrency, authenticated transport and proof verification are inputs or external dependencies. The model's dictionaries are in-memory fixtures, not production persistence.

The real implementation must commit replay-state changes atomically with message acceptance, serialize concurrent messages from one sender, and ensure a crash cannot apply a side effect without its deduplication record or consume a nonce without recording the response. Production approval also requires restore/failover tests against the independently protected high-water store.
