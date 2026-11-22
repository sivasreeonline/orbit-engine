# FENCE-001 durable monitor gossip replay object

**Status:** Cloudflare Durable Object implementation slice with synthetic tests; not yet a deployed or production-qualified monitor receiver.

## Storage and serialization model

The Worker exports `GossipReplayStateDO` as a SQLite-backed Durable Object. The Wrangler binding is internal to the Worker configuration; the object's public HTTP `fetch` handler returns 404. The receiver-side RPC method is intended to be called only after a trusted ingress component has authenticated the sender and verified the envelope signature, trust/revocation status, witness scope and Merkle consistency proof.

One Durable Object instance is addressed per sender/recipient/witness-scope relationship. The first accepted envelope binds those identities. Any later identity or scope substitution quarantines the relationship.

The state transition reads and writes one versioned state record inside a Durable Object storage transaction. The transaction includes:
- highest accepted sender sequence;
- sequence-to-message/digest deduplication;
- message-ID-to-sequence/digest deduplication;
- unresolved sequence gaps;
- outstanding consistency-proof request IDs, nonces and expirations;
- consumed request nonces.

The transaction is the atomic boundary: no successful acceptance response is returned before the replay state write commits. Exact retries are idempotent across Durable Object reconstruction because state is persisted rather than held in process memory.

## Receiver policy

The implementation preserves the replay reference model's bounded sequence-gap and reorder rules, five-minute message lifetime, 30-second future-clock skew allowance, and request/response nonce binding. It rejects:
- message-ID rebinding and sequence equivocation;
- relationship/scope changes;
- expired or malformed timestamps;
- excessive sequence jumps and stale out-of-window messages;
- nonce reuse, unsolicited responses and request/response nonce mismatch.

Accepted gaps remain explicit until each missing sequence arrives. The Durable Object does not treat a gap as agreement or an authorization decision.

Sequence/message deduplication records older than the retained 128-sequence history are pruned only after they are outside the 64-sequence replay acceptance window. Consumed nonces are retained without time-based pruning to avoid reopening nonce reuse; storage growth and a separately qualified compact representation remain an operational design item.

## Security boundaries

This object is a durable replay-state component, not a complete gossip service:
- It does not authenticate a monitor or verify Ed25519 signatures, trust bundles, revocation, Merkle proofs or trusted time.
- The caller must not accept client-supplied verification booleans. Only a trusted internal ingress path may invoke the RPC method after independent verification.
- A Durable Object's durable storage is not, by itself, proof against rollback after account-level restore, compromised deployment, or a coordinated administrative action.
- The component does not prove that every configured monitor receives every message, prevent network suppression, or establish a globally consistent view.
- The external monitor roster gate and independent witness/checkpoint governance remain required.
- No execution/admission path calls this object in this slice; it does not authorize host or student-code execution.

Production qualification requires authenticated internal invocation, independent monitor identities and failure domains, durable high-water checkpoints outside the authority restore domain, restore/failover and concurrency tests, bounded storage/retention operations, alert delivery, and split-view exercises under network partition and monitor compromise.
