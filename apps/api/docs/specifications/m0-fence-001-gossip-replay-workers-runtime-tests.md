# FENCE-001 gossip replay Durable Object: local Workers runtime tests

## Purpose

Exercise `GossipReplayStateDO` against Cloudflare's local Workers runtime
(`workerd` via Miniflare), using the actual Wrangler Durable Object binding
and SQLite-class migration. These tests complement, rather than replace, the
fast Node/Vitest state-machine tests that use a synthetic storage fixture.

## Coverage

The Workers runtime suite verifies:

- A committed replay decision is visible through a separately acquired RPC
  stub for the same Durable Object identity.
- Concurrent conflicting claims for one sender sequence are serialized by
  the Durable Object transaction boundary; both claims cannot be accepted.
- Consistency-proof request correlation and nonce consumption remain effective
  across RPC calls.
- The Durable Object's HTTP surface remains closed (404).

The runtime test uses synthetic messages and local Miniflare storage only.
It does not contact Cloudflare production, AWS, external witnesses, or any
provider endpoint. It does not execute student code or authorize host execution.

## What this does not prove

- Reacquiring an RPC stub is not a forced eviction, process restart, restore,
  or failover test. It demonstrates persistence through the configured local
  Durable Object storage path, not production recovery guarantees.
- Miniflare/workerd local behavior is not proof of Cloudflare production
  persistence, backup/restore semantics, regional failover, or storage
  durability under provider incidents.
- Monitor identity authentication, signature and trust verification,
  revocation, scope binding, Merkle consistency-proof verification, and
  authenticated network transport remain caller-side prerequisites.
- The replay Durable Object is not an independently protected rollback
  checkpoint. The FENCE-001 external witness high-water integration remains
  required to detect replay-state rollback.

## Running

From `apps/api`:

```bash
npm run test:workers
```

The standard `npm test` Node suite remains unchanged. CI runs both suites.


## Durable checkpoint recovery integration coverage

The Workers integration suite now also exercises the complete synthetic positive recovery path across the API Durable Object, private gateway Worker, synthetic provider and synthetic evidence-authority Worker:

- The pending intent is staged before any gateway RPC and survives a separately acquired Durable Object stub.
- A provider commit with a lost acknowledgement is recovered using the exact immutable operation identity.
- An evidence-authority outage after provider commit leaves the pending intent and persisted replay state unchanged.
- A structurally plausible but cryptographically invalid Merkle inclusion proof is rejected by the API Worker's independent verifier; the exact pending intent and accepted replay state remain unchanged.
- A later exact retry recovers the authority's original immutable evidence and finalizes the transition once, despite concurrent recovery callers.
- The persisted state advances only after evidence verification and atomic local finalization.

The alarm path distinguishes transient availability failures from integrity failures. Gateway/provider unavailability, ambiguous checkpoint outcomes and unexpected recovery errors retain a bounded retry schedule. Invalid pending bytes, unverifiable evidence and finalization-binding mismatches persist a quarantine record at `replay-checkpoint-quarantine-v1`. Constructor recovery checks that record before re-arming an alarm, so an invalid intent does not resume automatic retries after Durable Object reconstruction. The pending intent remains available for investigation and the accepted replay state is not advanced.

A newly staged transition clears a prior quarantine marker only after the lifecycle accepts the new pending intent. No public HTTP endpoint is added; the Durable Object HTTP surface remains closed.

These tests use ephemeral keys, synthetic Workers and local Durable Object storage. They prove the implemented integration and failure behavior in the local Workers test environment only. They do not qualify an independently administered production evidence authority, provider durability, operational independence, Cloudflare production persistence, or rollback protection in a live deployment.
