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
