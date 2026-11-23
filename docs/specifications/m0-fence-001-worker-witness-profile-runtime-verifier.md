# FENCE-001 Worker witness profile runtime verifier

## Status

Local Cloudflare Worker-compatible TypeScript verification implementation.
This is not a provider adapter, persistent trust-state implementation, or
production qualification. It reuses the existing FENCE-001 receipt, trust-bundle,
signed tree-head and RFC 9162 formats; it does not define a parallel format.

## Implemented verification path

`apps/api/src/witness/witness-profile-verifier.ts` implements:

1. RFC 8785 canonical JSON using the pinned `canonicalize` package.
2. Root-pinned trust-bundle envelope verification:
   - canonical body SHA-256 digest;
   - pinned Ed25519 root fingerprint and root signature;
   - expected trust-domain and witness binding;
   - exact next generation and predecessor digest;
   - key fingerprint, scope, purpose, validity, retirement and revocation shape checks.
3. Receipt verification against a root-verified trust bundle:
   - exact checkpoint body and receipt envelope field sets;
   - canonical checkpoint digest;
   - receipt/checkpoint operation, scope, generation and predecessor binding;
   - receipt-purpose key authorization and key lifecycle;
   - Ed25519 receipt signature under the existing domain prefix.
4. Signed tree-head verification:
   - exact tree-head profile and scope;
   - distinct `WITNESS_LOG_SIGNING` key purpose;
   - key fingerprint, scope, validity, retirement and revocation;
   - Ed25519 signature under the existing tree-head domain prefix.
5. RFC 9162 SHA-256 inclusion and consistency proof verification:
   - the complete canonical signed receipt envelope is the Merkle leaf;
   - proof-node length and digest grammar checks;
   - prior/current log and scope binding;
   - tree-size rollback and conflicting-root rejection.
6. `verifyWitnessEvidence` composes these checks into one path.

The implementation intentionally requires a `VerifiedTrustBundle` result for
receipt and tree-head checks. Callers must not pass an unverified trust-bundle
body directly.

## Persistent-state requirement

The verifier receives the expected trust-bundle generation/predecessor and the
prior accepted signed tree head from its caller. This PR does not persist either
value. Before production use, those values MUST come from a durable,
rollback-resistant trust-state store. A Worker-local cache, in-memory value, or
caller-supplied prior head is not sufficient.

The verifier also does not prove provider durability, log-signer independence,
monitor gossip, or split-view resistance by itself. A valid inclusion proof
shows inclusion in the supplied signed head; the caller must retain and compare
the prior trusted head and integrate independent monitor gossip.

## Test boundary

Tests reuse the existing receipt and trust-bundle vectors and create only
ephemeral synthetic log-signing keys in memory. No production root, signing
key, provider, secret, or external write is used. The Python conformance
validators remain authoritative cross-language reference tests; the TypeScript
tests demonstrate that the Worker runtime implementation agrees with the
published profile on these vectors.

## Not qualified

- durable trust-bundle anti-rollback storage;
- durable accepted tree-head pinning and monitor gossip integration;
- provider atomic compare-and-append, immutable lookup and strong latest reads;
- production key provisioning, rotation and independent provider durability;
- monitor replay Durable Object pending-intent/finalize/recovery integration.
