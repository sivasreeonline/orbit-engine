# FENCE-001 Worker evidence verification RPC

## Status

The private gateway exposes `WitnessGateway.verifyEvidence` over the API Worker's
named Service Binding RPC. It authenticates the caller, verifies the evidence
against pinned trust, and advances durable trust/head state. It does not append
new witness records or write to an external provider.

## Caller authentication

The API Worker signs the exact canonical evidence body bytes with its Ed25519
workload key. The gateway verifies a proof bound to:

- audience: `sky-high-witness-gateway`
- scope: `witness:verify-evidence`
- method: `POST`
- path: `/rpc/verify-evidence`
- SHA-256 digest of the exact body bytes
- short-lived issue/expiry timestamps and a fresh nonce

The gateway consumes the nonce in its gateway-owned Durable Object before
processing the evidence. Replay-store failure or authentication failure rejects
the call.

## Canonical evidence request

The body must be UTF-8 RFC 8785 canonical JSON with exactly these fields:

- `trustBundle`
- `checkpointBody`
- `checkpointDigest`
- `receiptEnvelope`
- `treeHeadEnvelope`
- `leafIndex`
- `inclusionProofHex`
- `consistencyProofHex`

The gateway rejects non-canonical bytes, duplicate-member encodings, malformed
nested envelopes and oversized bodies. The caller cannot choose the expected
trust domain, witness, authority or host independently: the gateway derives
them from the evidence and requires an exact configured allowlist match.

## Verification and state transitions

1. Parse the canonical evidence request and enforce the configured scope.
2. Read the gateway-owned trust-state Durable Object.
3. Verify the root-pinned trust bundle. Reuse the stored accepted bundle when
   the incoming digest matches, or verify exactly the next generation against
   the stored predecessor.
4. Verify the checkpoint digest and signed receipt using a
   `WITNESS_RECEIPT_SIGNING` key.
5. Verify the current signed tree head using a distinct
   `WITNESS_LOG_SIGNING` key.
6. Verify receipt inclusion using the complete canonical signed receipt
   envelope as the RFC 9162 Merkle leaf.
7. If a prior head exists, re-verify it using the trust-bundle snapshot stored
   with that head, then verify the RFC 9162 consistency proof. This preserves
   historical key context across later trust-bundle rotations.
8. Atomically advance the trust-bundle generation if needed, then compare-and-set
   the new signed tree head against the previously stored head digest.

The first observed signed head is recorded only with an empty consistency proof.
That establishes a local initial observation, not proof of log history before
the first observation.

## Configuration

- `WORKLOAD_CALLER_KEYS`: pinned API Worker public keys and allowed scopes.
- `WITNESS_ROOT_KEYS`: pinned root public keys.
- `WITNESS_TRUST_SCOPES`: exact allowlisted trust-domain/witness/authority/host
  tuples.

Missing or malformed configuration fails closed. No production values are
included in the repository.

## Result

A successful response reports the accepted trust-bundle generation/digest,
tree-head digest and size, and receipt leaf hash. Failure responses use
bounded reason codes and do not expose cryptographic or key material.

## Qualification boundary

- The operation verifies already-issued evidence; it does not create receipts,
  append witness leaves, or call an external provider.
- The local workerd integration tests use public test vectors and ephemeral
  synthetic log keys.
- Persistent state is scoped to one Cloudflare Durable Object namespace. It is
  not an independent external witness provider or monitor gossip network.
- Production root provisioning, trust-bundle rotation operations, provider
  atomic append/readback, independent monitor comparison and split-view
  resistance remain unqualified.
