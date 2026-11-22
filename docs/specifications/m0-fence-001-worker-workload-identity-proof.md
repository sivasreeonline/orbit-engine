# FENCE-001 Worker workload identity proof v1

Status: implementation reference contract; not production-qualified.

## Security boundary

A Cloudflare Service Binding is the private transport/capability boundary between Workers. It prevents the target service from being exposed through a public URL unless separately configured, but the application must not infer the caller's workload identity from the binding alone. Cloudflare Access identity context also does not propagate through Service Binding HTTP or RPC calls.

The receiving Worker therefore requires an explicit signed workload proof. Caller private keys remain in the caller Worker's secret store. The receiver is configured with pinned public keys and authorization scopes. Browser/client-supplied identity headers are never accepted as workload proof.

## Proof fields

The proof contains exactly:

- `callerId`, `keyId`
- `audience`, `scope`
- `method`, `path`
- `bodyDigest` (lowercase SHA-256 hex of the exact body bytes)
- `issuedAt`, `expiresAt` (Unix seconds)
- `nonce` (canonical unpadded base64url, at least 16 decoded bytes)
- `signature` (canonical unpadded base64url Ed25519 signature)

The verifier checks the caller/key pair against a deployment-pinned allowlist; key fingerprint; allowed audience and scope; key validity and revocation; proof lifetime; exact method/path/body binding; and Ed25519 signature.

## Signature input

The signed bytes are UTF-8 encoding of:

```text
SKYHIGH-FENCE-001-WORKER-WORKLOAD-V1\n
callerId\n
keyId\n
audience\n
scope\n
method\n
path\n
bodyDigest\n
issuedAt\n
expiresAt\n
nonce
```

All string fields are restricted to bounded ASCII grammars that exclude line breaks. This avoids JSON property-order and serialization ambiguity. The signature algorithm is Ed25519.

## Replay protection

The verifier requires a `WorkloadNonceStore` and consumes the caller/nonce pair only after all proof, key, signature, time, and request-binding checks pass. The production implementation MUST use an atomic durable insert-if-absent operation, scoped by caller ID, and retain the nonce until at least its proof expiry plus the configured clock-skew allowance. If the replay store is unavailable, authentication fails closed.

The repository now includes a caller-scoped Durable Object nonce store with transactional insert-if-absent semantics, a bounded active-entry limit, alarm-based expiry cleanup, and local workerd concurrency/restart tests. The in-memory store remains only a verifier unit-test double. Service-binding wiring, secret/key provisioning, rotation, and end-to-end private gateway tests remain the next integration slice.

## Time and scope

- Maximum proof lifetime: 60 seconds.
- Maximum future issue-time skew: 30 seconds.
- The receiver supplies trusted time; the proof does not establish its own clock.
- The audience must identify the receiving gateway.
- The scope must identify the exact witness/authority/host relationship.
- The method, path, and exact request body bytes are signed and checked again by the receiver.

## Non-goals and qualification status

This proof establishes a cryptographically authenticated caller identity under the configured public-key allowlist. It does not establish that the caller's code or deployment is uncompromised, that Cloudflare's control plane is an independent failure domain, or that a witness provider is durable or append-only.

No production keys, Cloudflare secrets, service binding, provider write, host execution, or student-code execution are introduced by this verifier slice. Production workload identity remains NOT QUALIFIED until key provisioning/rotation, durable nonce storage, deployment isolation, operational recovery, and independent security review are complete.
