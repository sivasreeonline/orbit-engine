# FENCE-001 API Worker workload proof client

## Status

Implementation and synthetic-key test coverage only. No production private key,
gateway allowlist, deployment, witness append, or external provider write is
provisioned or qualified by this change.

## Caller configuration

The API Worker accepts three optional runtime values:

- `WORKLOAD_CALLER_ID`: stable caller identifier, e.g. `sky-high-api`
- `WORKLOAD_CALLER_KEY_ID`: lowercase SHA-256 hex fingerprint of the raw 32-byte Ed25519 public key
- `WORKLOAD_CALLER_PRIVATE_KEY_PKCS8`: base64url-encoded Ed25519 PKCS#8 private key

The PKCS#8 value must be stored as a Cloudflare Worker secret, not committed to
source control, a Wrangler vars block, a fixture, or a client-visible response.
The gateway receives only the corresponding raw public key in its pinned
`WORKLOAD_CALLER_KEYS` allowlist.

No actual key material is included. Caller and gateway key records must be
provisioned as a coordinated operational step before enabling an application
call path.

## Proof construction

The API helper creates a proof for the fixed gateway contract:

- audience: `sky-high-witness-gateway`
- scope: `witness:authorize`
- method: `POST`
- path: `/rpc/authenticate`

The proof binds the SHA-256 digest of the exact body bytes, caller/key identity,
issued/expiry times, a fresh 192-bit random nonce, and an Ed25519 signature over
the existing domain-separated workload-signing tuple.

Proof lifetime is 45 seconds, below the verifier's 60-second maximum. The
private key is imported only inside the API Worker and is never included in the
RPC arguments. Only the proof and exact body bytes cross the Service Binding.

## Failure behavior

- Missing caller ID, key ID, or private-key secret returns
  `caller_identity_unconfigured`.
- Invalid key encoding/import/signing returns `caller_proof_signing_failed`.
- Missing private Service Binding returns `gateway_unavailable`.
- RPC errors fail closed as `gateway_unavailable`.
- The gateway remains responsible for pinned-key, audience, scope, time,
  signature, body-binding, and durable nonce validation.

## Validation

Tests generate ephemeral Ed25519 key pairs in memory, verify proof signatures,
and exercise the typed RPC client with a test double. They do not use production
credentials or contact a deployed gateway. The application API routes do not
yet invoke this helper; a later slice must connect a narrowly scoped witness
operation and add a true API-to-gateway Workers integration test before any
production activation.
