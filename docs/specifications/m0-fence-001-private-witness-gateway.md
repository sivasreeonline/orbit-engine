# FENCE-001 Private Witness Gateway Worker

## Status

Implementation slice only. This specification and code do not qualify a production
caller key, external witness provider, witness append path, or production deployment.

## Boundary

- The gateway is a separate Cloudflare Worker named `sky-high-witness-gateway`.
- `workers_dev` is disabled and no public route is configured.
- The API Worker reaches the gateway only through the `WITNESS_GATEWAY`
  Service Binding and typed RPC contract.
- A Service Binding is private transport, not caller authentication. The gateway
  independently verifies an Ed25519 workload proof.
- The gateway's `fetch` handler returns 404. The first RPC operation only
  authenticates/authorizes a request; it does not append a witness or contact a provider.

## Authentication contract

The gateway fixes the request context independently of caller input:

- audience: `sky-high-witness-gateway`
- scope: `witness:authorize`
- method: `POST`
- path: `/rpc/authenticate`

The caller supplies the signed proof and exact body bytes. Existing
`authenticateWorkloadCall` verifies the signature, key fingerprint, key
validity/revocation, time window, audience, scope, method, path, body digest,
and nonce. The gateway supplies its own trusted time and durable nonce store.

The `WORKLOAD_CALLER_KEYS` Worker variable is a JSON array of pinned public-key
records. It contains public keys only, never caller private keys. Missing,
empty, or malformed configuration fails closed. No real key material is committed.

## Replay protection

The gateway binds its own `WorkloadNonceReplayDO` namespace and migration.
Nonce consumption is atomic and caller-scoped. Replay-store failures fail closed
through the existing verifier. The API Worker's previous nonce namespace is not
used by this gateway RPC path.

## Qualification boundary

CI validates TypeScript, unit tests, the Workers runtime's closed HTTP surface,
and a Wrangler deployment dry run. It does not deploy the Worker, provision
secrets, establish a production caller allowlist, perform a provider write, or
prove external monitor durability/anti-equivocation.
