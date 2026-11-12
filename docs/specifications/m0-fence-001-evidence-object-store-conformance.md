# FENCE-001 immutable evidence object-store conformance

**Status:** Provider-neutral storage contract and executable harness. No object-store provider is selected or qualified.  
**Harness:** `scripts/validate_m0_fence_evidence_object_store.py`.

## Contract

Evidence artifacts must be stored as immutable, version-addressed objects. The adapter contract exposes:

- `put_immutable(object_key, content, retention_until, idempotency_key, writer_identity)`
- `get_exact_version(object_key, version_id, reader_identity)`
- `head_exact_version(object_key, version_id)`
- `delete_version(object_key, version_id)`

A successful put returns a stable object key, immutable version ID, SHA-256 and byte count. An exact retry with identical bytes and idempotency key returns the same version. Reusing an idempotency key with different content is rejected. A later object version must not mutate an earlier version; evidence manifests always reference exact version IDs, never a mutable `latest` alias.

The exact version must expose independently inspectable retention metadata, including compliance-mode object lock, a retention deadline no earlier than the requested deadline, and writer identity. The independent verifier reads the exact version through a distinct identity and independently recomputes SHA-256 and byte count. A retained exact version must reject deletion.

## Executable coverage

The harness exercises nine contract cases:
1. exact-version readback and digest/byte-count agreement;
2. exact idempotent put retry;
3. idempotency key cannot be rebound to different bytes;
4. prior exact version remains immutable after a later put;
5. compliance retention mode and deadline;
6. retained exact version cannot be deleted;
7. readback uses a distinct verifier identity;
8. concurrent idempotent puts resolve to one immutable version;
9. unknown version ID cannot fall back to a latest alias.

The in-memory adapter validates harness logic only. Its compliance metadata is synthetic and it cannot prove actual provider object-lock enforcement, retention bypass resistance, privileged deletion controls, independent account ownership, remote versioning, replication, durability or restore behavior.

## Running against a real adapter

A candidate provider adapter can expose a zero-argument factory returning an implementation of `EvidenceObjectStore` and run the same suite:

```sh
FENCE_EVIDENCE_OBJECT_STORE_FACTORY=provider_adapter.module:create_store \
  python scripts/validate_m0_fence_evidence_object_store.py
```

The adapter SDK and credentials must be provisioned only in the isolated qualification environment. Do not commit credentials or provider secrets.

## External evidence still required

The real qualification package must independently prove:
- compliance/object-lock mode is enforced by the provider, not merely reported by the client;
- the retention period cannot be shortened and deletion cannot be bypassed by the adapter, account owner, privileged administrator or recovery workflow during the retention window;
- exact version IDs are stable and cannot resolve to a different object after overwrite, restore or replication;
- collector and verifier use distinct identities, credentials, administrative principals and preferably separate accounts;
- object version readback is performed through an independently authenticated path;
- retention configuration, object metadata, provider audit events, API responses and denied delete/overwrite attempts are preserved as independently attested evidence;
- restore, replication lag, region outage and provider-account recovery preserve exact-version integrity.

A synthetic fixture, a metadata field named `COMPLIANCE`, or a passing in-memory test does not establish provider-enforced WORM semantics. Production approval remains false until provider-specific evidence is independently reviewed.
