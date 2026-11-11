# FENCE-001 complete predecessor evidence bundle

## Status and boundary

This is a provider-neutral evidence contract. It does not select a cloud provider, fencing mechanism, signing algorithm, key service, host, or deployment. It does not claim that any provider has been qualified.

The contract resolves an evidence-model ambiguity: a host-epoch response has one immutable fence-evidence reference, while a restored or cloned host may have multiple predecessor incarnations. That single reference must identify one aggregate predecessor-fence bundle, not an arbitrary single predecessor attestation.

## Required binding

The aggregate bundle is defined by `docs/schemas/m0-predecessor-fence-bundle.schema.json`. It binds:

- stable host enrollment identity;
- provider, account and region;
- exact target provider instance;
- unique issuance operation ID;
- issuance nonce and canonical request SHA-256 digests;
- complete predecessor-enumeration observation and independently verified source evidence;
- the canonical predecessor-set digest; and
- one distinct immutable provider-fence attestation reference, object version and digest for every enumerated predecessor.

An empty predecessor array is permitted only when the enumeration is explicitly complete and backed by independently verified inventory evidence. An empty array must never be used to mean that enumeration was skipped or unavailable.

## Canonical predecessor-set digest

The digest input is the normalized predecessor identity array. Each entry contains exactly:

- `provider_instance_id`;
- `incarnation_epoch`; and
- `relationship`.

Entries are sorted lexicographically by `provider_instance_id`. The JSON object keys are sorted, UTF-8 is used, whitespace is omitted, ASCII escaping is enabled, and non-finite numbers are forbidden. SHA-256 is computed over those canonical bytes.

Provider-fence attestation references and evidence digests are deliberately excluded from this set digest: they are evidence about the members, not the identities that define membership. The aggregate bundle digest separately commits to all evidence references and metadata.

## Per-predecessor fence evidence

Every predecessor entry must state `FENCED`, the provider-native or separately reviewed fencing method, a timezone-aware observation time, and a unique immutable attestation reference/object-version/digest tuple. The referenced attestation payload must match the bundle's provider/account/region, operation ID, predecessor instance ID and epoch, predecessor-set digest, fence method, and observed time.

The existing `m0-provider-fence-attestation-payload.schema.json` defines the per-predecessor payload shape. It does not authenticate the provider response, signature, evidence object, or actual compute/storage/control-path isolation. Those checks require the independently selected production trust profile and provider-specific verifier.

## Host-epoch response binding

The `fence_attestation_ref`, `fence_attestation_object_version` and `fence_attestation_sha256` fields in `m0-host-epoch-response-payload.schema.json` identify the exact immutable aggregate bundle object version and bytes. The authenticated authority response must also bind the same host enrollment, target provider instance, operation ID, nonce digest, request digest, predecessor-set digest, epoch and authority key version.

The authority must not issue an admissible epoch until complete enumeration and every predecessor fence are independently verified. The response signature/MAC must be verified using separately pinned trust material. A reference string, schema-valid payload, provider API request ID, or successful stop request is not proof of effective fencing.

## Structural validator and test vectors

Run:

```bash
python scripts/validate_m0_predecessor_fence_bundle.py
```

The deterministic synthetic tests cover a multi-predecessor bundle, a fully evidenced empty inventory, duplicate and unsorted predecessors, canonical digest mismatch, incomplete inventory, duplicate attestation references, premature fence chronology, and self-verified inventory evidence.

These tests validate only the bundle contract and canonicalization. They do not open or authenticate referenced provider evidence, verify signatures, prove provider completeness, or establish that a predecessor cannot resume.

## Mandatory independent evidence still required

FENCE-001 remains blocked until an independently reviewed provider-specific package demonstrates:

1. complete enumeration of all predecessor VMs, clones, snapshots and other authority-bearing incarnations;
2. provider-enforced prevention of compute execution, storage writes and privileged control-path use by every predecessor;
3. fence-before-epoch chronology and an authenticated, monotonic, replay-resistant authority response;
4. concurrency tests proving only one successor incarnation is admitted;
5. replay, rollback, lost-response and authority-recovery tests; and
6. independent read-back and verification of immutable evidence objects and the exact aggregate bundle digest.

No synthetic fixture, schema validation, application database lease, guest journal generation, or local test adapter can substitute for provider-side evidence.
