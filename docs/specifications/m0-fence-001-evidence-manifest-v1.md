# FENCE-001 independently attested evidence manifest v1

**Status:** Evidence packaging and verification contract. The checked-in vector is synthetic and test-only.  
**Signature suite:** RFC 8785 JCS, SHA-256 and Ed25519.  
**Domain separation:** `SKYHIGH-FENCE-001-EVIDENCE-MANIFEST-V1\0`.

## Purpose

A qualification result must be bound to the exact provider scope and adapter build that produced it. Every evidence artifact is identified by immutable object reference/version, SHA-256 and byte count. A collector attests to acquisition; a distinct independent verifier attests to the same manifest digest. The manifest is not a substitute for the raw evidence.

## Signed body and digest

The signed body is `manifestBody`. Its digest is lowercase SHA-256 over UTF-8 RFC 8785 JCS bytes. The envelope carries the digest and exactly two detached attestations:
- `COLLECTOR`
- `INDEPENDENT_VERIFIER`

Each Ed25519 signature covers the domain-separation prefix followed by JCS of exactly `{manifestDigest, role, signerIdentity, keyId}`. Key IDs are SHA-256 fingerprints of raw 32-byte Ed25519 public keys. Public keys are not embedded in the manifest; they must be supplied by an independently governed trust configuration. A key is authorized for one role and identity. The two identities and keys must differ.

## Evidence binding

The body pins provider name, account, region and service, plus adapter repository, immutable 40-character commit, version and configuration digest. Each artifact binds:
- one or more mandatory WIT-001–WIT-014 qualification controls;
- artifact type, immutable object reference/version, SHA-256 and byte count;
- acquisition timestamp and provider request IDs;
- collector and independent-verifier identities and key IDs;
- redaction state.

The manifest digest transitively binds every artifact claim to the provider and adapter scope. The validator rejects duplicate artifact IDs, mismatched signer identities/keys, missing role attestations, incorrect key authorization, invalid signatures and altered manifest content.

## Trust configuration and operation

The external verifier accepts a manifest and a separately provisioned trusted-key file:

```sh
FENCE_WITNESS_ADAPTER_FACTORY=... # adapter execution is a separate step
python scripts/validate_m0_fence_evidence_manifest.py --manifest run-manifest.json --trusted-keys /secure/trust/fence-evidence-keys.json
```

The trust file must be provisioned and pinned through a governance channel independent of the evidence collector and provider account. It must not be fetched from the manifest's object store or accepted because the manifest names its own key. Key rotation/revocation and trusted timestamp policy are governed by the independent trust configuration and the wider FENCE-001 trust lifecycle.

The validator verifies manifest-level signatures and structural bindings. It does not fetch evidence objects, prove object-lock immutability, validate provider request IDs with the provider, or establish that the independent verifier is genuinely independent. Those are external qualification tasks. Evidence-object bytes must be independently retrieved and re-hashed by the verifier; the resulting verification statement must itself be retained as immutable evidence.

## Test-only fixture

`docs/test-vectors/fence-evidence-manifest-v1.json` contains deterministic test keys and signatures. It is marked `testOnly: true` and is accepted only by the harness's fixture path. External qualification mode rejects test-only manifests. Fixture private seeds are not included. No key in the fixture is trusted for production use.

A valid manifest signature proves that the configured collector and verifier keys signed the manifest digest. It does not prove that the provider evidence is truthful, that the object store is immutable, or that either signer is independent. Production approval remains false until the full evidence package is independently reviewed.
