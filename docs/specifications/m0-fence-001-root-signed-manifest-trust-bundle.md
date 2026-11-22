# FENCE-001 root-signed manifest trust bundle

**Status:** Offline verifier and synthetic conformance tests. No production trust root is established.  
**Verifier:** `scripts/verify_m0_fence_rooted_trust_bundle.py`  
**Schema:** `docs/schemas/m0-fence-manifest-trust-bundle-v1.schema.json`

## Why this layer exists

PR #176 introduced an independently supplied public-key store with approval metadata, validity intervals and revocation tombstones. That file alone is not cryptographically self-authenticating. This layer anchors manifest signing keys in a separate root-signed trust bundle and requires the verifier to receive the root public-key pin and expected bundle predecessor/generation out of band.

The root pin and anti-rollback checkpoint are trust inputs. They must not be copied from the trust bundle being verified.

## Signed envelope

The envelope contains:
- `body`: trust domain, generation, predecessor digest, creation time, signing-key records and revocations;
- `bundleDigest`: SHA-256 of RFC 8785 canonical body bytes;
- `rootKeyId`: SHA-256 fingerprint of the raw 32-byte pinned Ed25519 root key;
- `rootSignature`: canonical unpadded base64url Ed25519 signature over the domain-separated canonical body.

Signature domain separator:

```text
SKYHIGH-FENCE-001-MANIFEST-TRUST-BUNDLE-V1\0
```

## Monotonic succession

The verifier requires:
- the root key to be present in the separate pinned-root configuration;
- exact trust-domain match;
- `generation == expectedGeneration + 1`;
- `previousBundleDigest == expectedPredecessorDigest`;
- a valid root signature and matching canonical body digest.

The expected generation and predecessor digest are required CLI inputs and must come from independently persisted verifier state. The script does not persist or advance that state itself. A caller must durably record a verified generation before accepting its successor; otherwise a fresh process cannot detect rollback across separate invocations.

## Manifest signer authorization

The root-signed bundle lists Ed25519 collector and independent-verifier public keys with:
- key fingerprint, identity and role;
- validity interval;
- accountable approval metadata;
- optional retirement timestamp.

A manifest must select exactly one key per role. Both identities and keys must differ. The manifest's signed creation time must be inside each key's validity window and precede retirement. Root-signed revocations fail closed for any selected key.

Key rotation is represented by adding a new key record in a successor generation and retaining old records for historical inspection. A retired key can verify only manifests created before its retirement timestamp. A revoked key cannot verify a manifest, regardless of its signed creation time.

## Verification command

```bash
python scripts/verify_m0_fence_rooted_trust_bundle.py \
  --manifest ./cloudtrail-evidence-manifest.json \
  --trust-bundle ./manifest-trust-bundle.json \
  --pinned-roots ./out-of-band-pinned-roots.json \
  --artifact-root ./cloudtrail-bundle \
  --expected-generation 0 \
  --expected-predecessor-digest <64-zeroes-for-generation-1> \
  --expected-trust-domain-id <operator-pinned-trust-domain>
```

The pinned-root file contains only a `keys` array of `keyId` and `publicKeyBase64Url` pairs. It is an out-of-band pin configuration, not a trust bundle. Protect and distribute it through the independent root-of-trust process.

After root verification, the command invokes the existing combined CloudTrail digest custody, S3 inventory and dual-principal STS identity validator. It does not accept a test-only bypass.

## Synthetic CI coverage

Tests exercise:
- root signature and pinned-root enforcement;
- canonical body digest binding;
- generation rollback/gap rejection;
- predecessor-fork rejection;
- trust-domain substitution/tampering;
- key validity and role binding;
- root-signed revocation handling.

CI uses ephemeral test root keys and the public synthetic manifest vector only. No production root, AWS credential, live provider API or student-code execution is involved.

## Limits

This verifier is a stateless validation component. It cannot guarantee anti-rollback unless its caller supplies the correct durable generation/predecessor checkpoint. Root-key rotation, root compromise recovery, independent operator approval, trusted time, durable checkpoint replication and monitor anti-equivocation remain external governance/operational requirements.

A cryptographically valid manifest still does not prove AWS origin, Object Lock compliance, complete CloudTrail delivery or production qualification. The combined gate continues to return `productionQualificationReady=false` and `externalQualificationStatus=REQUIRED`.
