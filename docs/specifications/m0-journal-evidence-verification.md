# M0 journal qualification evidence verification

The manifest validator is a structural check only. The independent verifier in
`internal/journal/evidence_verifier.go` adds byte-level SHA-256 verification,
detached Ed25519 attestation verification, reviewer-role/key policy checks,
implementer/reviewer separation, and policy-supplied evidence-age enforcement.

## Trust inputs

The verifier accepts an `EvidenceSource`, an explicit
`EvidenceVerificationPolicy`, and a caller-supplied verification timestamp.
It contains no embedded trust root, reviewer identity, public key, key
distribution mechanism, revocation feed, or default evidence-age duration.
The caller is responsible for authenticating and protecting the policy and
for implementing a read-only evidence source confined to the evidence package.

A trusted key must identify a principal, carry the
`JOURNAL_QUALIFICATION_REVIEWER` role, and have a configured validity window.
A key revoked at or before signing time is rejected. When distinct-reviewer
enforcement is enabled, the trusted reviewer principal must differ from the
implementer identity supplied by policy.

## Attestation format

The detached JSON attestation carries an Ed25519 signature over the canonical
JSON encoding of `QualificationAttestationPayload`. Its manifest digest binds
the complete typed manifest while omitting only the attestation file's own
SHA-256 field, avoiding a signature/hash cycle. The attestation file itself is
then SHA-256 checked against the manifest reference. The payload binds the
qualification ID, reviewer identity, key ID, and review timestamp.

## Report and limits

A successful verification report records policy identity/version, manifest
digest, checked evidence count, reviewer/key identity, and verification time.
The report is deterministic for identical inputs. It is an in-process result,
not a signed or immutable audit artifact.

This verifier does not authenticate policy distribution, establish legal or
organizational reviewer independence, fetch evidence from a provider, provide
key rotation/revocation distribution, validate hardware provenance, or prove
that test commands were honestly executed. It does not authorize deployment,
host execution, or student workloads. Production integration requires an
independently governed trust-policy source, confined evidence resolver,
key lifecycle procedure, and separate security review.
