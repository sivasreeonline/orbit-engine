# M0 Cryptographic Trust and Key Lifecycle Contract

**Status:** Security architecture proposal; no algorithm, cryptographic library, KMS/HSM, trust root, or production key is selected or deployed.
**Scope:** Authentication of external host-incarnation/fencing receipts and Phase A authorization artifacts.
**Safety:** This contract does not implement signature verification, create keys, contact a provider, authorize a migration, or permit privileged implementation, Phase A, Phase B, student execution, or production execution.

## 1. Security objectives and trust boundaries

The system must provide authenticity, integrity, protocol/context binding, replay resistance, key lifecycle enforcement and independently reproducible verification. A valid signature proves only that a key signed specific bytes; it does not prove provider fencing occurred, evidence is truthful, the signer was authorized for this purpose, or the host is safe.

Trust domains remain separate:

1. **Offline trust root:** authorizes trust-bundle signing keys and recovery/revocation policy. It never signs routine host-epoch receipts or Phase A run authorizations.
2. **External host-incarnation authority:** serializes host epochs and signs issuance/fence receipts only after provider-enforced predecessor fencing. Its online signing key is purpose- and environment-scoped.
3. **Provider control plane:** supplies independently authenticated operation and fence evidence. Provider credentials and API tokens are not signing keys and must never be embedded in signed evidence.
4. **Phase A decision signer:** signs the immutable authorization decision only after independent security review. It is not the host-epoch issuer and cannot manufacture provider-fence facts.
5. **Verifier:** independently validates trust bundle, signature, canonical payload, key status, context bindings and evidence references. It is separate from host owner, evidence acquirer, authority operator and security reviewer.
6. **Application ledger:** stores public trust metadata, immutable references, verification reports and event facts. Neon is not a trust root, key issuer, provider authority, or substitute for cryptographic verification.

No single principal may control the offline root, online signer, provider fencing, evidence acquisition and independent verification.

## 2. Algorithm and encoding decision gate

No cryptographic algorithm or library is frozen here. Before implementation, record a versioned cryptographic profile approved by security review and checked against the actual authority, host agent, verifier, language/runtime, KMS/HSM and compliance requirements.

Evaluate Ed25519 where all deployed runtimes and custody services support it, and ECDSA P-256 with SHA-256 where a validated compliance profile or provider/HSM compatibility requires it. Any alternative needs a threat-model and interoperability rationale plus independent approval.

The final profile pins one algorithm per protocol version and key purpose. There is no sender-selected algorithm negotiation, automatic fallback, none algorithm, or acceptance of unknown aliases. Reject algorithm/key-type mismatch, weak or deprecated algorithms, malformed key/signature lengths and unapproved curves. Never implement custom cryptography.

Because current contracts and manifests are JSON-based, evaluate RFC 8785 JSON Canonicalization Scheme (JCS) as the initial candidate. Deterministic CBOR/COSE is an alternative only with a documented exact profile and interoperability tests; encodings must not be mixed within one protocol version. In either case:

- Strictly decode UTF-8 and reject malformed input, duplicate object keys, ambiguous numbers, invalid types and non-canonical encodings.
- Define required/optional fields, unknown-field handling, integer bounds, timestamp grammar, byte-string encoding and Unicode policy.
- Reject non-finite numbers and floating-point values in security-critical fields; use bounded integers and normalized UTC timestamps.
- Re-encode the parsed payload and require byte-for-byte equality with received canonical bytes before signature verification.
- Hash exact canonical bytes; never sign implementation-dependent JSON serialization or a parsed object without canonicalization.

A profile change requires a new protocol/profile version, new test vectors, independent review and explicit migration/overlap plan. Existing artifacts remain verifiable under their original pinned profile, subject to revocation policy.

## 3. Signed envelope and domain separation

Every signed object has a canonical payload and detached signature envelope. The final schema must bind at least:

- protocol, immutable profile version, message type and explicit audience;
- issuer ID, key ID, immutable key version and pinned algorithm;
- subject host-enrollment ID and exact provider-instance ID;
- epoch, operation ID, response ID and one-time nonce digest;
- request digest and predecessor-set digest;
- fence-evidence digest plus immutable evidence object/version reference;
- exact host-qualification record reference and digest where applicable;
- issue, not-before and expiry times with trusted-time provenance;
- payload digest, canonicalization profile and signature bytes/reference.

The signed message includes a fixed protocol-specific domain-separation prefix, such as the literal ASCII context ORBIT-M0-HOST-EPOCH-RESPONSE/v1 followed by an unambiguous separator and canonical payload bytes. Phase A authorization, trust bundles, revocation statements and provider-fence attestations each require distinct context strings and message types. A signature valid for one protocol or artifact type is never reusable in another.

The verifier checks expected audience, message type, host identity, provider instance, epoch, nonce/request/predecessor digests, evidence digest, qualification digest, validity interval and protocol version against independently obtained request and authority state. It must not trust values supplied only by the signed object.

Reject duplicate envelope fields, detached-signature substitution, digest/reference mismatch, trailing data and unsupported critical extensions.

## 4. Key hierarchy, custody and role separation

### 4.1 Root and online signing keys

- Keep the trust root offline or in a separately controlled high-assurance signing boundary. Root operations require dual control and auditable ceremonies.
- Use dedicated online keys per environment, authority and signing purpose. Development, test and production keys are never shared.
- Prefer non-exportable private keys in a reviewed KMS/HSM or equivalent custody boundary. The signer exposes a narrow typed operation, not a general-purpose signing oracle.
- Private key bytes, seed material, recovery shares and bearer credentials must never be stored in Neon, R2, source control, CI variables, logs, crash dumps or evidence bundles.
- Neon may store public key material or immutable public-key references, key ID/version, algorithm, purpose, validity, status, trust-bundle generation and revocation evidence digest. Private material is prohibited.
- Signing requests require authenticated workload identity, explicit purpose, audience, rate/budget limits, operation ID, structured audit event and approval policy. Operators cannot silently change payload fields after approval.

### 4.2 Key identity and lifecycle

Key identity is immutable and never reused. Required lifecycle:

| State | Signing | Verification | Required behavior |
|---|---|---|---|
| GENERATED | Denied | Denied | Exists only in controlled provisioning workflow |
| PENDING | Denied | Denied | Public key awaits independent trust-bundle approval |
| ACTIVE | Allowed within exact purpose/profile | Allowed | Validity and trust-bundle freshness required |
| DEPRECATED_VERIFY_ONLY | Denied | Historical verification only | No new receipts or authorizations |
| REVOKED | Denied | Reject for admission; preserve forensic metadata | Terminal; never reactivate |
| DESTROYED | Denied | Historical verification only if public key retained and policy permits | Private-key destruction evidenced; cannot return to active |

Rotation uses a new key ID/version and a signed trust-bundle update. Any overlap window is explicit, bounded, purpose-specific and independently approved. The old key becomes verify-only after overlap and is revoked when compromise or policy requires. Revocation is terminal and takes precedence over cached validity. A compromised key cannot be made acceptable by extending validity or restoring an older trust bundle.

Historical forensic verification and current admission are separate decisions: an old signature may be cryptographically reproducible while ineligible for new admission because the key is revoked, the artifact expired, or the host epoch is stale.

### 4.3 Rotation and compromise response

The key incident runbook defines detection, signer disablement, root-authorized revocation statement, trust-bundle publication, cache invalidation, verifier refresh, affected artifact/epoch inventory, re-issuance policy, audit preservation, KMS/HSM outage recovery and external anti-rollback checkpoint update.

If key status, custody integrity, signer identity, revocation freshness or root availability is uncertain, deny new issuance and acceptance and quarantine affected hosts/authorizations. No fallback to an older key, cached positive status, alternate algorithm or unsigned mode is permitted.

## 5. Trust bundle and anti-rollback

A trust bundle is a signed, versioned, immutable artifact containing trust-bundle ID and strictly increasing generation; root identity/key version; environment, authority, purpose and protocol/profile allowlists; public keys and immutable IDs/versions; algorithms, validity intervals and status; revocation statements/effective times; issue/expiry times; previous-bundle digest; current-bundle digest; signature and independent verification metadata.

The verifier accepts only a root-authenticated bundle for the exact environment and purpose. It persists the highest independently witnessed generation and digest outside any guest snapshot or restorable application database. A restored guest, Neon snapshot, stale replica or copied trust cache cannot lower that checkpoint. Bundle rollback, missing predecessor link, revoked root, expired bundle, unavailable anti-rollback witness or inconsistent revocation state causes quarantine and denies admission.

The anti-rollback witness must be outside the same restore/failure domain as Neon, R2 object metadata and the guest. Its operator, storage, monotonicity, recovery and independent audit evidence remain unresolved gates; a database sequence alone is insufficient.

## 6. Verification procedure (fail closed)

For each host-epoch response, provider-fence attestation, trust bundle or Phase A authorization, the verifier must:

1. Resolve the exact immutable object version and verify byte length and SHA-256 against an independently recorded reference.
2. Strictly parse envelope/payload; reject duplicate keys, malformed UTF-8, unsupported critical fields, unknown profile, trailing bytes and non-canonical encoding.
3. Re-encode canonically and require exact byte equality; recompute and compare payload/evidence digests.
4. Resolve trust bundle from an independently pinned root and verify bundle signature, environment, purpose, generation, expiry and anti-rollback checkpoint.
5. Resolve exact key ID/version and require key type, algorithm, purpose, issuer, environment and protocol profile to match policy.
6. Verify signature over domain-separated canonical bytes using the approved library and pinned profile.
7. Check key validity and revocation using authoritative freshness rules; do not infer current validity from artifact issue time alone.
8. Check trusted-time evidence, not-before/expiry bounds and maximum clock uncertainty.
9. Compare audience, host enrollment, provider instance, epoch, operation ID, nonce/request/predecessor digests, fence evidence, qualification record and authorization scope with independently obtained request/authority/provider/ledger state.
10. Check replay tombstones, monotonic epoch, terminal revocation, run budget and exact immutable evidence versions.
11. Emit a signed or tamper-evident verification report with verifier identity/version, trust-bundle generation/digest, key ID/version, algorithm/profile, artifact digest, evidence references, decision, reason codes and trusted time.
12. Persist report and exact digest before caller treats verification as complete. Admission remains denied until separate host acceptance/readback and readiness requirements pass.

No verifier may return a boolean valid without recording artifact identity, trust context, policy version and reason. A successful signature check is necessary, never sufficient proof of fencing or safe execution.

## 7. Required negative and interoperability test vectors

Before runtime approval, publish deterministic, language-neutral vectors with canonical payload bytes, expected digest, public key, signature, profile, expected result and reason code. Use non-production keys and no private key material.

Positive vectors: valid host-epoch receipt and provider-fence attestation; valid Phase A authorization with exact host/epoch/review/qualification bindings; valid trust bundle and bounded key-rotation overlap; historical verify-only artifact accepted for audit but denied for admission.

Negative vectors must cover:
- one-byte payload/signature/evidence tamper;
- wrong key, key ID/version, issuer, audience, subject, provider instance or protocol domain;
- wrong algorithm, key-type mismatch, unsupported curve, malformed signature length and downgrade/fallback attempt;
- duplicate JSON keys, malformed UTF-8, non-canonical JSON, Unicode edge cases, ambiguous integer/number forms and invalid timestamps;
- detached signature swapped between otherwise valid payloads;
- nonce, operation ID, response ID or epoch replay; stale predecessor-set digest;
- expired/not-yet-valid artifact and excessive trusted-clock uncertainty;
- key revoked before verification, compromised root, stale/rolled-back bundle, missing revocation entry, unknown key and unavailable trust service;
- mismatched R2 object version, object digest, payload digest, manifest digest or evidence reference;
- unknown critical extension, cross-environment key, cross-purpose signature and domain-separation collision attempt;
- restored Neon/guest snapshot with lower generation or missing revocation tombstone;
- valid signature with provider-fence evidence absent, contradictory or independently unverifiable.

Tests run across the authority signer and at least two independently implemented verifiers where feasible. Cross-language vectors match byte-for-byte. Fuzzing supplements but does not replace fixed acceptance cases. Vector generation must not use the implementation under test as its only oracle.

## 8. Failure, availability and recovery behavior

| Failure | Required result |
|---|---|
| KMS/HSM unavailable or signing timeout | No new signature; reconcile by stable operation ID; uncertain outcome quarantined |
| Trust bundle unavailable, stale or expired | Deny new issuance/acceptance; no cached-positive fallback |
| Revocation service unavailable or freshness unknown | Deny admission and new authorization claims |
| Unknown key/profile/algorithm | Reject and audit; no negotiation or fallback |
| Signature or canonicalization failure | Reject, preserve bounded diagnostic evidence, quarantine relevant host/authorization |
| Clock source uncertain | No validity-window decision; remain quarantined |
| Verifier unavailable | No admission; retry same immutable artifact and operation ID only |
| Rotation partially committed | Treat as uncertain; require root-authorized reconciliation and external checkpoint |
| Key compromise suspected | Disable signer, publish revocation, identify affected artifacts, quarantine and independently re-issue under a new epoch/key after complete fencing |

Cleanup and termination controls remain locally available and independent of online trust services. Cryptographic outage may deny new privilege/admission; it must never prevent termination, cleanup, evidence finalization attempts or safe quarantine.

## 9. Evidence, audit and principal separation

Retain immutable references to key-generation/attestation ceremony, custody policy, signer workload identity, access policy, dual-control approvals, trust-bundle bytes/version/digest, revocation statements, KMS/HSM audit records, signing request/response digests, verifier build/profile, deterministic test vectors/results and anti-rollback witness checkpoints.

The evidence acquirer cannot be the independent verifier. The verifier cannot own the host, operate provider fencing, administer signing keys or author the security review being verified. Reviewer approval follows complete evidence acquisition and independent verification. Timestamps include source and uncertainty; logs never contain private key material or raw credentials.

## 10. Approval gates and explicit non-claims

Before implementation approval, independent reviewers must select and sign off: threat model/trust-domain ownership/principal separation; algorithm/profile and canonical encoding including runtime/HSM interoperability; cryptographic library versions and maintenance/security policy; root ceremony, custody, dual control, backup/recovery and destruction evidence; signed envelope schemas/domain-separation registry; trust-bundle distribution, revocation freshness and anti-rollback recovery; trusted-time source and uncertainty; deterministic cross-language vectors, negative tests, fuzzing and independent verifier; and operational compromise/rotation exercise with evidence retention.

No production key, migration, external authority, signer, verifier, provider adapter or host agent is implemented or approved here. No algorithm is selected until compatibility and custody reviews are complete. Synthetic validators prove only document linkage and required text; they do not perform cryptographic verification or establish provider fencing.

## 11. Related contracts

- docs/specifications/m0-authorization-lifecycle-and-recovery-contract.md
- docs/specifications/m0-authorization-ledger-data-model.md
- docs/specifications/m0-host-and-journal-qualification-protocol.md
- docs/security/m0-sandbox-security-review-packet.md

All four documents must remain aligned. Changes to key identity, algorithm, canonicalization, trust-bundle generation, revocation, evidence references or verifier policy require coordinated contract and validator updates.

## 12. Machine-readable schema and fixture contract

The proposed machine-readable artifacts are:
- docs/schemas/m0-crypto-signed-envelope.schema.json
- docs/schemas/m0-crypto-trust-bundle.schema.json
- docs/schemas/m0-crypto-key-metadata.schema.json
- docs/schemas/m0-crypto-verification-report.schema.json
- docs/schemas/m0-crypto-verification-fixture-catalog.json

Run scripts/validate_m0_crypto_contract.py for Draft 2020-12 schema meta-validation and structural positive/negative fixtures. These fixtures are contract-only: placeholder values do not represent real keys, signatures, cryptographic verification, trust-bundle authentication or provider fencing. Algorithm-specific known-answer vectors remain blocked until the algorithm/profile/library is independently approved.


## 13. Typed message payload contracts and fixture execution boundary

The signed-envelope contract now binds the following message families to strict, message-specific payload shapes:
- `host-epoch-response`: enrolled host, provider/account/region/instance identity, monotonic incarnation epoch, operation/response IDs, nonce/request/predecessor-set digests, exact fence-attestation reference/digest and authority observation time.
- `provider-fence-attestation`: exact provider resource and operation identity, predecessor instance/epoch, provider request/response IDs, declared fencing mechanism, terminal `FENCED` state, predecessor-set digest and immutable evidence reference/digest.
- `phase-a-authorization`: exact host epoch receipt and acceptance, independently verified fence report, host qualification record, 33-control security review with `FENCE-001=pass`, bounded run count and short validity window. The schema expressly denies Phase B, student and production execution.
- `key-revocation`: authority/key/version/purpose/environment, reason, effective time, trust-bundle generation, affected-artifact inventory and permanent no-reactivation rule.

The envelope contains the same conditional payload constraints inline so offline schema validation does not require network resolution of repository-relative references. The four standalone payload schemas remain the canonical independently reusable definitions; the validator checks their structure and the envelope's embedded equivalents.

The negative-fixture catalog now assigns an explicit execution disposition to all 20 required cases. Structural, parser, policy, chronology, binding, replay and fail-closed cases are exercised by the validator. Canonical-byte equivalence remains blocked because no canonicalization profile has been approved. The catalog deliberately does not claim signature verification or production cryptographic coverage.

These schemas are contract gates, not credentials or authority. A schema-valid Phase A payload is not a signed authorization, a valid signature is not provider-fence proof, and neither grants permission to run privileged or student workloads.


### Authorization scope and principal separation clarification

The message payload named `phase-a-authorization` is restricted to `M0_CLEANUP_CALIBRATION_ONLY`; it is not a general host-qualification, full-M0-proof, Phase B, student, or production grant. Its payload explicitly binds five distinct principals: host owner, evidence acquirer, fence verifier, independent security reviewer, and authorization signer. The structural validator rejects role collisions. This supplements, and does not replace, the role/evidence checks in the independent security-review record and cleanup-calibration authorization contract.


Typed payload schema artifacts:
- `docs/schemas/m0-host-epoch-response-payload.schema.json`
- `docs/schemas/m0-provider-fence-attestation-payload.schema.json`
- `docs/schemas/m0-phase-a-authorization-payload.schema.json`
- `docs/schemas/m0-key-revocation-payload.schema.json`
- `scripts/validate_m0_crypto_contract.py`


### Key lifecycle and trust-bundle transition contract

The append-only key lifecycle event schema is `docs/schemas/m0-crypto-key-lifecycle-event.schema.json`. It defines explicit generation, pending, activation, deprecation, revocation and destruction transitions. Revocation is terminal for signing and admission; a revoked key may never return to ACTIVE. Historical public-key verification is a separate, policy-bounded audit capability and does not restore signing authority.

Trust-bundle successors must increment generation by exactly one, bind the exact previous bundle digest, and preserve authority, root identity and environment. Revocation statements must identify an exact key ID/version and agree with that key's REVOKED status and revocation metadata. Duplicate key-version identities and duplicate revocation identities are rejected by semantic validation.

The ledger remains an application-side projection. An externally anchored anti-rollback checkpoint is required to detect Neon restore to an earlier event/revocation generation. A schema-valid event or bundle does not authenticate its signature or establish custody.


Key lifecycle event schema:
- `docs/schemas/m0-crypto-key-lifecycle-event.schema.json`
