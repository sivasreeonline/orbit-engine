# FENCE-001 provider-neutral authority conformance model

**Status:** Synthetic reference model and test contract only.  
**Scope:** Deterministic checks for authority-side epoch issuance, retry identity, compare-and-swap serialization, exact response acceptance, and stale-state detection.  
**Safety:** This is not an authority implementation, provider integration, cryptographic verifier, database test, or qualification result. It does not authorize privileged implementation, Phase A, Phase B, student execution, or production execution.

## Required invariants

1. **Monotonic issuance:** a newly committed successor epoch is exactly the current epoch plus one in this reference model; the production contract requires strictly increasing epochs.
2. **Nonce idempotency:** the same nonce digest and same request digest return byte-identical previously committed response bytes after a lost acknowledgement. They never allocate a second epoch.
3. **Nonce collision rejection:** the same nonce digest with a different request digest is a hard conflict.
4. **Operation identity:** an operation ID cannot be reused with changed request content or silently rebound to a different nonce.
5. **Compare-and-swap:** every new issuance checks the expected host-record version. A stale writer conflicts.
6. **Single pending successor:** a second successor cannot issue while the prior response is pending durable acceptance. A new issuance also requires a newly confirmed predecessor-fence input and a predecessor set whose maximum epoch equals the current authority epoch.
7. **Exact acceptance:** acceptance is bound to exact response bytes, provider instance identity, and epoch. Repeated acceptance of the same bytes is idempotent.
8. **Anti-rollback:** restoring an older authority snapshot while an independent checkpoint remains current is detected and denied.

## Deterministic model

Run:

```bash
python scripts/validate_m0_fence_authority_conformance.py
```

The synthetic fixture exercises lost acknowledgement and exact-byte retry, nonce/request mismatch, operation-ID collision, pending-successor contention, missing fence confirmation, stale compare-and-swap, response alteration, wrong target instance, idempotent acceptance, monotonic next epoch, and restoration of a stale authority snapshot.

The model's `synthetic_fence_confirmed` input is an untrusted test switch, not evidence. Its in-memory anti-rollback anchor is a test double, not an external witness or independently administered checkpoint. It does not test true concurrent transactions, crash consistency, provider APIs, predecessor discovery, compute/storage/control-path isolation, signatures, key rotation, durable response delivery, or real anti-rollback storage.

A passing run is limited to reference-state-machine behavior. Provider-specific qualification still requires controlled concurrency/replay/rollback tests, independently acquired provider and authority records, authenticated evidence, durable transactional storage, and independent review under the FENCE-001 and authorization lifecycle contracts.
