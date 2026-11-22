#!/usr/bin/env python3
"""Synthetic durable-checkpoint integration tests for rooted FENCE-001 bundles."""
from __future__ import annotations
import base64, copy, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785
from verify_m0_fence_rooted_trust_bundle import SIGNATURE_PREFIX
from validate_m0_fence_provider_trust_bundle_checkpoint import CheckpointAcceptanceError, accept_trust_bundle_checkpoint
from validate_m0_witness_provider_adapter_conformance import AppendConflict, ZERO_DIGEST, LoseAcknowledgementOnce, load_adapter_factory

def sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()

def make_bundle(generation, predecessor, root, keys, created_at="2026-11-01T00:00:00Z"):
    body={"profile":"sky-high-fence-manifest-trust-bundle-v1","schemaVersion":1,
      "trustDomainId":"checkpoint-test-domain","generation":generation,
      "previousBundleDigest":predecessor,"createdAt":created_at,"keys":keys,"revocations":[]}
    canonical=rfc8785.dumps(body)
    public=root.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
    return {"body":body,"bundleDigest":sha(canonical),"rootKeyId":sha(public),
      "rootSignature":base64.urlsafe_b64encode(root.sign(SIGNATURE_PREFIX+canonical)).decode().rstrip("=")}, {sha(public):public}

def main():
    collector, verifier, root = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys=[]
    for role,identity,key in (("COLLECTOR","collector-identity",collector),("INDEPENDENT_VERIFIER","verifier-identity",verifier)):
        raw=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
        keys.append({"keyId":sha(raw),"identity":identity,"role":role,
          "publicKeyBase64Url":base64.urlsafe_b64encode(raw).decode().rstrip("="),
          "notBefore":"2026-01-01T00:00:00Z","notAfter":"2027-01-01T00:00:00Z",
          "approvedBy":"synthetic-governance","approvalReference":"FIXTURE-APPROVAL"})
    manifest={"manifestBody":{"createdAt":"2026-11-20T00:00:00Z"},"attestations":[
      {"role":"COLLECTOR","keyId":keys[0]["keyId"],"signerIdentity":keys[0]["identity"]},
      {"role":"INDEPENDENT_VERIFIER","keyId":keys[1]["keyId"],"signerIdentity":keys[1]["identity"]}]}
    first,roots=make_bundle(1,ZERO_DIGEST,root,keys)
    adapter_factory, adapter_kind=load_adapter_factory()
    adapter=adapter_factory()
    def accept(bundle):
        return accept_trust_bundle_checkpoint(adapter,bundle,roots,manifest=manifest,
          trust_domain_id="checkpoint-test-domain",witness_id="test-witness",authority_id="test-authority",host_id="test-host")
    assert accept(first)["status"]=="ACCEPTED"
    assert accept(first)["status"]=="ALREADY_ACCEPTED"
    # Reconstruct an adapter over the same durable table to model process restart.
    if hasattr(adapter, "_client") and hasattr(adapter, "_table_name"):
        restarted=type(adapter)(adapter._client, adapter._table_name)
        restarted_result=accept_trust_bundle_checkpoint(restarted,first,roots,manifest=manifest,
          trust_domain_id="checkpoint-test-domain",witness_id="test-witness",authority_id="test-authority",host_id="test-host")
        assert restarted_result["status"]=="ALREADY_ACCEPTED"
        print("PASS checkpoint and receipt survive adapter reconstruction")
    # Inject response loss after provider commit; exact operation lookup must recover it.
    recovery_adapter=LoseAcknowledgementOnce(adapter_factory())
    recovered=accept_trust_bundle_checkpoint(recovery_adapter,first,roots,manifest=manifest,
      trust_domain_id="checkpoint-test-domain",witness_id="recovery-witness",authority_id="test-authority",host_id="test-host")
    assert recovered["status"]=="ACCEPTED"
    assert accept_trust_bundle_checkpoint(recovery_adapter,first,roots,manifest=manifest,
      trust_domain_id="checkpoint-test-domain",witness_id="recovery-witness",authority_id="test-authority",host_id="test-host")["status"]=="ALREADY_ACCEPTED"
    print("PASS lost acknowledgement recovers exact committed receipt without duplicate append")
    tampered=copy.deepcopy(first)
    tampered["body"]["trustDomainId"]="attacker-domain"
    try: accept(tampered)
    except ValueError as error: assert "digest mismatch" in str(error) or "trust-domain substitution" in str(error)
    else: raise AssertionError("tampered replay bypassed root signature verification")
    print("PASS root-verified trust bundle is checkpointed, exact retry is idempotent, and tampered replay is rejected")
    second,_=make_bundle(2,first["bundleDigest"],root,keys)
    assert accept(second)["generation"]==2
    print("PASS successor requires exact durable generation and predecessor")
    try: accept(first)
    except CheckpointAcceptanceError as error: assert "no longer the current high-water" in str(error)
    else: raise AssertionError("old checkpoint replay after successor was accepted")
    print("PASS old replay is rejected after a successor advances the high-water")
    fork,_=make_bundle(3,first["bundleDigest"],root,keys)
    try: accept(fork)
    except ValueError as error: assert "generation rollback or gap" in str(error) or "predecessor fork" in str(error)
    else: raise AssertionError("forked successor was accepted")
    print("PASS forked or gapped successor is rejected")
    a,_=make_bundle(3,second["bundleDigest"],root,keys)
    b,_=make_bundle(3,second["bundleDigest"],root,keys,created_at="2026-11-02T00:00:00Z")
    outcomes=[]
    for candidate in (a,b):
        try: outcomes.append(accept(candidate)["status"])
        except (AppendConflict, ValueError): outcomes.append("CONFLICT")
    assert outcomes.count("ACCEPTED")==1 and outcomes.count("CONFLICT")==1, outcomes
    print("PASS competing successor candidates cannot both advance the durable head")
    print(f"Durable trust-bundle checkpoint integration tests passed using {adapter_kind}; no live provider was called.")

if __name__=="__main__": main()
