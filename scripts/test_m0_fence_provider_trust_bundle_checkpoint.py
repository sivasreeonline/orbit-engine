#!/usr/bin/env python3
"""Synthetic durable-checkpoint integration tests for rooted FENCE-001 bundles."""
from __future__ import annotations
import base64, hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rfc8785
from validate_m0_fence_rooted_trust_bundle import SIGNATURE_PREFIX
from validate_m0_fence_provider_trust_bundle_checkpoint import CheckpointAcceptanceError, accept_trust_bundle_checkpoint
from validate_m0_witness_provider_adapter_conformance import AppendConflict, InMemoryWitnessAdapter, ZERO_DIGEST

def sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()

def make_bundle(generation, predecessor, root, keys):
    body={"profile":"sky-high-fence-manifest-trust-bundle-v1","schemaVersion":1,
      "trustDomainId":"checkpoint-test-domain","generation":generation,
      "previousBundleDigest":predecessor,"createdAt":"2026-11-01T00:00:00Z","keys":keys,"revocations":[]}
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
    adapter=InMemoryWitnessAdapter()
    def accept(bundle):
        return accept_trust_bundle_checkpoint(adapter,bundle,roots,manifest=manifest,
          trust_domain_id="checkpoint-test-domain",witness_id="test-witness",authority_id="test-authority",host_id="test-host")
    assert accept(first)["status"]=="ACCEPTED"
    assert accept(first)["status"]=="ALREADY_ACCEPTED"
    print("PASS root-verified trust bundle is checkpointed and exact retry is idempotent")
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
    b,_=make_bundle(3,second["bundleDigest"],root,keys)
    outcomes=[]
    for candidate in (a,b):
        try: outcomes.append(accept(candidate)["status"])
        except AppendConflict: outcomes.append("CONFLICT")
    assert outcomes.count("ACCEPTED")==1 and outcomes.count("CONFLICT")==1
    print("PASS competing successors produce one CAS winner and one conflict")
    print("Synthetic durable trust-bundle checkpoint tests passed; no live provider was called.")

if __name__=="__main__": main()
