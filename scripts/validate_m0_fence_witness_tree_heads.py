#!/usr/bin/env python3
"""Signed FENCE-001 tree-head verifier; synthetic fixtures only."""
from __future__ import annotations
import base64, hashlib, json, sys
from datetime import datetime, timezone
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
import validate_m0_fence_witness_profile as receipt_profile
import validate_m0_fence_witness_merkle_proofs as merkle

ROOT=Path(__file__).resolve().parents[1]
PREFIX=b"SKYHIGH-FENCE-001-WITNESS-TREE-HEAD-V1\x00"
TRUST_VECTOR=ROOT/"docs/test-vectors/fence-witness-v1-003-trust-bundle.json"
RECEIPT_VECTOR=ROOT/"docs/test-vectors/fence-witness-v1-001.json"
def b64(data): return base64.urlsafe_b64encode(data).decode().rstrip("=")
def raw_public(key): return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def key_id(key): return hashlib.sha256(raw_public(key)).hexdigest()
def parse_time(s): return datetime.fromisoformat(s.replace("Z","+00:00"))
def require(ok,msg):
    if not ok: raise AssertionError(msg)

def sign_tree_head(body, signer):
    return {"body":body,"signature":b64(signer.sign(PREFIX+rfc8785.dumps(body)))}

def verify_tree_head(envelope, trust_body, trusted_time, expected_scope):
    schema=json.loads((ROOT/"docs/schemas/m0-fence-witness-v1.schema.json").read_text())
    errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(envelope))
    if errors: raise ValueError("tree-head envelope schema invalid: "+errors[0].message)
    body=envelope["body"]
    if body["profile"]!="sky-high-fence-witness-merkle-v1" or body["schemaVersion"]!=1: raise ValueError("tree-head profile/version mismatch")
    if body["treeSize"]<=0: raise ValueError("tree size must be positive")
    if len(bytes.fromhex(body["rootHash"]))!=32: raise ValueError("root hash must be 32 bytes")
    if (body["witnessId"],body["authorityId"],body["hostId"])!=expected_scope: raise ValueError("tree-head scope substitution")
    keys=[k for k in trust_body["keys"] if k["keyId"]==body["keyId"]]
    if len(keys)!=1: raise ValueError("tree-head signing key missing or ambiguous")
    key=keys[0]
    if key["purpose"]!="WITNESS_LOG_SIGNING": raise ValueError("tree-head key has wrong purpose")
    if key["witnessId"]!=body["witnessId"] or body["authorityId"] not in key["authorityIds"]: raise ValueError("tree-head key scope mismatch")
    head_time=parse_time(body["timestamp"])
    if not (parse_time(key["notBefore"])<=head_time<parse_time(key["notAfter"])): raise ValueError("tree-head timestamp outside key validity")
    if head_time>trusted_time: raise ValueError("tree-head timestamp is in the future relative to trusted time")
    if not (parse_time(key["notBefore"])<=trusted_time<parse_time(key["notAfter"])): raise ValueError("trusted time outside key validity")
    if "retiredAt" in key and trusted_time>=parse_time(key["retiredAt"]): raise ValueError("tree-head key retired")
    if any(r["keyId"]==body["keyId"] for r in trust_body["revocations"]): raise ValueError("tree-head key revoked")
    pub=receipt_profile.decode_canonical_base64url(key["publicKeyBase64Url"])
    if hashlib.sha256(pub).hexdigest()!=key["keyId"]: raise ValueError("tree-head key fingerprint mismatch")
    sig=receipt_profile.decode_canonical_base64url(envelope["signature"])
    if len(sig)!=64: raise ValueError("tree-head signature length invalid")
    Ed25519PublicKey.from_public_bytes(pub).verify(sig,PREFIX+rfc8785.dumps(body))
    return body

def verify_receipt_inclusion(receipt_envelope, index, tree_head, proof_hex):
    # Leaf is the complete canonical signed receipt envelope, not its body or an opaque token.
    receipt_body=receipt_envelope["body"]
    if (receipt_body["witnessId"],receipt_body["authorityId"],receipt_body["hostId"]) != (tree_head["witnessId"],tree_head["authorityId"],tree_head["hostId"]): raise ValueError("receipt/tree-head scope mismatch")
    leaf=merkle.leaf_hash(rfc8785.dumps(receipt_envelope))
    proof=[bytes.fromhex(x) for x in proof_hex]
    root=bytes.fromhex(tree_head["rootHash"])
    if not merkle.verify_inclusion(index,tree_head["treeSize"],leaf,root,proof):
        raise ValueError("receipt inclusion proof invalid")
    return leaf

def verify_head_extension(prior, current, proof_hex):
    old_size, new_size=prior["treeSize"],current["treeSize"]
    if (prior["witnessId"],prior["authorityId"],prior["hostId"],prior["logId"]) != (current["witnessId"],current["authorityId"],current["hostId"],current["logId"]): raise ValueError("tree-head log/scope substitution")
    if new_size<old_size: raise ValueError("tree-size rollback")
    proof=[bytes.fromhex(x) for x in proof_hex]
    if not merkle.verify_consistency(old_size,new_size,bytes.fromhex(prior["rootHash"]),bytes.fromhex(current["rootHash"]),proof):
        raise ValueError("tree-head consistency proof invalid")
    return True

def main():
    trust_vector=json.loads(TRUST_VECTOR.read_text())
    root=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(trust_vector["testRootKey"]["privateSeedHex"]))
    root_pub=raw_public(root); root_id=hashlib.sha256(root_pub).hexdigest()
    gen1=trust_vector["generation1"]
    body=json.loads(json.dumps(gen1["body"]))
    receipt_key=body["keys"][0]
    log_signer=Ed25519PrivateKey.from_private_bytes(bytes.fromhex("a1"*32))
    log_pub=raw_public(log_signer); log_id=hashlib.sha256(log_pub).hexdigest()
    body["keys"].append({"keyId":log_id,"publicKeyBase64Url":b64(log_pub),"purpose":"WITNESS_LOG_SIGNING","witnessId":body["witnessId"],"authorityIds":["authority-vector-01"],"notBefore":"2026-01-01T00:00:00Z","notAfter":"2030-01-01T00:00:00Z"})
    bundle=receipt_profile.sign_trust_bundle(body,root)
    receipt_profile.verify_trust_bundle_envelope(bundle,{root_id:root_pub},0,"0"*64,body["trustDomainId"],body["witnessId"])
    receipt=json.loads(RECEIPT_VECTOR.read_text())
    receipt_envelope={"body":receipt["receiptBody"],"signature":receipt["signatureBase64Url"]}
    # Verify the receipt signature and binding using the pre-existing validator.
    vector_result={"checkpointBody":receipt["checkpointBody"],"checkpointDigest":receipt["checkpointDigest"],"receiptBody":receipt["receiptBody"],"signatureBase64Url":receipt["signatureBase64Url"]}
    now=datetime(2026,1,2,3,5,1,tzinfo=timezone.utc)
    receipt_profile.verify_receipt_against_trusted_bundle(vector_result,body,now)
    leaf_bytes=rfc8785.dumps(receipt_envelope)
    second_leaf=b"synthetic second receipt envelope"
    entries=[leaf_bytes,second_leaf]
    root_hash=merkle.merkle_tree_hash(entries).hex()
    head_body={"profile":"sky-high-fence-witness-merkle-v1","schemaVersion":1,"witnessId":body["witnessId"],"authorityId":"authority-vector-01","hostId":receipt["receiptBody"]["hostId"],"logId":"synthetic-log-01","treeSize":2,"rootHash":root_hash,"timestamp":"2026-01-02T03:05:00Z","keyId":log_id}
    envelope=sign_tree_head(head_body,log_signer)
    verified=verify_tree_head(envelope,body,now,(body["witnessId"],"authority-vector-01",receipt["receiptBody"]["hostId"]))
    verify_receipt_inclusion(receipt_envelope,0,verified,[x.hex() for x in merkle.inclusion_proof(0,entries)])
    prior_entries=entries[:1]
    prior_body={**head_body,"treeSize":1,"rootHash":merkle.merkle_tree_hash(prior_entries).hex()}
    prior=verify_tree_head(sign_tree_head(prior_body,log_signer),body,now,(body["witnessId"],"authority-vector-01",receipt["receiptBody"]["hostId"]))
    verify_head_extension(prior,verified,[x.hex() for x in merkle.consistency_proof(1,entries)])
    # Negative security cases.
    cases=[]
    bad={**envelope,"signature":b64(b"\\x00"*64)}
    try: verify_tree_head(bad,body,now,(body["witnessId"],"authority-vector-01",receipt["receiptBody"]["hostId"]))
    except (ValueError,InvalidSignature): cases.append("bad signature")
    else: raise AssertionError("bad STH signature accepted")
    wrong_purpose=json.loads(json.dumps(body)); wrong_purpose["keys"][1]["purpose"]="WITNESS_RECEIPT_SIGNING"
    try: verify_tree_head(envelope,wrong_purpose,now,(body["witnessId"],"authority-vector-01",receipt["receiptBody"]["hostId"]))
    except ValueError: cases.append("wrong key purpose")
    else: raise AssertionError("receipt key accepted for STH")
    wrong_scope=(body["witnessId"],"other-authority",receipt["receiptBody"]["hostId"])
    try: verify_tree_head(envelope,body,now,wrong_scope)
    except ValueError: cases.append("wrong authority scope")
    else: raise AssertionError("wrong STH scope accepted")
    try: verify_head_extension({**prior,"treeSize":3},verified,[])
    except ValueError: cases.append("tree-size rollback")
    else: raise AssertionError("tree-size rollback accepted")
    try: verify_receipt_inclusion(receipt_envelope,0,verified,[])
    except ValueError: cases.append("invalid inclusion proof")
    else: raise AssertionError("invalid inclusion proof accepted")
    print("FENCE-001 signed tree-head integration: PASS")
    print("Reused: root-signed trust bundle, receipt verifier, RFC 9162 proof functions")
    print("Positive: signed STH, full-envelope receipt inclusion, prior-head consistency")
    print("Negative cases: "+", ".join(cases))
    print("Scope: deterministic synthetic keys only; no provider durability or anti-equivocation qualification")

if __name__=="__main__": main()
