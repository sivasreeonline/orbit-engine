#!/usr/bin/env python3
"""RFC 9162 Merkle inclusion/consistency proof reference model and fixture checks.

This is a deterministic proof-algorithm conformance harness only. It does not
authenticate signed tree heads, qualify a provider, prove monitor independence,
or authorize production witness use.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "docs/test-vectors/fence-witness-v1-004-merkle-transparency.json"
PROFILE = "sky-high-fence-witness-merkle-v1"
HASH_SIZE = 32


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_power_of_two_less_than(value: int) -> int:
    if value <= 1:
        raise ValueError("tree size must be greater than one")
    return 1 << ((value - 1).bit_length() - 1)


def merkle_tree_hash(entries: Sequence[bytes]) -> bytes:
    size = len(entries)
    if size == 0:
        return hashlib.sha256(b"").digest()
    if size == 1:
        return leaf_hash(entries[0])
    split = largest_power_of_two_less_than(size)
    return node_hash(
        merkle_tree_hash(entries[:split]),
        merkle_tree_hash(entries[split:]),
    )


def inclusion_proof(leaf_index: int, entries: Sequence[bytes]) -> list[bytes]:
    size = len(entries)
    if leaf_index < 0 or leaf_index >= size:
        raise ValueError("leaf index is outside the tree")
    if size == 1:
        return []
    split = largest_power_of_two_less_than(size)
    if leaf_index < split:
        return inclusion_proof(leaf_index, entries[:split]) + [
            merkle_tree_hash(entries[split:])
        ]
    return inclusion_proof(leaf_index - split, entries[split:]) + [
        merkle_tree_hash(entries[:split])
    ]


def verify_inclusion(
    leaf_index: int,
    tree_size: int,
    leaf_digest: bytes,
    root_digest: bytes,
    proof: Sequence[bytes],
) -> bool:
    if type(leaf_index) is not int or type(tree_size) is not int:
        return False
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if len(leaf_digest) != HASH_SIZE or len(root_digest) != HASH_SIZE:
        return False
    if any(len(item) != HASH_SIZE for item in proof):
        return False

    fn = leaf_index
    sn = tree_size - 1
    calculated = leaf_digest
    for sibling in proof:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            calculated = node_hash(sibling, calculated)
            if (fn & 1) == 0:
                while fn != 0 and (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            calculated = node_hash(calculated, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and calculated == root_digest


def consistency_subproof(
    first_size: int, entries: Sequence[bytes], complete_subtree_known: bool
) -> list[bytes]:
    second_size = len(entries)
    if first_size == second_size:
        return [] if complete_subtree_known else [merkle_tree_hash(entries)]
    split = largest_power_of_two_less_than(second_size)
    if first_size <= split:
        return consistency_subproof(
            first_size, entries[:split], complete_subtree_known
        ) + [merkle_tree_hash(entries[split:])]
    return consistency_subproof(
        first_size - split, entries[split:], False
    ) + [merkle_tree_hash(entries[:split])]


def consistency_proof(first_size: int, entries: Sequence[bytes]) -> list[bytes]:
    if type(first_size) is not int or not 0 < first_size < len(entries):
        raise ValueError("consistency proof requires 0 < first_size < second_size")
    return consistency_subproof(first_size, entries, True)


def verify_consistency(
    first_size: int,
    second_size: int,
    first_root: bytes,
    second_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    if type(first_size) is not int or type(second_size) is not int:
        return False
    if first_size <= 0 or second_size < first_size:
        return False
    if len(first_root) != HASH_SIZE or len(second_root) != HASH_SIZE:
        return False
    if any(len(item) != HASH_SIZE for item in proof):
        return False
    if first_size == second_size:
        return not proof and first_root == second_root
    if not proof:
        return False

    path = list(proof)
    if first_size & (first_size - 1) == 0:
        path.insert(0, first_root)

    fn = first_size - 1
    sn = second_size - 1
    if fn & 1:
        while fn & 1:
            fn >>= 1
            sn >>= 1

    first_calculated = path[0]
    second_calculated = path[0]
    for sibling in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            first_calculated = node_hash(sibling, first_calculated)
            second_calculated = node_hash(sibling, second_calculated)
            if (fn & 1) == 0:
                while fn != 0 and (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            second_calculated = node_hash(second_calculated, sibling)
        fn >>= 1
        sn >>= 1

    return (
        first_calculated == first_root
        and second_calculated == second_root
        and sn == 0
    )


def decode_path(path_hex: Sequence[str]) -> list[bytes]:
    result = [bytes.fromhex(item) for item in path_hex]
    if any(len(item) != HASH_SIZE for item in result):
        raise ValueError("every Merkle proof node must be exactly 32 bytes")
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_published_vector(vector: dict[str, Any]) -> tuple[list[bytes], dict[int, bytes]]:
    require(vector.get("testOnly") is True, "Merkle vector must be marked testOnly")
    require(vector.get("profile") == PROFILE, "unexpected Merkle proof profile")
    require(
        vector.get("algorithm")
        == {
            "tree": "RFC9162-MerkleTree",
            "hash": "SHA-256",
            "leafPrefixHex": "00",
            "nodePrefixHex": "01",
        },
        "unexpected Merkle tree algorithm parameters",
    )
    entries = [item.encode("utf-8") for item in vector["entriesUtf8"]]
    roots: dict[int, bytes] = {}
    for size_text, head in vector["treeHeads"].items():
        size = int(size_text)
        root = bytes.fromhex(head["rootHashHex"])
        require(head["treeSize"] == size, "tree-head size key mismatch")
        require(len(root) == HASH_SIZE, "tree-head root must be 32 bytes")
        require(merkle_tree_hash(entries[:size]) == root, f"tree head {size}: root mismatch")
        roots[size] = root

    for item in vector["inclusionProofs"]:
        size = item["treeSize"]
        index = item["leafIndex"]
        leaf = item["leafUtf8"].encode("utf-8")
        proof = decode_path(item["pathHex"])
        require(leaf == entries[index], "inclusion vector leaf does not match ordered entry")
        require(
            verify_inclusion(index, size, leaf_hash(leaf), roots[size], proof),
            f"inclusion proof failed for leaf {index} in tree {size}",
        )
        require(
            proof == inclusion_proof(index, entries[:size]),
            f"inclusion proof is not the deterministic minimal path for leaf {index}",
        )

    for item in vector["consistencyProofs"]:
        first = item["firstTreeSize"]
        second = item["secondTreeSize"]
        proof = decode_path(item["pathHex"])
        require(
            verify_consistency(first, second, roots[first], roots[second], proof),
            f"consistency proof failed for {first} -> {second}",
        )
        require(
            proof == consistency_proof(first, entries[:second]),
            f"consistency proof is not the deterministic minimal path for {first} -> {second}",
        )
    return entries, roots


def run_negative_cases(entries: list[bytes], roots: dict[int, bytes]) -> int:
    inclusion = inclusion_proof(3, entries)
    altered = list(inclusion)
    altered[0] = bytes([altered[0][0] ^ 1]) + altered[0][1:]
    require(
        not verify_inclusion(3, 7, leaf_hash(entries[3]), roots[7], altered),
        "altered inclusion node was accepted",
    )
    require(
        not verify_inclusion(3, 7, leaf_hash(b"substituted-checkpoint"), roots[7], inclusion),
        "substituted checkpoint leaf was accepted",
    )
    require(
        not verify_inclusion(7, 7, leaf_hash(entries[0]), roots[7], inclusion),
        "out-of-range inclusion index was accepted",
    )
    require(
        not verify_inclusion(3, 7, leaf_hash(entries[3]), roots[7], inclusion[:-1]),
        "truncated inclusion proof was accepted",
    )
    require(
        not verify_inclusion(3, 7, leaf_hash(entries[3]), roots[7], inclusion + [b"x" * 32]),
        "overlong inclusion proof was accepted",
    )

    consistency = consistency_proof(3, entries)
    altered_consistency = list(consistency)
    altered_consistency[0] = bytes([altered_consistency[0][0] ^ 1]) + altered_consistency[0][1:]
    require(
        not verify_consistency(3, 7, roots[3], roots[7], altered_consistency),
        "altered consistency node was accepted",
    )
    require(
        not verify_consistency(3, 7, bytes([roots[3][0] ^ 1]) + roots[3][1:], roots[7], consistency),
        "substituted old tree head was accepted",
    )
    require(
        not verify_consistency(3, 7, roots[3], roots[7], consistency[:-1]),
        "truncated consistency proof was accepted",
    )
    require(
        not verify_consistency(3, 7, roots[3], roots[7], consistency + [b"x" * 32]),
        "overlong consistency proof was accepted",
    )
    require(
        not verify_consistency(7, 3, roots[7], roots[3], []),
        "reversed tree sizes were accepted",
    )
    require(
        not verify_consistency(7, 7, roots[7], bytes([roots[7][0] ^ 1]) + roots[7][1:], []),
        "same-size conflicting roots were accepted",
    )

    forked_entries = list(entries)
    forked_entries[1] = b"forked-checkpoint-01"
    forked_root = merkle_tree_hash(forked_entries)
    require(
        not verify_consistency(3, 7, roots[3], forked_root, consistency),
        "a rewritten prefix was accepted as an append-only extension",
    )
    return 11


def exhaustive_model_checks(max_size: int = 40) -> tuple[int, int]:
    inclusion_count = 0
    consistency_count = 0
    for size in range(1, max_size + 1):
        entries = [f"model-checkpoint-{index:03d}".encode("utf-8") for index in range(size)]
        root = merkle_tree_hash(entries)
        for index, entry in enumerate(entries):
            proof = inclusion_proof(index, entries)
            require(
                verify_inclusion(index, size, leaf_hash(entry), root, proof),
                f"generated inclusion proof failed at index={index}, size={size}",
            )
            inclusion_count += 1
        for first in range(1, size):
            proof = consistency_proof(first, entries)
            require(
                verify_consistency(first, size, merkle_tree_hash(entries[:first]), root, proof),
                f"generated consistency proof failed at {first} -> {size}",
            )
            consistency_count += 1
    return inclusion_count, consistency_count


def main() -> None:
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    entries, roots = validate_published_vector(vector)
    negative_count = run_negative_cases(entries, roots)
    inclusion_count, consistency_count = exhaustive_model_checks()
    print("FENCE-001 RFC 9162 Merkle proof model: PASS")
    print(f"Published vector: {len(entries)} leaves, {len(vector['inclusionProofs'])} inclusion proofs, {len(vector['consistencyProofs'])} consistency proofs")
    print(f"Negative proof cases: {negative_count}")
    print(f"Exhaustive generated checks: {inclusion_count} inclusion, {consistency_count} consistency")
    print("Scope: proof mathematics only; STH signatures, provider semantics, monitor independence and production qualification remain external")


if __name__ == "__main__":
    main()
