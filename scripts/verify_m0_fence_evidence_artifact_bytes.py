#!/usr/bin/env python3
"""Verify materialized evidence bytes against a dual-signed FENCE-001 manifest.

This proves only that the local files inspected at verification time match the
signed manifest's digest and byte count. It does not prove remote object-lock,
retention, origin authenticity or provider-side immutability.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import tempfile
from typing import Any

from validate_m0_fence_evidence_manifest import (
    ROOT,
    load_json,
    validate_manifest,
)


FIXTURE_ARTIFACT = b"synthetic provider evidence fixture only\n"


def verify_artifact_files(body: dict[str, Any], artifact_root: Path) -> int:
    root = artifact_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("artifact root must be a directory")

    verified = 0
    for artifact in body["artifacts"]:
        artifact_id = artifact["artifactId"]
        if not artifact_id or artifact_id in (".", "..") or any(char in artifact_id for char in ("/", "\\", "\x00")):
            raise ValueError("artifact ID is not a safe local filename")
        candidate = root / artifact_id
        if candidate.is_symlink():
            raise ValueError(f"{artifact_id}: symlink evidence files are not accepted")
        resolved = candidate.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError(f"{artifact_id}: evidence path escapes artifact root")
        if not resolved.is_file():
            raise ValueError(f"{artifact_id}: evidence artifact is not a regular file")

        digest = hashlib.sha256()
        byte_count = 0
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
        if digest.hexdigest() != artifact["sha256"]:
            raise ValueError(f"{artifact_id}: materialized evidence SHA-256 mismatch")
        if byte_count != artifact["byteCount"]:
            raise ValueError(f"{artifact_id}: materialized evidence byte count mismatch")
        verified += 1
    return verified


def run_fixture_tests() -> tuple[int, int]:
    vector = load_json(ROOT / "docs/test-vectors/m0-fence-evidence-manifest-v1.json")
    body = vector["manifestBody"]
    with tempfile.TemporaryDirectory(prefix="fence-evidence-") as directory:
        root = Path(directory)
        (root / "artifact-001").write_bytes(FIXTURE_ARTIFACT)
        require_count = verify_artifact_files(body, root)
        if require_count != 1:
            raise AssertionError("fixture artifact was not verified")

        (root / "artifact-001").write_bytes(FIXTURE_ARTIFACT + b"tamper")
        try:
            verify_artifact_files(body, root)
        except ValueError as error:
            if "SHA-256 mismatch" not in str(error):
                raise
        else:
            raise AssertionError("tampered artifact bytes were accepted")

        (root / "artifact-001").write_bytes(FIXTURE_ARTIFACT)
        (root / "artifact-001").unlink()
        try:
            verify_artifact_files(body, root)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing artifact was accepted")
    return require_count, 2


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, help="dual-signed evidence manifest envelope JSON")
    parser.add_argument("--trusted-keys", type=Path, help="independently governed trusted-key configuration JSON")
    parser.add_argument("--artifact-root", type=Path, help="directory containing materialized files named by artifactId")
    args = parser.parse_args()
    supplied = (args.manifest, args.trusted_keys, args.artifact_root)
    if any(supplied) and not all(supplied):
        parser.error("--manifest, --trusted-keys and --artifact-root must be supplied together")

    if all(supplied):
        envelope = load_json(args.manifest)
        trust = load_json(args.trusted_keys)
        if not isinstance(trust.get("keys"), list):
            raise SystemExit("trusted-key document must contain a keys array")
        digest = validate_manifest(envelope, trust["keys"], allow_test_only=False)
        count = verify_artifact_files(envelope["manifestBody"], args.artifact_root)
        print(f"Evidence manifest signature verification: PASS ({digest})")
        print(f"Materialized evidence artifacts byte-verified: {count}")
        print("Remote immutability and provider-origin claims remain separate qualification evidence")
        return

    vector = load_json(ROOT / "docs/test-vectors/m0-fence-evidence-manifest-v1.json")
    verified, rejected = run_fixture_tests()
    print("FENCE-001 evidence artifact byte verifier: PASS")
    print(f"Fixture artifacts byte-verified: {verified}")
    print(f"Negative cases rejected: {rejected} (tampered bytes, missing artifact)")
    print("Scope: synthetic fixture only; no provider evidence or remote immutability proof")


if __name__ == "__main__":
    main()
