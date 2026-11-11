#!/usr/bin/env python3
"""Validate immutable upstream source pins used by ADR-0019.

This verifies the committed manifest structure and cross-references. It does
not make network requests or independently re-fetch upstream content.
"""
from datetime import date
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/adr/ADR-0019-upstream-source-manifest.json"
SCHEMA_PATH = ROOT / "docs/schemas/ADR-0019-upstream-source-manifest.schema.json"
LEDGER_PATH = ROOT / "docs/adr/ADR-0019-upstream-compatibility-evidence.md"
DOSSIER_PATH = ROOT / "docs/adr/ADR-0019-decision-dossier.md"
ADR_PATH = ROOT / "docs/adr/ADR-0019-m0-host-launch-boundary.md"
SECURITY_PATH = ROOT / "docs/security/m0-sandbox-security-review-packet.md"
QUALIFICATION_PATH = ROOT / "docs/specifications/m0-host-and-journal-qualification-protocol.md"
CHECKLIST_PATH = ROOT / "docs/security/m0-independent-security-review-checklist.md"
WORKFLOW_PATH = ROOT / ".github/workflows/m0-preflight-ci.yml"
EXPECTED = {
    "gvisor-rootless": ("google/gvisor", "g3doc/user_guide/rootless.md"),
    "gvisor-containerd": ("google/gvisor", "g3doc/user_guide/containerd/quick_start.md"),
    "gvisor-platforms": ("google/gvisor", "g3doc/user_guide/platforms.md"),
    "gvisor-networking": ("google/gvisor", "g3doc/user_guide/networking.md"),
    "gvisor-install": ("google/gvisor", "g3doc/user_guide/install.md"),
    "containerd-rootless": ("containerd/containerd", "docs/rootless.md"),
    "rootlesskit-v3.3.0": ("rootless-containers/rootlesskit", "README.md"),
    "runc-cgroup": ("opencontainers/runc", "docs/cgroup-v2.md"),
}

def main():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    ledger = LEDGER_PATH.read_text(encoding="utf-8")
    linked_docs = [
        DOSSIER_PATH.read_text(encoding="utf-8"),
        ADR_PATH.read_text(encoding="utf-8"),
        SECURITY_PATH.read_text(encoding="utf-8"),
        QUALIFICATION_PATH.read_text(encoding="utf-8"),
        CHECKLIST_PATH.read_text(encoding="utf-8"),
    ]
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [error.message for error in validator.iter_errors(manifest)]
    if errors:
        raise AssertionError("upstream source manifest schema invalid: " + "; ".join(errors))

    entries = manifest["entries"]
    ids = [entry["source_id"] for entry in entries]
    if len(ids) != len(set(ids)) or set(ids) != set(EXPECTED):
        raise AssertionError("source manifest must include each of the eight expected source IDs exactly once")
    by_id = {entry["source_id"]: entry for entry in entries}
    for source_id, (repository, path) in EXPECTED.items():
        entry = by_id[source_id]
        if entry["repository"] != repository or entry["path"] != path:
            raise AssertionError(f"{source_id}: repository/path mismatch")
        expected_url = f"https://github.com/{repository}/blob/{entry['commit_sha']}/{path}"
        if entry["immutable_file_url"] != expected_url:
            raise AssertionError(f"{source_id}: immutable URL is not pinned to the recorded commit")
        if entry["blob_sha1"] == entry["commit_sha"]:
            raise AssertionError(f"{source_id}: file blob SHA-1 must not be confused with repository commit SHA")
        if entry["content_byte_length"] <= 0:
            raise AssertionError(f"{source_id}: content length must be positive")
        if entry["source_id"] == "rootlesskit-v3.3.0":
            if entry["source_ref"] != "v3.3.0" or entry["commit_signature_status"] != "verified":
                raise AssertionError("RootlessKit v3.3.0 must be represented by its verified release commit")
        if entry["commit_signature_status"] == "verified" and entry["commit_signature_reason"] not in {"valid", "verified"}:
            raise AssertionError(f"{source_id}: verified commit must record a valid verification result")
        if entry["immutable_file_url"] not in ledger:
            raise AssertionError(f"{source_id}: immutable source URL missing from compatibility ledger")
    try:
        reviewed_on = date.fromisoformat(manifest["reviewed_on"])
    except (TypeError, ValueError) as exc:
        raise AssertionError("manifest reviewed_on must be a valid ISO date") from exc
    if reviewed_on > date(2026, 11, 10):
        raise AssertionError("manifest review date is in the future relative to this capture")
    if "ADR-0019-upstream-source-manifest.json" not in ledger:
        raise AssertionError("compatibility ledger must link the source manifest")
    for index, content in enumerate(linked_docs):
        if "ADR-0019-upstream-source-manifest.json" not in content:
            raise AssertionError(f"review document {index + 1} must link the source manifest")
    if "validate_m0_upstream_source_manifest.py" not in workflow:
        raise AssertionError("M0 workflow must execute the upstream source manifest validator")
    mutable_patterns = [
        "https://gvisor.dev/docs/",
        "github.com/google/gvisor/blob/main/",
        "github.com/google/gvisor/blob/master/",
        "github.com/containerd/containerd/blob/main/",
        "github.com/rootless-containers/rootlesskit/blob/master/",
        "github.com/opencontainers/runc/blob/main/",
    ]
    if any(pattern in ledger for pattern in mutable_patterns):
        raise AssertionError("compatibility ledger contains a mutable upstream documentation URL")
    print("PASS  Draft 2020-12 upstream source manifest schema")
    print("PASS  exactly eight immutable source pins with commit/blob/content hashes")
    print("PASS  immutable file URLs resolve to the recorded commit and path")
    print("PASS  RootlessKit v3.3.0 verified release and unsigned source commits explicitly distinguished")
    print("PASS  compatibility ledger links every immutable source URL and the manifest")
    print("PASS  ADR, dossier, security packet, qualification protocol and checklist link the manifest")
    print("PASS  M0 workflow executes this validator and ledger contains no mutable upstream docs URLs")
    print("NOTE  validation checks committed metadata only; it does not re-fetch or re-hash upstream network content")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
