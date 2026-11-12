#!/usr/bin/env python3
"""Verify provider-native audit provenance for FENCE-001 qualification evidence.

The provider adapter only collects raw pages. A separately provisioned verifier
must authenticate each page against independently pinned provider trust material.
A passing synthetic fixture validates this contract's fail-closed behavior only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
MAX_PAGES = 1000
MAX_EVENTS = 100000


@dataclass(frozen=True)
class AuditPage:
    provider: str
    account_id: str
    region: str
    service: str
    source_principal_id: str
    verifier_principal_id: str
    cursor_start: str
    cursor_end: str
    complete: bool
    events: tuple[dict[str, Any], ...]
    raw_response: bytes
    signature_evidence: bytes


@dataclass(frozen=True)
class Verification:
    status: str
    provider: str
    account_id: str
    region: str
    service: str
    verifier_principal_id: str
    authenticated_service_principal_id: str
    authentication_method: str
    trust_root_id: str
    trust_root_sha256: str
    verified_response_sha256: str
    signature_status: str
    transport_status: str
    verified_event_set_sha256: str


class AuditPageAdapter(Protocol):
    def fetch_page(self, cursor: str, *, verifier_principal_id: str) -> AuditPage: ...


class ProviderAuditVerifier(Protocol):
    def verify_page(
        self, page: AuditPage, *, expected_identity: dict[str, str],
        pinned_trust_root_id: str, pinned_trust_root_sha256: str,
        verifier_principal_id: str
    ) -> Verification: ...


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_output_dir(output_dir: Path) -> None:
    """Create or validate a fresh evidence directory before any provider API call."""
    try:
        mode = output_dir.lstat().st_mode
    except FileNotFoundError:
        try:
            output_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise ValueError("audit evidence output directory changed during preflight") from exc
        return
    if stat.S_ISLNK(mode):
        raise ValueError("audit evidence output directory must not be a symbolic link")
    if not stat.S_ISDIR(mode):
        raise ValueError("audit evidence output path must be a directory")
    if next(output_dir.iterdir(), None) is not None:
        raise ValueError("audit evidence output directory must be new or empty; refusing to overwrite prior evidence")


def write_new_artifact(output_dir: Path, filename: str, content: bytes) -> None:
    """Create one evidence file without following or replacing an existing path."""
    path = output_dir / filename
    try:
        with path.open("xb") as artifact:
            artifact.write(content)
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite existing audit evidence artifact: {filename}") from exc


def require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise ValueError(f"{field} must be a non-empty safe provider identifier")
    return value


def normalized_event_set_digest(events: tuple[dict[str, Any], ...]) -> str:
    """Digest the verifier-authenticated normalized event projection deterministically."""
    normalized = []
    for event in events:
        normalized.append({
            key: ({"$bytesSha256": digest(value), "$byteCount": len(value)} if isinstance(value, bytes) else value)
            for key, value in sorted(event.items())
        })
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return digest(encoded)


def validate_page(
    page: AuditPage, verification: Verification, expected: dict[str, str],
    pinned_root_id: str, pinned_root_sha256: str, verifier_id: str,
    expected_cursor: str
) -> None:
    for field in ("provider", "account_id", "region", "service"):
        if getattr(page, field) != expected[field]:
            raise ValueError(f"audit page {field} does not match pinned provider scope")
        if getattr(verification, field) != expected[field]:
            raise ValueError(f"verification result {field} does not match pinned provider scope")
    if page.verifier_principal_id != verifier_id or verification.verifier_principal_id != verifier_id:
        raise ValueError("audit page was not independently verified by the pinned verifier principal")
    if not page.source_principal_id or page.source_principal_id == verifier_id:
        raise ValueError("audit source principal is missing or aliases the independent verifier")
    if verification.authenticated_service_principal_id != page.source_principal_id:
        raise ValueError("authenticated audit-service identity does not match the captured source principal")
    if page.cursor_start != expected_cursor:
        raise ValueError("audit cursor gap, replay or out-of-order page detected")
    require_id(page.cursor_start, "cursor_start")
    require_id(page.cursor_end, "cursor_end")
    if page.cursor_end == page.cursor_start:
        raise ValueError("audit page did not advance the provider cursor")
    if not isinstance(page.raw_response, bytes) or not page.raw_response:
        raise ValueError("raw provider audit response bytes are missing")
    if not isinstance(page.signature_evidence, bytes) or not page.signature_evidence:
        raise ValueError("provider-native authentication evidence is missing")
    if verification.status != "VERIFIED":
        raise ValueError("independent provider audit verification did not pass")
    if verification.signature_status != "VERIFIED" or verification.transport_status != "VERIFIED":
        raise ValueError("provider-native signature or authenticated transport verification failed")
    if verification.authentication_method not in {
        "PROVIDER_SIGNED_AUDIT_ENVELOPE", "AUTHENTICATED_AUDIT_API_RESPONSE"
    }:
        raise ValueError("unsupported or unspecified provider audit authentication method")
    if verification.trust_root_id != pinned_root_id or verification.trust_root_sha256 != pinned_root_sha256:
        raise ValueError("provider audit verification used a trust root other than the independently pinned root")
    if verification.verified_response_sha256 != digest(page.raw_response):
        raise ValueError("verifier result is not bound to the exact captured raw response bytes")
    if verification.verified_event_set_sha256 != normalized_event_set_digest(page.events):
        raise ValueError("normalized audit events are not bound to the independently verified raw page")


def validate_event(
    event: dict[str, Any], expected_request: dict[str, dict[str, str]],
    seen_event_ids: set[str], seen_sequences: set[int], expected_sequence: int
) -> int:
    required = {
        "event_id", "provider_request_id", "sequence", "actor_principal_id",
        "action", "outcome", "resource_ref", "version_id", "occurred_at", "raw_bytes"
    }
    missing = required - event.keys()
    if missing:
        raise ValueError(f"audit event missing fields: {', '.join(sorted(missing))}")
    event_id = require_id(event["event_id"], "event_id")
    request_id = require_id(event["provider_request_id"], "provider_request_id")
    if event_id in seen_event_ids:
        raise ValueError("duplicate provider audit event ID detected")
    if type(event["sequence"]) is not int or event["sequence"] != expected_sequence:
        raise ValueError("provider audit sequence gap, replay or reordering detected")
    if event["sequence"] in seen_sequences:
        raise ValueError("duplicate provider audit sequence detected")
    if not all(isinstance(event[k], str) and event[k].strip() for k in (
        "actor_principal_id", "action", "outcome", "resource_ref", "version_id", "occurred_at"
    )):
        raise ValueError("provider audit event contains empty identity or binding fields")
    if not isinstance(event["raw_bytes"], bytes) or not event["raw_bytes"]:
        raise ValueError("raw provider audit event bytes are missing")
    expected = expected_request.get(request_id)
    if expected is None:
        raise ValueError("provider audit event does not correspond to a required privileged-bypass request")
    for field in ("actor_principal_id", "action", "outcome", "resource_ref", "version_id"):
        if event[field] != expected[field]:
            raise ValueError(f"provider audit event {field} does not match the originating privileged request")
    seen_event_ids.add(event_id)
    seen_sequences.add(event["sequence"])
    return expected_sequence + 1


def run_contract(
    adapter: AuditPageAdapter, verifier: ProviderAuditVerifier,
    expected: dict[str, str], pinned_root_id: str, pinned_root_sha256: str,
    verifier_id: str, initial_cursor: str, attempts: list[dict[str, Any]],
    output_dir: Path
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", pinned_root_sha256):
        raise ValueError("pinned trust-root SHA-256 must be lowercase 64-character hex")
    if not attempts:
        raise ValueError("privileged-bypass run report contains no attempts")
    expected_requests: dict[str, dict[str, str]] = {}
    for attempt in attempts:
        request_id = require_id(attempt.get("providerRequestId"), "providerRequestId")
        if request_id in expected_requests:
            raise ValueError("privileged-bypass run report contains duplicate provider request IDs")
        expected_requests[request_id] = {
            "actor_principal_id": attempt["actorPrincipalId"],
            "action": attempt["action"],
            "outcome": attempt["result"],
            "resource_ref": attempt["objectRef"],
            "version_id": attempt["versionId"],
        }
    if verifier_id in {item["actor_principal_id"] for item in expected_requests.values()}:
        raise ValueError("independent audit verifier must not be a privileged mutation actor")

    prepare_output_dir(output_dir)
    cursor = initial_cursor
    expected_sequence = 1
    seen_events: set[str] = set()
    seen_sequences: set[int] = set()
    page_records: list[dict[str, Any]] = []
    event_records: list[dict[str, Any]] = []
    total_events = 0

    for page_number in range(1, MAX_PAGES + 1):
        page = adapter.fetch_page(cursor, verifier_principal_id=verifier_id)
        verification = verifier.verify_page(
            page, expected_identity=expected, pinned_trust_root_id=pinned_root_id,
            pinned_trust_root_sha256=pinned_root_sha256, verifier_principal_id=verifier_id
        )
        validate_page(page, verification, expected, pinned_root_id, pinned_root_sha256, verifier_id, cursor)
        if not page.events:
            raise ValueError("provider returned an empty audit page without a terminal event")
        page_digest = digest(page.raw_response)
        page_artifact = f"audit-page-{page_number:04d}.bin"
        write_new_artifact(output_dir, page_artifact, page.raw_response)
        signature_artifact = f"audit-page-{page_number:04d}-authentication.bin"
        write_new_artifact(output_dir, signature_artifact, page.signature_evidence)
        page_records.append({
            "page": page_number, "cursorStart": page.cursor_start, "cursorEnd": page.cursor_end,
            "rawResponseArtifact": page_artifact, "rawResponseSha256": page_digest,
            "rawResponseByteCount": len(page.raw_response),
            "authenticationEvidenceArtifact": signature_artifact,
            "authenticationEvidenceSha256": digest(page.signature_evidence),
            "authenticationEvidenceByteCount": len(page.signature_evidence),
            "authenticationMethod": verification.authentication_method,
            "trustRootId": verification.trust_root_id,
            "trustRootSha256": verification.trust_root_sha256,
            "authenticatedServicePrincipalId": verification.authenticated_service_principal_id,
        })
        for event in page.events:
            expected_sequence = validate_event(event, expected_requests, seen_events, seen_sequences, expected_sequence)
            total_events += 1
            if total_events > MAX_EVENTS:
                raise ValueError("provider audit stream exceeded the bounded event limit")
            artifact = f"audit-event-{total_events:06d}.bin"
            write_new_artifact(output_dir, artifact, event["raw_bytes"])
            event_records.append({
                "eventId": event["event_id"], "providerRequestId": event["provider_request_id"],
                "sequence": event["sequence"], "artifact": artifact,
                "sha256": digest(event["raw_bytes"]), "byteCount": len(event["raw_bytes"]),
            })
        cursor = page.cursor_end
        if page.complete:
            break
    else:
        raise ValueError("provider audit stream exceeded the maximum page count")

    missing_requests = set(expected_requests) - {
        record["providerRequestId"] for record in event_records
    }
    if missing_requests:
        raise ValueError("provider audit stream is incomplete: one or more privileged request IDs are absent")
    report = {
        "profile": "sky-high-fence-provider-audit-provenance-v1",
        "testOnly": False,
        "providerIdentity": {
            "provider": expected["provider"], "accountId": expected["account_id"],
            "region": expected["region"], "service": expected["service"]
        },
        "independentVerifierPrincipalId": verifier_id,
        "pinnedTrustRoot": {"id": pinned_root_id, "sha256": pinned_root_sha256},
        "initialCursor": initial_cursor,
        "finalCursor": cursor,
        "pages": page_records,
        "events": event_records,
        "eventCount": total_events,
        "qualificationStatus": "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED",
        "testOnly": False,
        "limitations": [
            "The provider-specific verifier and pinned trust-root governance require independent review.",
            "An authenticated API response does not by itself prove provider event completeness or retention.",
            "This report is not a dual-signed evidence manifest and does not authorize host admission or execution."
        ]
    }
    write_new_artifact(
        output_dir, "provider-audit-provenance-run.json",
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return report


class FixtureAdapter:
    def __init__(self, scenario: str = "success") -> None:
        self.scenario = scenario
        self.fetch_calls = 0
        self.cursor = "cursor-0"
        self.sequence = 1
        self.request = {
            "providerRequestId": "request-001",
            "actorPrincipalId": "privileged-actor-1",
            "action": "DELETE_AS_OBJECT_OWNER",
            "result": "DENIED",
            "objectRef": "object://qualification/evidence",
            "versionId": "version-001",
        }

    def fetch_page(self, cursor: str, *, verifier_principal_id: str) -> AuditPage:
        self.fetch_calls += 1
        if cursor != self.cursor:
            raise ValueError("fixture cursor mismatch")
        event = {
            "event_id": "event-001", "provider_request_id": self.request["providerRequestId"],
            "sequence": self.sequence, "actor_principal_id": self.request["actorPrincipalId"],
            "action": self.request["action"], "outcome": self.request["result"],
            "resource_ref": self.request["objectRef"], "version_id": self.request["versionId"],
            "occurred_at": "2026-11-12T00:00:00Z", "raw_bytes": b"fixture-provider-event"
        }
        raw = b"fixture-provider-audit-response"
        signature = b"fixture-provider-authentication-evidence"
        if self.scenario == "wrong-account":
            account = "attacker-account"
        else:
            account = "qualification-account"
        page = AuditPage(
            "fixture-provider", account, "fixture-region", "audit-service",
            "audit-service-principal", verifier_principal_id,
            cursor, "cursor-1", True, (event,), raw, signature
        )
        self.cursor = "cursor-1"
        return page


class FixtureVerifier:
    def __init__(self, scenario: str = "success") -> None:
        self.scenario = scenario

    def verify_page(self, page: AuditPage, *, expected_identity: dict[str, str],
                    pinned_trust_root_id: str, pinned_trust_root_sha256: str,
                    verifier_principal_id: str) -> Verification:
        return Verification(
            "REJECTED" if self.scenario == "unsigned" else "VERIFIED",
            page.provider, page.account_id, page.region, page.service,
            verifier_principal_id, page.source_principal_id,
            "PROVIDER_SIGNED_AUDIT_ENVELOPE", pinned_trust_root_id,
            "0" * 64 if self.scenario == "wrong-root" else pinned_trust_root_sha256,
            digest(page.raw_response), "INVALID" if self.scenario == "bad-signature" else "VERIFIED",
            "VERIFIED", normalized_event_set_digest(page.events)
        )


def run_self_test() -> None:
    expected = {"provider": "fixture-provider", "account_id": "qualification-account",
                "region": "fixture-region", "service": "audit-service"}
    root_hash = "a" * 64
    attempts = [{
        "providerRequestId": "request-001", "actorPrincipalId": "privileged-actor-1",
        "action": "DELETE_AS_OBJECT_OWNER", "result": "DENIED",
        "objectRef": "object://qualification/evidence", "versionId": "version-001"
    }]
    with tempfile.TemporaryDirectory() as temporary:
        result = run_contract(FixtureAdapter(), FixtureVerifier(), expected, "fixture-root",
                              root_hash, "independent-verifier", "cursor-0", attempts, Path(temporary))
        assert result["eventCount"] == 1
        assert result["qualificationStatus"] == "AUDIT_STREAM_AUTHENTICATED_AND_REQUESTS_CORRELATED"

    # A rerun against the same directory must stop before making another
    # provider request and must leave every previously collected byte intact.
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary)
        first = run_contract(FixtureAdapter(), FixtureVerifier(), expected, "fixture-root",
                             root_hash, "independent-verifier", "cursor-0", attempts, output)
        report_path = output / "provider-audit-provenance-run.json"
        page_path = output / "audit-page-0001.bin"
        original_report = report_path.read_bytes()
        original_page = page_path.read_bytes()
        retry_adapter = FixtureAdapter()
        try:
            run_contract(retry_adapter, FixtureVerifier(), expected, "fixture-root",
                         root_hash, "independent-verifier", "cursor-0", attempts, output)
        except ValueError as error:
            assert "new or empty" in str(error)
        else:
            raise AssertionError("non-empty evidence directory was accepted for a retry")
        assert retry_adapter.fetch_calls == 0, "provider adapter was called before output-directory rejection"
        assert report_path.read_bytes() == original_report
        assert page_path.read_bytes() == original_page

    # A pre-existing non-empty directory is rejected before collection.
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "existing"
        output.mkdir()
        sentinel = output / "prior-evidence.bin"
        sentinel.write_bytes(b"preserve-me")
        blocked_adapter = FixtureAdapter()
        try:
            run_contract(blocked_adapter, FixtureVerifier(), expected, "fixture-root",
                         root_hash, "independent-verifier", "cursor-0", attempts, output)
        except ValueError as error:
            assert "new or empty" in str(error)
        else:
            raise AssertionError("pre-existing evidence directory was accepted")
        assert blocked_adapter.fetch_calls == 0
        assert sentinel.read_bytes() == b"preserve-me"

    # The requested output path itself may not be a symbolic link to a
    # different directory, even when the link target is empty.
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        target = base / "target"
        target.mkdir()
        alias = base / "alias"
        try:
            alias.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pass
        else:
            blocked_adapter = FixtureAdapter()
            try:
                run_contract(blocked_adapter, FixtureVerifier(), expected, "fixture-root",
                             root_hash, "independent-verifier", "cursor-0", attempts, alias)
            except ValueError as error:
                assert "symbolic link" in str(error)
            else:
                raise AssertionError("symbolic-link evidence directory was accepted")
            assert blocked_adapter.fetch_calls == 0
            assert list(target.iterdir()) == []

    for scenario, verifier_scenario, expected_error in (
        ("wrong-account", "success", "account_id"),
        ("success", "unsigned", "did not pass"),
        ("success", "bad-signature", "signature"),
        ("success", "wrong-root", "trust root"),
    ):
        try:
            run_contract(FixtureAdapter(scenario), FixtureVerifier(verifier_scenario), expected,
                         "fixture-root", root_hash, "independent-verifier", "cursor-0",
                         attempts, Path(tempfile.mkdtemp()))
        except ValueError as error:
            if expected_error not in str(error):
                raise AssertionError(f"unexpected rejection: {error}") from error
        else:
            raise AssertionError(f"unsafe fixture scenario was accepted: {scenario}/{verifier_scenario}")

    duplicated = [dict(attempts[0]), dict(attempts[0])]
    try:
        run_contract(FixtureAdapter(), FixtureVerifier(), expected, "fixture-root", root_hash,
                     "independent-verifier", "cursor-0", duplicated, Path(tempfile.mkdtemp()))
    except ValueError as error:
        assert "duplicate provider request" in str(error)
    else:
        raise AssertionError("duplicate request IDs were accepted")

    print("FENCE-001 provider audit provenance self-test passed (synthetic fixtures only)")


def load_factory(value: str) -> Any:
    module_name, separator, attribute = value.partition(":")
    if not separator:
        raise ValueError("factory must use package.module:create_instance")
    return getattr(importlib.import_module(module_name), attribute)()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run-report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--initial-cursor")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return
    required_env = {
        "FENCE_PROVIDER_AUDIT_ADAPTER_FACTORY": os.getenv("FENCE_PROVIDER_AUDIT_ADAPTER_FACTORY"),
        "FENCE_PROVIDER_AUDIT_VERIFIER_FACTORY": os.getenv("FENCE_PROVIDER_AUDIT_VERIFIER_FACTORY"),
        "FENCE_PROVIDER_AUDIT_EXPECTED_PROVIDER": os.getenv("FENCE_PROVIDER_AUDIT_EXPECTED_PROVIDER"),
        "FENCE_PROVIDER_AUDIT_EXPECTED_ACCOUNT_ID": os.getenv("FENCE_PROVIDER_AUDIT_EXPECTED_ACCOUNT_ID"),
        "FENCE_PROVIDER_AUDIT_EXPECTED_REGION": os.getenv("FENCE_PROVIDER_AUDIT_EXPECTED_REGION"),
        "FENCE_PROVIDER_AUDIT_EXPECTED_SERVICE": os.getenv("FENCE_PROVIDER_AUDIT_EXPECTED_SERVICE"),
        "FENCE_PROVIDER_AUDIT_TRUST_ROOT_ID": os.getenv("FENCE_PROVIDER_AUDIT_TRUST_ROOT_ID"),
        "FENCE_PROVIDER_AUDIT_TRUST_ROOT_SHA256": os.getenv("FENCE_PROVIDER_AUDIT_TRUST_ROOT_SHA256"),
        "FENCE_PROVIDER_AUDIT_VERIFIER_PRINCIPAL_ID": os.getenv("FENCE_PROVIDER_AUDIT_VERIFIER_PRINCIPAL_ID"),
    }
    missing = [key for key, value in required_env.items() if not value]
    if missing or not args.run_report or not args.output_dir or not args.initial_cursor:
        parser.error("external mode requires all FENCE_PROVIDER_AUDIT_* variables plus --run-report, --output-dir and --initial-cursor")
    report = json.loads(args.run_report.read_text(encoding="utf-8"))
    if report.get("testOnly") is not False or report.get("qualificationStatus") != "PROVIDER_DENIED_ALL_SEVEN_AND_AUDIT_READBACK_VERIFIED":
        parser.error("run report must be a non-test-only completed PR98 provider privileged-bypass report")
    expected = {
        "provider": required_env["FENCE_PROVIDER_AUDIT_EXPECTED_PROVIDER"],
        "account_id": required_env["FENCE_PROVIDER_AUDIT_EXPECTED_ACCOUNT_ID"],
        "region": required_env["FENCE_PROVIDER_AUDIT_EXPECTED_REGION"],
        "service": required_env["FENCE_PROVIDER_AUDIT_EXPECTED_SERVICE"],
    }
    result = run_contract(
        load_factory(required_env["FENCE_PROVIDER_AUDIT_ADAPTER_FACTORY"]),
        load_factory(required_env["FENCE_PROVIDER_AUDIT_VERIFIER_FACTORY"]),
        expected, required_env["FENCE_PROVIDER_AUDIT_TRUST_ROOT_ID"],
        required_env["FENCE_PROVIDER_AUDIT_TRUST_ROOT_SHA256"],
        required_env["FENCE_PROVIDER_AUDIT_VERIFIER_PRINCIPAL_ID"],
        args.initial_cursor, report["attempts"], args.output_dir
    )
    print(json.dumps({"qualificationStatus": result["qualificationStatus"],
                      "eventCount": result["eventCount"], "outputDir": str(args.output_dir)}, indent=2))


if __name__ == "__main__":
    main()
