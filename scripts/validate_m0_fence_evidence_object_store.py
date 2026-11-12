#!/usr/bin/env python3
"""Provider-neutral immutable evidence object-store conformance harness.

The in-memory adapter is a test fixture only. External qualification requires
running the same contract against a real object store and independent reader.
"""
from __future__ import annotations

import importlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Lock
from typing import Callable, Protocol


class ObjectMutationDenied(Exception):
    pass


class ObjectIdempotencyConflict(Exception):
    pass


class ObjectVersionNotFound(Exception):
    pass


@dataclass(frozen=True)
class ObjectVersion:
    object_key: str
    version_id: str
    sha256: str
    byte_count: int


@dataclass(frozen=True)
class ObjectMetadata:
    object_key: str
    version_id: str
    sha256: str
    byte_count: int
    retention_until: int
    object_lock_mode: str
    writer_identity: str


class EvidenceObjectStore(Protocol):
    def put_immutable(
        self,
        object_key: str,
        content: bytes,
        *,
        retention_until: int,
        idempotency_key: str,
        writer_identity: str,
    ) -> ObjectVersion: ...

    def get_exact_version(
        self, object_key: str, version_id: str, *, reader_identity: str
    ) -> bytes: ...

    def head_exact_version(self, object_key: str, version_id: str) -> ObjectMetadata: ...

    def delete_version(self, object_key: str, version_id: str) -> None: ...


class InMemoryEvidenceObjectStore:
    """Thread-safe reference fixture; no durable storage or real object lock."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._versions: dict[tuple[str, str], tuple[bytes, ObjectMetadata]] = {}
        self._idempotency: dict[str, tuple[str, bytes, ObjectVersion]] = {}
        self._counter = 0

    def put_immutable(
        self,
        object_key: str,
        content: bytes,
        *,
        retention_until: int,
        idempotency_key: str,
        writer_identity: str,
    ) -> ObjectVersion:
        import hashlib

        with self._lock:
            if not all(value.strip() for value in (object_key, idempotency_key, writer_identity)):
                raise ValueError("object key, idempotency key and writer identity are required")
            if not isinstance(content, bytes) or not content:
                raise ValueError("evidence content must be non-empty bytes")
            prior = self._idempotency.get(idempotency_key)
            if prior is not None:
                if prior[0] != object_key or prior[1] != content:
                    raise ObjectIdempotencyConflict("object idempotency key reused with different key/content")
                return prior[2]
            self._counter += 1
            version_id = f"version-{self._counter:08d}"
            digest = hashlib.sha256(content).hexdigest()
            version = ObjectVersion(object_key, version_id, digest, len(content))
            metadata = ObjectMetadata(
                object_key, version_id, digest, len(content), retention_until,
                "COMPLIANCE", writer_identity,
            )
            self._versions[(object_key, version_id)] = (content, metadata)
            self._idempotency[idempotency_key] = (object_key, content, version)
            return version

    def get_exact_version(self, object_key: str, version_id: str, *, reader_identity: str) -> bytes:
        with self._lock:
            stored = self._versions.get((object_key, version_id))
            if stored is None:
                raise ObjectVersionNotFound("exact object version does not exist")
            if not reader_identity.strip() or reader_identity == stored[1].writer_identity:
                raise PermissionError("readback must use a distinct independent verifier identity")
            return stored[0]

    def head_exact_version(self, object_key: str, version_id: str) -> ObjectMetadata:
        with self._lock:
            stored = self._versions.get((object_key, version_id))
            if stored is None:
                raise ObjectVersionNotFound("exact object version does not exist")
            return stored[1]

    def delete_version(self, object_key: str, version_id: str) -> None:
        with self._lock:
            if (object_key, version_id) not in self._versions:
                raise ObjectVersionNotFound("exact object version does not exist")
            raise ObjectMutationDenied("compliance-retained object version cannot be deleted")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


@dataclass(frozen=True)
class Result:
    name: str
    passed: bool
    detail: str


def run_conformance(factory: Callable[[], EvidenceObjectStore]) -> list[Result]:
    results: list[Result] = []

    def case(name: str, action: Callable[[], None]) -> None:
        try:
            action()
            results.append(Result(name, True, "passed"))
        except Exception as error:
            results.append(Result(name, False, f"{type(error).__name__}: {error}"))

    def fresh() -> EvidenceObjectStore:
        return factory()

    def put(store: EvidenceObjectStore, content: bytes = b"raw signed provider response") -> ObjectVersion:
        return store.put_immutable(
            "qualification/run-001/artifact-001",
            content,
            retention_until=9_000,
            idempotency_key="artifact-001-key",
            writer_identity="collector-identity",
        )

    def exact_readback_and_hash_metadata() -> None:
        import hashlib
        store = fresh()
        version = put(store)
        content = store.get_exact_version(version.object_key, version.version_id, reader_identity="independent-verifier")
        metadata = store.head_exact_version(version.object_key, version.version_id)
        require(content == b"raw signed provider response", "exact version returned altered bytes")
        require(hashlib.sha256(content).hexdigest() == version.sha256 == metadata.sha256, "SHA-256 differs across put/read/head")
        require(len(content) == version.byte_count == metadata.byte_count, "byte count differs across put/read/head")
    case("exact-version readback and digest/byte-count agreement", exact_readback_and_hash_metadata)

    def idempotent_retry_returns_same_version() -> None:
        store = fresh()
        first = put(store)
        second = put(store)
        require(first == second, "idempotent retry created a different object version")
    case("exact idempotent put retry", idempotent_retry_returns_same_version)

    def idempotency_key_content_binding() -> None:
        store = fresh()
        put(store)
        try:
            store.put_immutable(
                "qualification/run-001/artifact-001", b"changed bytes",
                retention_until=9_000, idempotency_key="artifact-001-key",
                writer_identity="collector-identity",
            )
        except ObjectIdempotencyConflict:
            return
        raise AssertionError("idempotency key was rebound to different content")
    case("idempotency key cannot be rebound to different bytes", idempotency_key_content_binding)

    def exact_version_survives_later_object_version() -> None:
        store = fresh()
        first = put(store)
        second = store.put_immutable(
            first.object_key, b"new distinct evidence version",
            retention_until=9_000, idempotency_key="artifact-002-key",
            writer_identity="collector-identity",
        )
        require(first.version_id != second.version_id, "new evidence version reused an immutable version ID")
        old = store.get_exact_version(first.object_key, first.version_id, reader_identity="independent-verifier")
        new = store.get_exact_version(second.object_key, second.version_id, reader_identity="independent-verifier")
        require(old == b"raw signed provider response", "later put changed prior immutable version")
        require(new == b"new distinct evidence version", "new version did not preserve its own bytes")
    case("prior exact version remains immutable after a later put", exact_version_survives_later_object_version)

    def compliance_retention_metadata() -> None:
        store = fresh()
        version = put(store)
        metadata = store.head_exact_version(version.object_key, version.version_id)
        require(metadata.object_lock_mode == "COMPLIANCE", "object version is not under compliance-mode retention")
        require(metadata.retention_until >= 9_000, "retention deadline is shorter than requested")
        require(metadata.writer_identity == "collector-identity", "writer identity missing from immutable metadata")
    case("compliance retention mode and deadline", compliance_retention_metadata)

    def delete_is_denied() -> None:
        store = fresh()
        version = put(store)
        try:
            store.delete_version(version.object_key, version.version_id)
        except ObjectMutationDenied:
            return
        raise AssertionError("compliance-retained evidence version was deletable")
    case("retained exact version cannot be deleted", delete_is_denied)

    def independent_reader_required() -> None:
        store = fresh()
        version = put(store)
        try:
            store.get_exact_version(version.object_key, version.version_id, reader_identity="collector-identity")
        except PermissionError:
            return
        raise AssertionError("collector was allowed to act as independent readback verifier")
    case("readback uses a distinct verifier identity", independent_reader_required)

    def concurrent_idempotent_puts_collapse_to_one_version() -> None:
        store = fresh()
        def write(_: int) -> ObjectVersion:
            return store.put_immutable(
                "qualification/run-001/concurrent-artifact",
                b"same immutable bytes",
                retention_until=9_000,
                idempotency_key="concurrent-idempotency-key",
                writer_identity="collector-identity",
            )
        with ThreadPoolExecutor(max_workers=8) as pool:
            versions = list(pool.map(write, range(8)))
        require(len({(item.object_key, item.version_id) for item in versions}) == 1, "concurrent exact retries created multiple versions")
    case("concurrent idempotent puts resolve to one immutable version", concurrent_idempotent_puts_collapse_to_one_version)

    def wrong_version_does_not_fall_back_to_latest() -> None:
        store = fresh()
        version = put(store)
        try:
            store.get_exact_version(version.object_key, "latest", reader_identity="independent-verifier")
        except ObjectVersionNotFound:
            return
        raise AssertionError("unknown version alias silently resolved to latest")
    case("unknown version ID cannot fall back to latest alias", wrong_version_does_not_fall_back_to_latest)

    return results


def load_factory() -> tuple[Callable[[], EvidenceObjectStore], str]:
    target = os.environ.get("FENCE_EVIDENCE_OBJECT_STORE_FACTORY")
    if not target:
        return InMemoryEvidenceObjectStore, "IN_MEMORY_REFERENCE_FIXTURE"
    module_name, separator, attribute = target.partition(":")
    if not separator or not module_name or not attribute:
        raise SystemExit("FENCE_EVIDENCE_OBJECT_STORE_FACTORY must use module.path:factory_name")
    factory = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(factory):
        raise SystemExit("configured evidence object-store factory is not callable")
    return factory, f"EXTERNAL_ADAPTER:{target}"


def main() -> None:
    factory, mode = load_factory()
    results = run_conformance(factory)
    failures = [item for item in results if not item.passed]
    for item in results:
        print(f"{'PASS' if item.passed else 'FAIL'} {item.name}: {item.detail}")
    print(f"Evidence object-store contract cases: {len(results)}; passed: {len(results) - len(failures)}; failed: {len(failures)}")
    print(f"Execution mode: {mode}")
    if mode == "IN_MEMORY_REFERENCE_FIXTURE":
        print("NOT PROVIDER QUALIFICATION: in-memory fixture does not prove remote object lock or durability")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
