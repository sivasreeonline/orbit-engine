#!/usr/bin/env python3
"""Provider-neutral FENCE-001 witness adapter conformance harness.

The in-memory adapter is a test fixture only. A PASS means only that the
adapter supplied to this process satisfies the exercised contract; it is not
provider qualification, cryptographic receipt verification, durability proof,
or evidence of independent failure domains.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib
import os
from dataclasses import dataclass
from threading import Lock
from typing import Callable, Protocol, Sequence


class AppendConflict(Exception):
    """The expected predecessor was no longer the witness high-water."""


class IdempotencyConflict(Exception):
    """An idempotency key was reused for a different checkpoint."""


class AmbiguousCommit(Exception):
    """The append may have committed, but the caller did not receive its receipt."""


@dataclass(frozen=True)
class Scope:
    trust_domain_id: str
    witness_id: str
    authority_id: str
    host_id: str


@dataclass(frozen=True)
class Checkpoint:
    scope: Scope
    generation: int
    operation_id: str
    phase: str
    checkpoint_digest: str
    previous_digest: str


@dataclass(frozen=True)
class Receipt:
    scope: Scope
    generation: int
    operation_id: str
    checkpoint_digest: str
    previous_digest: str
    consistency_token: str


@dataclass(frozen=True)
class StoredCheckpoint:
    checkpoint: Checkpoint
    receipt: Receipt


class WitnessAdapter(Protocol):
    """Required provider adapter behavior.

    append_if_current must atomically compare the exact expected predecessor,
    append one immutable checkpoint, and bind idempotency_key to the exact
    canonical checkpoint bytes. An ambiguous timeout may occur after commit;
    retrying the same key and bytes must return the original receipt.
    read_latest must be a strongly consistent read, not a cached/replica-stale
    observation. read_by_operation must return the exact immutable commit.
    """

    def append_if_current(
        self,
        checkpoint: Checkpoint,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> Receipt: ...

    def read_latest(self, scope: Scope) -> StoredCheckpoint | None: ...

    def read_by_operation(self, scope: Scope, operation_id: str) -> StoredCheckpoint | None: ...


ZERO_DIGEST = "0" * 64
TEST_SCOPE = Scope("test-domain", "test-witness", "test-authority", "test-host")


def checkpoint(
    generation: int,
    operation_id: str,
    digest_character: str,
    previous_digest: str,
    phase: str = "ISSUED",
) -> Checkpoint:
    return Checkpoint(
        scope=TEST_SCOPE,
        generation=generation,
        operation_id=operation_id,
        phase=phase,
        checkpoint_digest=digest_character * 64,
        previous_digest=previous_digest,
    )


class LoseAcknowledgementOnce:
    """Inject a lost response after the wrapped provider has committed."""

    def __init__(self, delegate: WitnessAdapter):
        self._delegate = delegate
        self._lost = False

    def append_if_current(
        self,
        value: Checkpoint,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> Receipt:
        receipt = self._delegate.append_if_current(
            value,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            idempotency_key=idempotency_key,
        )
        if not self._lost:
            self._lost = True
            raise AmbiguousCommit("injected lost acknowledgement after provider append returned")
        return receipt

    def read_latest(self, scope: Scope) -> StoredCheckpoint | None:
        return self._delegate.read_latest(scope)

    def read_by_operation(self, scope: Scope, operation_id: str) -> StoredCheckpoint | None:
        return self._delegate.read_by_operation(scope, operation_id)


class InMemoryWitnessAdapter:
    """Deterministic fixture; deliberately not durable or production safe."""

    def __init__(self, *, lose_ack_once: bool = False, stale_latest: bool = False):
        self._lock = Lock()
        self._records: list[StoredCheckpoint] = []
        self._idempotency: dict[str, tuple[Checkpoint, Receipt]] = {}
        self._lose_ack_once = lose_ack_once
        self._stale_latest = stale_latest
        self._last_read: StoredCheckpoint | None = None

    def append_if_current(
        self,
        value: Checkpoint,
        *,
        expected_generation: int,
        expected_digest: str,
        idempotency_key: str,
    ) -> Receipt:
        with self._lock:
            prior = self._idempotency.get(idempotency_key)
            if prior is not None:
                if prior[0] != value:
                    raise IdempotencyConflict("idempotency key is bound to different checkpoint content")
                return prior[1]

            latest = self._records[-1] if self._records else None
            actual_generation = latest.checkpoint.generation if latest else 0
            actual_digest = latest.checkpoint.checkpoint_digest if latest else ZERO_DIGEST
            if (actual_generation, actual_digest) != (expected_generation, expected_digest):
                raise AppendConflict("expected predecessor is not the current witness high-water")
            if value.generation != expected_generation + 1:
                raise AppendConflict("checkpoint generation must advance exactly one")
            if value.previous_digest != expected_digest:
                raise AppendConflict("checkpoint does not name the exact expected predecessor")
            if latest and value.scope != latest.checkpoint.scope:
                raise AppendConflict("checkpoint scope changed within a witness history")
            if not idempotency_key.strip() or not value.operation_id.strip():
                raise ValueError("operation and idempotency identifiers must be non-empty")
            if any(item.checkpoint.operation_id == value.operation_id for item in self._records):
                raise IdempotencyConflict("operation ID already exists with another idempotency key")

            receipt = Receipt(
                scope=value.scope,
                generation=value.generation,
                operation_id=value.operation_id,
                checkpoint_digest=value.checkpoint_digest,
                previous_digest=value.previous_digest,
                consistency_token=f"fixture-token-{value.generation}",
            )
            stored = StoredCheckpoint(value, receipt)
            self._records.append(stored)
            self._idempotency[idempotency_key] = (value, receipt)
            if self._lose_ack_once:
                self._lose_ack_once = False
                raise AmbiguousCommit("synthetic acknowledgement loss after durable-commit point")
            return receipt

    def read_latest(self, scope: Scope) -> StoredCheckpoint | None:
        with self._lock:
            latest = self._records[-1] if self._records else None
            if latest is not None and latest.checkpoint.scope != scope:
                return None
            if self._stale_latest:
                return self._last_read
            self._last_read = latest
            return latest

    def read_by_operation(self, scope: Scope, operation_id: str) -> StoredCheckpoint | None:
        with self._lock:
            for item in self._records:
                if item.checkpoint.scope == scope and item.checkpoint.operation_id == operation_id:
                    return item
            return None


@dataclass(frozen=True)
class ConformanceResult:
    name: str
    passed: bool
    detail: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_receipt_matches(value: Checkpoint, receipt: Receipt) -> None:
    require(receipt.scope == value.scope, "receipt scope differs from submitted checkpoint")
    require(receipt.generation == value.generation, "receipt generation differs from submitted checkpoint")
    require(receipt.operation_id == value.operation_id, "receipt operation ID differs from submitted checkpoint")
    require(receipt.checkpoint_digest == value.checkpoint_digest, "receipt digest differs from submitted checkpoint")
    require(receipt.previous_digest == value.previous_digest, "receipt predecessor differs from submitted checkpoint")
    require(bool(receipt.consistency_token.strip()), "provider consistency token is empty")


def run_conformance(adapter_factory: Callable[[], WitnessAdapter]) -> list[ConformanceResult]:
    results: list[ConformanceResult] = []

    def case(name: str, action: Callable[[], None]) -> None:
        try:
            action()
            results.append(ConformanceResult(name, True, "passed"))
        except Exception as error:  # each failure is reported without hiding later cases
            results.append(ConformanceResult(name, False, f"{type(error).__name__}: {error}"))

    def fresh() -> WitnessAdapter:
        return adapter_factory()

    def append_genesis(adapter: WitnessAdapter) -> Receipt:
        value = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        receipt = adapter.append_if_current(
            value, expected_generation=0, expected_digest=ZERO_DIGEST,
            idempotency_key="idempotency-1",
        )
        assert_receipt_matches(value, receipt)
        return receipt

    def genesis_append_and_readback() -> None:
        adapter = fresh()
        receipt = append_genesis(adapter)
        latest = adapter.read_latest(TEST_SCOPE)
        require(latest is not None, "latest read omitted a committed genesis checkpoint")
        require(latest.receipt == receipt, "latest read returned a different receipt")
        require(latest.checkpoint.generation == 1, "latest read returned wrong generation")
        require(latest.checkpoint.checkpoint_digest == "1" * 64, "latest read returned wrong digest")

    case("atomic genesis append and immediate latest readback", genesis_append_and_readback)

    def exact_retry_is_idempotent() -> None:
        adapter = fresh()
        value = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        args = dict(expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="same-key")
        first = adapter.append_if_current(value, **args)
        second = adapter.append_if_current(value, **args)
        require(first == second, "exact retry did not return the original receipt")
        latest = adapter.read_latest(TEST_SCOPE)
        require(latest is not None and latest.checkpoint.generation == 1, "exact retry created another generation")
    case("exact idempotent retry", exact_retry_is_idempotent)

    def ambiguous_ack_retry() -> None:
        adapter = LoseAcknowledgementOnce(fresh())
        value = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        args = dict(expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="lost-ack-key")
        try:
            adapter.append_if_current(value, **args)
        except AmbiguousCommit:
            pass
        else:
            raise AssertionError("fixture did not simulate the lost acknowledgement")
        recovered = adapter.append_if_current(value, **args)
        assert_receipt_matches(value, recovered)
        latest = adapter.read_latest(TEST_SCOPE)
        require(latest is not None and latest.checkpoint.generation == 1, "lost-ack retry duplicated the commit")
    case("lost acknowledgement and exact retry recovery", ambiguous_ack_retry)

    def idempotency_key_content_binding() -> None:
        adapter = fresh()
        first = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        adapter.append_if_current(first, expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="fixed-key")
        changed = checkpoint(1, "operation-1", "a", ZERO_DIGEST)
        try:
            adapter.append_if_current(changed, expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="fixed-key")
        except IdempotencyConflict:
            return
        raise AssertionError("same idempotency key accepted different checkpoint content")
    case("idempotency key cannot be rebound to different bytes", idempotency_key_content_binding)

    def operation_id_uniqueness() -> None:
        adapter = fresh()
        first = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        adapter.append_if_current(first, expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="key-1")
        changed = checkpoint(2, "operation-1", "2", "1" * 64, phase="ACCEPTED")
        try:
            adapter.append_if_current(changed, expected_generation=1, expected_digest="1" * 64, idempotency_key="key-2")
        except IdempotencyConflict:
            return
        raise AssertionError("operation ID was reused for another checkpoint")
    case("operation ID uniqueness across checkpoint phases", operation_id_uniqueness)

    def stale_predecessor_is_rejected() -> None:
        adapter = fresh()
        append_genesis(adapter)
        stale = checkpoint(2, "operation-2", "2", "f" * 64)
        try:
            adapter.append_if_current(stale, expected_generation=1, expected_digest="f" * 64, idempotency_key="key-2")
        except AppendConflict:
            return
        raise AssertionError("append accepted a stale/forked predecessor")
    case("stale predecessor and fork rejection", stale_predecessor_is_rejected)

    def generation_gap_is_rejected() -> None:
        adapter = fresh()
        invalid = checkpoint(2, "operation-2", "2", ZERO_DIGEST)
        try:
            adapter.append_if_current(invalid, expected_generation=0, expected_digest=ZERO_DIGEST, idempotency_key="key-2")
        except AppendConflict:
            return
        raise AssertionError("append accepted a generation gap")
    case("generation gap rejection", generation_gap_is_rejected)

    def read_by_operation_is_exact() -> None:
        adapter = fresh()
        first = append_genesis(adapter)
        latest = checkpoint(2, "operation-2", "2", first.checkpoint_digest, phase="ACCEPTED")
        second_receipt = adapter.append_if_current(
            latest, expected_generation=1, expected_digest=first.checkpoint_digest,
            idempotency_key="idempotency-2",
        )
        found = adapter.read_by_operation(TEST_SCOPE, "operation-1")
        require(found is not None, "operation lookup omitted an existing commit")
        require(found.checkpoint.generation == 1, "operation lookup returned wrong generation")
        require(found.receipt == first, "operation lookup returned a different receipt")
        found_second = adapter.read_by_operation(TEST_SCOPE, "operation-2")
        require(found_second is not None and found_second.receipt == second_receipt, "second operation lookup mismatch")
    case("immutable read-by-operation lookup", read_by_operation_is_exact)

    def latest_read_advances_after_successor() -> None:
        adapter = fresh()
        first = append_genesis(adapter)
        second = checkpoint(2, "operation-2", "2", first.checkpoint_digest, phase="ACCEPTED")
        receipt = adapter.append_if_current(
            second, expected_generation=1, expected_digest=first.checkpoint_digest,
            idempotency_key="idempotency-2",
        )
        latest = adapter.read_latest(TEST_SCOPE)
        require(latest is not None and latest.receipt == receipt, "latest read did not expose the committed successor")
        require(latest.checkpoint.generation == 2, "latest read regressed to a predecessor")
    case("strong latest-read successor visibility", latest_read_advances_after_successor)

    def concurrent_compare_and_append_has_one_winner() -> None:
        adapter = fresh()
        first = append_genesis(adapter)
        digest_characters = ("a", "b", "c", "d", "e", "f", "0", "1")
        contenders = [
            checkpoint(2, f"concurrent-{index}", digest_characters[index], first.checkpoint_digest)
            for index in range(8)
        ]

        def attempt(value: Checkpoint) -> tuple[str, Receipt | None]:
            try:
                receipt = adapter.append_if_current(
                    value, expected_generation=1, expected_digest=first.checkpoint_digest,
                    idempotency_key=f"concurrent-key-{value.operation_id}",
                )
                return ("committed", receipt)
            except AppendConflict:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=len(contenders)) as pool:
            outcomes = list(pool.map(attempt, contenders))
        winners = [receipt for status, receipt in outcomes if status == "committed" and receipt is not None]
        conflicts = [status for status, _ in outcomes if status == "conflict"]
        require(len(winners) == 1, f"expected one atomic winner, observed {len(winners)}")
        require(len(conflicts) == len(contenders) - 1, "losing concurrent appends were not rejected")
        latest = adapter.read_latest(TEST_SCOPE)
        require(latest is not None and latest.checkpoint.generation == 2, "concurrent append created multiple successors")
        require(latest.receipt == winners[0], "latest read does not identify the sole concurrent winner")
    case("concurrent compare-and-append linearization", concurrent_compare_and_append_has_one_winner)

    def receipt_must_bind_exact_checkpoint() -> None:
        adapter = fresh()
        value = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        receipt = append_genesis(adapter)
        forged = Receipt(
            scope=receipt.scope, generation=receipt.generation,
            operation_id=receipt.operation_id, checkpoint_digest="f" * 64,
            previous_digest=receipt.previous_digest, consistency_token=receipt.consistency_token,
        )
        try:
            assert_receipt_matches(value, forged)
        except AssertionError:
            return
        raise AssertionError("receipt mismatch was accepted")
    case("receipt field binding", receipt_must_bind_exact_checkpoint)

    def empty_consistency_token_is_rejected() -> None:
        value = checkpoint(1, "operation-1", "1", ZERO_DIGEST)
        receipt = Receipt(TEST_SCOPE, 1, "operation-1", "1" * 64, ZERO_DIGEST, "")
        try:
            assert_receipt_matches(value, receipt)
        except AssertionError:
            return
        raise AssertionError("empty provider consistency token was accepted")
    case("non-empty provider consistency token", empty_consistency_token_is_rejected)

    return results


def load_adapter_factory() -> tuple[Callable[[], WitnessAdapter], str]:
    target = os.environ.get("FENCE_WITNESS_ADAPTER_FACTORY")
    if not target:
        return InMemoryWitnessAdapter, "IN_MEMORY_REFERENCE_FIXTURE"
    module_name, separator, attribute = target.partition(":")
    if not separator or not module_name or not attribute:
        raise SystemExit("FENCE_WITNESS_ADAPTER_FACTORY must use module.path:factory_name")
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute, None)
    if not callable(factory):
        raise SystemExit("configured witness adapter factory is not callable")
    return factory, f"EXTERNAL_ADAPTER:{target}"


def main() -> None:
    factory, mode = load_adapter_factory()
    results = run_conformance(factory)
    failures = [item for item in results if not item.passed]
    for item in results:
        print(f"{'PASS' if item.passed else 'FAIL'} {item.name}: {item.detail}")
    print(f"Provider adapter contract cases: {len(results)}; passed: {len(results) - len(failures)}; failed: {len(failures)}")
    print(f"Execution mode: {mode}")
    if mode == "IN_MEMORY_REFERENCE_FIXTURE":
        print("NOT PROVIDER QUALIFICATION: fixture results are not external provider evidence")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
