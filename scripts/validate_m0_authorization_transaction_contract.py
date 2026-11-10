#!/usr/bin/env python3
"""Deterministic reference model for M0 authorization ledger transaction contracts.

Synthetic in-memory tests only. No PostgreSQL, Neon, witness, provider or host
integration is performed.
"""
import copy
import hashlib
import json
import sys


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


class Conflict(Exception):
    pass


class Denied(Exception):
    pass


class Ledger:
    def __init__(self, budget=1):
        self.auth = {"state": "ACCEPTED", "budget": budget, "consumed": 0,
                     "version": 1, "revocation_generation": 0}
        self.claims = {}
        self.requests = {}
        self.auth_events = []
        self.run_events = []

    def snapshot(self):
        return copy.deepcopy((self.auth, self.claims, self.requests,
                              self.auth_events, self.run_events))

    def restore(self, snapshot):
        (self.auth, self.claims, self.requests,
         self.auth_events, self.run_events) = snapshot

    def append_auth_event(self, kind, run_id, request_id, details):
        previous = self.auth_events[-1]["digest"] if self.auth_events else "0" * 64
        event = {"seq": len(self.auth_events) + 1, "kind": kind,
                 "run_id": run_id, "request_id": request_id,
                 "state_version": self.auth["version"], "previous": previous,
                 "details": details}
        event["digest"] = digest(event)
        self.auth_events.append(event)

    def consume(self, run_id, request_digest, request_id, expected_version,
                witnessed_revocation_generation, crash=None):
        existing = self.claims.get(run_id)
        if existing:
            if existing["request_digest"] != request_digest:
                raise Conflict("run ID reused with different request digest")
            return {"result": "EXISTING", "claim": copy.deepcopy(existing),
                    "resume_allowed": self.auth["state"] == "ACCEPTED"}
        if request_id in self.requests:
            raise Conflict("request ID reused without matching claim")
        if self.auth["state"] != "ACCEPTED":
            raise Denied("authorization is not ACCEPTED")
        if expected_version != self.auth["version"]:
            raise Conflict("stale authorization version")
        if witnessed_revocation_generation != self.auth["revocation_generation"]:
            raise Denied("stale external revocation checkpoint")
        if self.auth["consumed"] >= self.auth["budget"]:
            raise Denied("run budget exhausted")

        before = self.snapshot()
        claim = {"run_id": run_id, "request_digest": request_digest,
                 "claim_sequence": self.auth["consumed"] + 1,
                 "claimed_state_version": self.auth["version"] + 1}
        self.claims[run_id] = claim
        self.requests[request_id] = (run_id, request_digest)
        self.auth["consumed"] += 1
        self.auth["version"] += 1
        self.append_auth_event("CONSUMED", run_id, request_id,
                               {"claim_sequence": claim["claim_sequence"]})
        self.run_events.append({"run_id": run_id, "seq": 1, "kind": "CLAIMED"})
        if crash == "before_commit":
            self.restore(before)
            return {"result": "ROLLED_BACK"}
        if crash == "after_commit":
            return {"result": "ACK_LOST", "claim": copy.deepcopy(claim)}
        return {"result": "CREATED", "claim": copy.deepcopy(claim)}

    def revoke(self, request_id):
        if self.auth["state"] == "REVOKED":
            return "ALREADY_REVOKED"
        if self.auth["state"] != "ACCEPTED":
            raise Denied("cannot revoke from current state")
        self.auth["state"] = "REVOKED"
        self.auth["version"] += 1
        self.auth["revocation_generation"] += 1
        self.append_auth_event("REVOKED", None, request_id,
                               {"revocation_generation": self.auth["revocation_generation"]})
        return "REVOKED"

    def record_run_event(self, run_id, kind):
        transitions = {
            "CLAIMED": {"STARTED", "FAILED", "QUARANTINED"},
            "STARTED": {"COMPLETED", "FAILED", "QUARANTINED"},
            "COMPLETED": set(), "FAILED": set(), "QUARANTINED": set(),
        }
        history = [e for e in self.run_events if e["run_id"] == run_id]
        if not history:
            raise Denied("claim does not exist")
        if kind not in transitions[history[-1]["kind"]]:
            raise Denied("illegal or terminal run-event transition")
        self.run_events.append({"run_id": run_id, "seq": len(history) + 1, "kind": kind})

    def check(self):
        assert self.auth["consumed"] == len(self.claims)
        assert self.auth["consumed"] <= self.auth["budget"]
        assert len(self.requests) == len(self.claims)
        for i, event in enumerate(self.auth_events):
            assert event["seq"] == i + 1
            assert event["previous"] == (self.auth_events[i - 1]["digest"] if i else "0" * 64)
            material = {k: v for k, v in event.items() if k != "digest"}
            assert event["digest"] == digest(material)
        return True


def expect(exc, fn, message):
    try:
        fn()
    except exc:
        return
    raise AssertionError(message)


def main():
    # Pre-commit crash rolls back claim, budget and both event streams together.
    ledger = Ledger(1)
    assert ledger.consume("r1", "a" * 64, "q1", 1, 0, "before_commit")["result"] == "ROLLED_BACK"
    assert ledger.auth["consumed"] == 0 and not ledger.claims and not ledger.auth_events and not ledger.run_events

    # Commit succeeds but acknowledgement is lost: retry resolves the same claim.
    assert ledger.consume("r1", "a" * 64, "q1", 1, 0, "after_commit")["result"] == "ACK_LOST"
    assert ledger.auth["consumed"] == 1
    assert ledger.consume("r1", "a" * 64, "q1-retry", 2, 0)["result"] == "EXISTING"
    expect(Conflict, lambda: ledger.consume("r1", "b" * 64, "q-conflict", 2, 0),
           "changed request digest must conflict")
    expect(Denied, lambda: ledger.consume("r2", "c" * 64, "q2", 2, 0),
           "final budget slot must not be over-consumed")
    ledger.check()

    # Claim first then revoke: slot remains consumed; existing claim cannot resume.
    ledger.revoke("rev1")
    assert ledger.consume("r1", "a" * 64, "resolve", 3, 1)["resume_allowed"] is False
    expect(Denied, lambda: ledger.consume("r2", "c" * 64, "q-after-revoke", 3, 1),
           "new claim after revocation must fail")

    # Revoke first then claim: no claim may be created.
    reverse = Ledger(1)
    reverse.revoke("rev-first")
    expect(Denied, lambda: reverse.consume("r3", "d" * 64, "q3", 1, 1),
           "claim after committed revocation must fail")
    assert not reverse.claims and reverse.auth["consumed"] == 0

    # Separate append-only run outcome events; claim identity itself never mutates.
    race = Ledger(1)
    race.consume("r4", "e" * 64, "q4", 1, 0)
    original_claim = copy.deepcopy(race.claims["r4"])
    race.record_run_event("r4", "STARTED")
    race.record_run_event("r4", "QUARANTINED")
    assert race.claims["r4"] == original_claim
    expect(Denied, lambda: race.record_run_event("r4", "STARTED"),
           "terminal run outcome cannot be reopened")
    race.check()

    # Tampering with the append-only authorization event chain is detectable.
    tampered = copy.deepcopy(race)
    tampered.auth_events[0]["details"]["claim_sequence"] = 77
    expect(AssertionError, tampered.check, "event-chain tampering must be detected")

    # Stale external revocation generation is fail-closed.
    stale = Ledger(2)
    stale.revoke("rev-stale")
    expect(Denied, lambda: stale.consume("r5", "f" * 64, "q5", 2, 0),
           "stale witness generation must deny consumption")

    print("PASS  atomic rollback before commit and durable claim after lost acknowledgement")
    print("PASS  idempotency, digest conflict and final-slot budget enforcement")
    print("PASS  both serializable claim/revocation orderings and resume denial")
    print("PASS  immutable claim identity and append-only run outcome transitions")
    print("PASS  authorization event digest chain, tamper detection and witness freshness")
    print("NOTE  synthetic in-memory model only; no PostgreSQL or production integration")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
