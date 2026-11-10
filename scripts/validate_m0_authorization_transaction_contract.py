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
        self.run_events.append({"run_id": run_id, "seq": 1, "kind": "CLAIMED",
                                "request_id": request_id, "request_digest": request_digest})
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

    def record_run_event(self, run_id, kind, request_id, request_digest):
        prior = next((event for event in self.run_events
                      if event.get("request_id") == request_id), None)
        if prior:
            if (prior["run_id"] != run_id or prior["kind"] != kind
                    or prior["request_digest"] != request_digest):
                raise Conflict("run-event request ID reused with changed content")
            return "EXISTING"

        transitions = {
            "CLAIMED": {"STARTED", "FAILED", "QUARANTINED"},
            "STARTED": {"COMPLETED", "FAILED", "QUARANTINED"},
            "COMPLETED": set(), "FAILED": set(), "QUARANTINED": set(),
        }
        history = [event for event in self.run_events if event["run_id"] == run_id]
        if not history:
            raise Denied("claim does not exist")
        if kind not in transitions[history[-1]["kind"]]:
            raise Denied("illegal or terminal run-event transition")
        self.run_events.append({"run_id": run_id, "seq": len(history) + 1, "kind": kind,
                                "request_id": request_id, "request_digest": request_digest})
        return "CREATED"

    def update_claim(self, run_id, fields):
        raise Denied("immutable claim rows cannot be updated")

    def delete_claim(self, run_id):
        raise Denied("immutable claim rows cannot be deleted")

    def quarantine_counter_drift(self):
        if self.auth["consumed"] != len(self.claims):
            self.auth["state"] = "QUARANTINED"
            self.auth["version"] += 1
            self.append_auth_event("COUNTER_DRIFT_QUARANTINED", None, "counter-drift",
                                   {"stored_count": self.auth["consumed"], "claim_count": len(self.claims)})
            return True
        return False

    def check(self):
        assert self.auth["consumed"] == len(self.claims)
        assert self.auth["consumed"] <= self.auth["budget"]
        assert len(self.requests) == len(self.claims)
        for index, event in enumerate(self.auth_events):
            assert event["seq"] == index + 1
            assert event["previous"] == (self.auth_events[index - 1]["digest"] if index else "0" * 64)
            material = {key: value for key, value in event.items() if key != "digest"}
            assert event["digest"] == digest(material)
        return True


def expect(exception, callback, label):
    try:
        callback()
    except exception:
        return
    raise AssertionError(label)


def main():
    ledger = Ledger(1)
    result = ledger.consume("r1", "a" * 64, "q1", 1, 0, "before_commit")
    assert result["result"] == "ROLLED_BACK"
    assert ledger.auth["consumed"] == 0 and not ledger.claims
    assert not ledger.auth_events and not ledger.run_events

    result = ledger.consume("r1", "a" * 64, "q1", 1, 0, "after_commit")
    assert result["result"] == "ACK_LOST"
    assert ledger.auth["consumed"] == 1
    assert ledger.consume("r1", "a" * 64, "q1-retry", 2, 0)["result"] == "EXISTING"
    expect(Conflict, lambda: ledger.consume("r1", "b" * 64, "q-conflict", 2, 0),
           "changed request digest must conflict")
    expect(Denied, lambda: ledger.consume("r2", "c" * 64, "q2", 2, 0),
           "final budget slot must not be over-consumed")
    ledger.check()

    ledger.revoke("rev1")
    assert ledger.consume("r1", "a" * 64, "resolve", 3, 1)["resume_allowed"] is False
    expect(Denied, lambda: ledger.consume("r2", "c" * 64, "q-after-revoke", 3, 1),
           "new claim after revocation must fail")

    reverse = Ledger(1)
    reverse.revoke("rev-first")
    expect(Denied, lambda: reverse.consume("r3", "d" * 64, "q3", 1, 1),
           "claim after committed revocation must fail")
    assert not reverse.claims and reverse.auth["consumed"] == 0

    race = Ledger(1)
    race.consume("r4", "e" * 64, "q4", 1, 0)
    original_claim = copy.deepcopy(race.claims["r4"])
    assert race.record_run_event("r4", "STARTED", "start-r4", "1" * 64) == "CREATED"
    assert race.record_run_event("r4", "STARTED", "start-r4", "1" * 64) == "EXISTING"
    expect(Conflict, lambda: race.record_run_event("r4", "STARTED", "start-r4", "2" * 64),
           "run-event request ID with changed digest must conflict")
    race.record_run_event("r4", "QUARANTINED", "quarantine-r4", "3" * 64)
    assert race.claims["r4"] == original_claim
    expect(Denied, lambda: race.record_run_event("r4", "STARTED", "reopen-r4", "4" * 64),
           "terminal run outcome cannot be reopened")
    expect(Denied, lambda: race.update_claim("r4", {"request_digest": "z" * 64}),
           "claim identity update must be denied")
    expect(Denied, lambda: race.delete_claim("r4"),
           "claim identity deletion must be denied")
    race.check()

    # Both serial orders of two claimers competing for the final slot.
    for order in (("left", "right"), ("right", "left")):
        contested = Ledger(1)
        winners = []
        for run_id in order:
            try:
                result = contested.consume(run_id, run_id[0] * 64, "req-" + run_id,
                                           1 + len(winners), 0)
                if result["result"] == "CREATED":
                    winners.append(run_id)
            except Denied:
                pass
        assert len(winners) == 1 and contested.auth["consumed"] == 1
        contested.check()

    drift = Ledger(2)
    drift.consume("r-drift", "g" * 64, "q-drift", 1, 0)
    drift.auth["consumed"] = 0
    assert drift.quarantine_counter_drift()
    assert drift.auth["state"] == "QUARANTINED"
    assert drift.auth["consumed"] == 0 and "r-drift" in drift.claims

    tampered = copy.deepcopy(race)
    tampered.auth_events[0]["details"]["claim_sequence"] = 77
    expect(AssertionError, tampered.check, "event-chain tampering must be detected")

    stale = Ledger(2)
    stale.revoke("rev-stale")
    expect(Denied, lambda: stale.consume("r5", "f" * 64, "q5", 2, 0),
           "stale witness generation must deny consumption")

    print("PASS  atomic rollback before commit and durable claim after lost acknowledgement")
    print("PASS  idempotency, digest conflict and final-slot budget enforcement")
    print("PASS  both serializable claim/revocation orderings and resume denial")
    print("PASS  immutable claim identity, mutation denial and append-only run outcome transitions")
    print("PASS  both final-slot contender orders, run-event idempotency and counter-drift quarantine")
    print("PASS  authorization event digest chain, tamper detection and witness freshness")
    print("NOTE  synthetic in-memory model only; no PostgreSQL or production integration")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
