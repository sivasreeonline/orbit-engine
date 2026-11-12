#!/usr/bin/env python3
"""Validate the FENCE-001 monitor gossip envelope schema and semantic invariants.

The fixtures use test-only keys/signatures. This validates message shape and
policy bindings, not cryptographic signatures, trusted time or network delivery.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs/schemas/m0-fence-monitor-gossip-envelope-v1.schema.json"
VECTORS_PATH = ROOT / "docs/test-vectors/fence-monitor-gossip-v1.json"
MAX_TTL_SECONDS = 300


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_time(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include an explicit timezone")
    return parsed


def semantic_errors(message: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    sender = message.get("sender", {})
    recipient = message.get("recipient", {})
    if sender.get("monitorId") == recipient.get("monitorId"):
        errors.append("sender and recipient monitor identities must differ")

    try:
        issued = parse_time(message["issuedAt"])
        expires = parse_time(message["expiresAt"])
        ttl = (expires - issued).total_seconds()
        if ttl <= 0 or ttl > MAX_TTL_SECONDS:
            errors.append("message expiry must be after issue time and within five minutes")
    except (KeyError, TypeError, ValueError):
        errors.append("message issue/expiry timestamps must be valid timezone-aware values")

    scope = message.get("scope")
    body = message.get("body", {})
    message_type = message.get("messageType")
    if message_type == "HEAD_ADVERTISEMENT":
        if body.get("head", {}).get("scope") != scope:
            errors.append("advertised signed head scope must equal envelope scope")
    elif message_type in ("CONSISTENCY_PROOF_REQUEST", "CONSISTENCY_PROOF_RESPONSE"):
        first = body.get("fromHead", {})
        second = body.get("toHead", {})
        if first.get("generation", 0) >= second.get("generation", 0):
            errors.append("consistency proof must bind an older head to a strictly newer head")
        if message_type == "CONSISTENCY_PROOF_RESPONSE":
            if body.get("requestMessageId") is None or body.get("requestNonce") is None:
                errors.append("proof response must bind the originating request ID and nonce")
    elif message_type == "EQUIVOCATION_ALERT":
        first = body.get("firstHead", {})
        second = body.get("secondHead", {})
        if first.get("scope") != scope or second.get("scope") != scope:
            errors.append("both equivocation heads must match the alert envelope scope")
        if first.get("generation") != second.get("generation"):
            errors.append("equivocation alert heads must have the same generation")
        if first.get("rootHash") == second.get("rootHash"):
            errors.append("equivocation alert must contain distinct signed root hashes")
    return errors


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_members)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    if not isinstance(vectors, dict) or vectors.get("testOnly") is not True:
        raise SystemExit("monitor gossip vectors must be explicitly marked testOnly")
    messages = vectors.get("messages")
    if not isinstance(messages, list) or len(messages) != 4:
        raise SystemExit("expected exactly four monitor gossip message fixtures")
    seen_ids: set[str] = set()
    seen_sequences: set[tuple[str, str, int]] = set()
    for message in messages:
        schema_errors = list(validator.iter_errors(message))
        if schema_errors:
            raise SystemExit(f"schema validation failed: {schema_errors[0].message}")
        semantic = semantic_errors(message)
        if semantic:
            raise SystemExit("semantic validation failed: " + "; ".join(semantic))
        message_id = message["messageId"]
        sequence_key = (
            message["sender"]["monitorId"],
            message["recipient"]["monitorId"],
            message["senderSequence"],
        )
        if message_id in seen_ids or sequence_key in seen_sequences:
            raise SystemExit("fixture repeats a message ID or sender/recipient sequence")
        seen_ids.add(message_id)
        seen_sequences.add(sequence_key)

    first = messages[0]
    negatives = []
    changed = json.loads(json.dumps(first))
    changed["sender"]["monitorId"] = changed["recipient"]["monitorId"]
    negatives.append(("self-addressed message", changed, "sender and recipient"))

    changed = json.loads(json.dumps(messages[1]))
    changed["body"]["fromHead"]["generation"] = 7
    negatives.append(("reversed consistency range", changed, "older head"))

    changed = json.loads(json.dumps(messages[3]))
    changed["body"]["secondHead"]["rootHash"] = changed["body"]["firstHead"]["rootHash"]
    negatives.append(("non-conflicting equivocation alert", changed, "distinct signed root hashes"))

    changed = json.loads(json.dumps(first))
    changed["expiresAt"] = "2026-11-12T00:10:00Z"
    negatives.append(("excessive message lifetime", changed, "within five minutes"))

    changed = json.loads(json.dumps(first))
    changed["body"]["head"]["scope"]["hostId"] = "different-host"
    negatives.append(("scope substitution", changed, "scope must equal"))

    for label, message, expected in negatives:
        schema_errors = list(validator.iter_errors(message))
        semantic = semantic_errors(message)
        if not schema_errors and not any(expected in error for error in semantic):
            raise AssertionError(f"negative case unexpectedly accepted: {label}")

    try:
        json.loads('{"messageId":"first","messageId":"second"}', object_pairs_hook=reject_duplicate_members)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON member was accepted")

    print("FENCE-001 monitor gossip envelope validation: PASS")
    print("Message types: HEAD_ADVERTISEMENT, CONSISTENCY_PROOF_REQUEST, CONSISTENCY_PROOF_RESPONSE, EQUIVOCATION_ALERT")
    print(f"Negative cases: {len(negatives) + 1} (including duplicate JSON member)")
    print("Scope: schema and semantic bindings only; test signatures are not cryptographically verified")


if __name__ == "__main__":
    main()
