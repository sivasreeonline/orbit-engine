#!/usr/bin/env python3
"""Synthetic-only tests for the injected AWS STS caller identity verifier."""
from __future__ import annotations

from typing import Any

from aws_sts_caller_identity import AwsStsCallerIdentityVerifier


ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/skyhigh/evidence-collector"
CALLER_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/evidence-collector/session-2026-11-20"
USER_ID = f"AROAEXAMPLEIDENTITY:session-2026-11-20"


class FakeStsClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls = 0

    def get_caller_identity(self) -> dict[str, Any]:
        self.calls += 1
        return self.response


def valid_response() -> dict[str, Any]:
    return {
        "Account": ACCOUNT,
        "Arn": CALLER_ARN,
        "UserId": USER_ID,
        "ResponseMetadata": {"RequestId": "sts-request-001"},
    }


def rejected(action, label: str) -> None:
    try:
        action()
    except (ValueError, TypeError):
        return
    raise AssertionError(f"expected fail-closed rejection: {label}")


def main() -> None:
    client = FakeStsClient(valid_response())
    verifier = AwsStsCallerIdentityVerifier(
        client, expected_account_id=ACCOUNT, expected_role_arn=ROLE_ARN
    )
    evidence = verifier.verify()
    result = evidence.to_dict(test_only=True, identity_role="COLLECTOR")
    assert client.calls == 1
    assert result["verified"] is True
    assert result["callerAccountId"] == ACCOUNT
    assert result["expectedRoleArn"] == ROLE_ARN
    assert result["roleName"] == "evidence-collector"
    assert result["sessionName"] == "session-2026-11-20"
    assert result["requestId"] == "sts-request-001"
    print("PASS STS caller identity is pinned to expected account and assumed role")

    wrong_account = valid_response()
    wrong_account["Account"] = "999999999999"
    rejected(
        lambda: AwsStsCallerIdentityVerifier(
            FakeStsClient(wrong_account),
            expected_account_id=ACCOUNT,
            expected_role_arn=ROLE_ARN,
        ).verify(),
        "wrong account",
    )

    wrong_role = valid_response()
    wrong_role["Arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/unexpected-role/session-2026-11-20"
    rejected(
        lambda: AwsStsCallerIdentityVerifier(
            FakeStsClient(wrong_role),
            expected_account_id=ACCOUNT,
            expected_role_arn=ROLE_ARN,
        ).verify(),
        "wrong assumed role",
    )

    user_principal = valid_response()
    user_principal["Arn"] = f"arn:aws:iam::{ACCOUNT}:user/some-user"
    rejected(
        lambda: AwsStsCallerIdentityVerifier(
            FakeStsClient(user_principal),
            expected_account_id=ACCOUNT,
            expected_role_arn=ROLE_ARN,
        ).verify(),
        "IAM user principal",
    )

    missing_request_id = valid_response()
    missing_request_id["ResponseMetadata"] = {}
    rejected(
        lambda: AwsStsCallerIdentityVerifier(
            FakeStsClient(missing_request_id),
            expected_account_id=ACCOUNT,
            expected_role_arn=ROLE_ARN,
        ).verify(),
        "missing STS request ID",
    )

    rejected(
        lambda: AwsStsCallerIdentityVerifier(
            FakeStsClient(valid_response()),
            expected_account_id=ACCOUNT,
            expected_role_arn=f"arn:aws:iam::999999999999:role/other",
        ),
        "expected role ARN account mismatch",
    )
    print("PASS wrong account, role, user principal and missing request ID are rejected")

    rejected(lambda: evidence.to_dict(test_only="false", identity_role="COLLECTOR"), "non-boolean testOnly")
    rejected(lambda: evidence.to_dict(test_only=True, identity_role="OTHER"), "invalid identity role")
    print("STS identity tests passed; synthetic client only, no AWS credentials or API calls.")


if __name__ == "__main__":
    main()
