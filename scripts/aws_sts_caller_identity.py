#!/usr/bin/env python3
"""Read-only AWS STS caller-identity verifier around an injected client."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


ROLE_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/(.+)$")
ASSUMED_ROLE_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/([^/]+)/([^/]+)$"
)


@dataclass(frozen=True)
class StsCallerIdentityEvidence:
    expected_account_id: str
    expected_role_arn: str
    caller_account_id: str
    caller_arn: str
    caller_user_id: str
    partition: str
    role_name: str
    session_name: str
    request_id: str

    def to_dict(self, *, test_only: bool, identity_role: str) -> dict[str, Any]:
        if type(test_only) is not bool:
            raise ValueError("test_only must be an explicit boolean")
        if identity_role not in {"COLLECTOR", "INDEPENDENT_VERIFIER"}:
            raise ValueError("identity_role must be COLLECTOR or INDEPENDENT_VERIFIER")
        return {
            "profile": "sky-high-aws-sts-caller-identity-v1",
            "schemaVersion": 1,
            "testOnly": test_only,
            "identityRole": identity_role,
            "verified": True,
            "expectedAccountId": self.expected_account_id,
            "expectedRoleArn": self.expected_role_arn,
            "callerAccountId": self.caller_account_id,
            "callerArn": self.caller_arn,
            "callerUserId": self.caller_user_id,
            "partition": self.partition,
            "roleName": self.role_name,
            "sessionName": self.session_name,
            "requestId": self.request_id,
        }


class AwsStsCallerIdentityVerifier:
    """Verify the injected AWS client is operating as one expected IAM role."""

    def __init__(self, client: Any, *, expected_account_id: str, expected_role_arn: str) -> None:
        if not re.fullmatch(r"[0-9]{12}", expected_account_id):
            raise ValueError("expected_account_id must be a 12-digit AWS account ID")
        role_match = ROLE_ARN.fullmatch(expected_role_arn)
        if role_match is None:
            raise ValueError("expected_role_arn must be a supported AWS IAM role ARN")
        if role_match.group(2) != expected_account_id:
            raise ValueError("expected IAM role ARN account differs from expected_account_id")
        if not callable(getattr(client, "get_caller_identity", None)):
            raise TypeError("injected STS client must provide get_caller_identity")
        self._client = client
        self._account = expected_account_id
        self._role_arn = expected_role_arn
        self._partition = role_match.group(1)
        self._role_name = role_match.group(3).rsplit("/", 1)[-1]

    def verify(self) -> StsCallerIdentityEvidence:
        response = self._client.get_caller_identity()
        if not isinstance(response, dict):
            raise ValueError("STS GetCallerIdentity response must be an object")
        account = response.get("Account")
        arn = response.get("Arn")
        user_id = response.get("UserId")
        metadata = response.get("ResponseMetadata")
        request_id = metadata.get("RequestId") if isinstance(metadata, dict) else None
        if account != self._account:
            raise ValueError("STS caller account differs from the pinned AWS account")
        if not isinstance(arn, str) or not isinstance(user_id, str) or not user_id:
            raise ValueError("STS caller ARN or UserId is missing")
        match = ASSUMED_ROLE_ARN.fullmatch(arn)
        if match is None:
            raise ValueError("STS caller must be an assumed IAM role, not a user or root principal")
        partition, arn_account, role_name, session_name = match.groups()
        if partition != self._partition or arn_account != self._account:
            raise ValueError("STS caller ARN partition/account differs from the pinned scope")
        if role_name != self._role_name:
            raise ValueError("STS caller role name differs from the pinned IAM role")
        if not session_name:
            raise ValueError("STS assumed-role session name is missing")
        if ":" not in user_id or user_id.rsplit(":", 1)[-1] != session_name:
            raise ValueError("STS UserId session suffix differs from the assumed-role ARN")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("STS response RequestId is required for identity evidence")
        return StsCallerIdentityEvidence(
            expected_account_id=self._account,
            expected_role_arn=self._role_arn,
            caller_account_id=account,
            caller_arn=arn,
            caller_user_id=user_id,
            partition=partition,
            role_name=role_name,
            session_name=session_name,
            request_id=request_id,
        )
