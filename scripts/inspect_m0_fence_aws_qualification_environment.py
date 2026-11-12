#!/usr/bin/env python3
"""Read-only AWS environment preflight for the first FENCE-001 qualification target.

This command inspects existing resources only. It never creates, changes, deletes,
uploads, restores, or attempts privileged mutations against AWS resources.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

PROFILE = "sky-high-fence-aws-read-only-preflight-v1"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
REGION = re.compile(r"^[a-z0-9-]{3,32}$")
READ_ONLY_OPERATIONS = (
    "sts:GetCallerIdentity",
    "dynamodb:DescribeTable",
    "dynamodb:DescribeContinuousBackups",
    "s3:GetBucketLocation",
    "s3:GetBucketVersioning",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketPublicAccessBlock",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "cloudtrail:GetEventSelectors",
)


class PreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def load_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreflightError(f"cannot read preflight configuration: {type(exc).__name__}") from exc
    require(isinstance(value, dict), "configuration root must be an object")
    allowed = {
        "profile", "qualificationRunId", "accountId", "region",
        "expectedCallerArnPrefix", "dynamodbTableName", "evidenceBucketName",
        "cloudTrailArn", "cloudTrailLogBucketName",
    }
    require(set(value) == allowed, "configuration must contain exactly the documented fields")
    require(value["profile"] == PROFILE, "unsupported AWS preflight configuration profile")
    for key in ("qualificationRunId", "dynamodbTableName", "evidenceBucketName", "cloudTrailLogBucketName"):
        require(isinstance(value[key], str) and SAFE_NAME.fullmatch(value[key]) is not None,
                f"{key} must be a safe non-empty identifier")
    require(isinstance(value["accountId"], str) and ACCOUNT.fullmatch(value["accountId"]) is not None,
            "accountId must be a 12-digit AWS account ID")
    require(isinstance(value["region"], str) and REGION.fullmatch(value["region"]) is not None,
            "region must be a valid-looking AWS Region identifier")
    prefix = value["expectedCallerArnPrefix"]
    require(isinstance(prefix, str) and prefix.startswith(
        f"arn:aws:sts::{value['accountId']}:assumed-role/") and prefix.endswith("/"),
        "expectedCallerArnPrefix must pin an assumed-role ARN prefix in the expected account and end with '/'")
    trail_arn = value["cloudTrailArn"]
    arn_prefix = f"arn:aws:cloudtrail:{value['region']}:{value['accountId']}:trail/"
    require(isinstance(trail_arn, str) and trail_arn.startswith(arn_prefix)
            and SAFE_NAME.fullmatch(trail_arn[len(arn_prefix):]) is not None,
            "cloudTrailArn must pin a named trail in the expected account and Region")
    require(value["evidenceBucketName"] != value["cloudTrailLogBucketName"],
            "evidence bucket and CloudTrail log bucket must be separate")
    return value


def add_check(checks: list[dict[str, Any]], check_id: str, status: str,
              observed: Any, detail: str) -> None:
    checks.append({"id": check_id, "status": status, "observed": observed, "detail": detail})


def error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        if isinstance(error, dict) and isinstance(error.get("Code"), str):
            return error["Code"]
    return type(exc).__name__


def values_cover(values: list[str], target: str, *, prefix: bool = False) -> bool:
    for value in values:
        if value == "*" or value == target:
            return True
        if prefix and target.startswith(value):
            return True
        if prefix and value.startswith(target):
            return True
    return False


def selector_write_capable(selector: dict[str, Any]) -> bool:
    return selector.get("ReadWriteType", "All") in {"All", "WriteOnly"}


def basic_selector_covers(selectors: list[dict[str, Any]], resource_type: str,
                          resource_arn: str, *, prefix: bool = False) -> bool:
    for selector in selectors:
        if not selector_write_capable(selector):
            continue
        for resource in selector.get("DataResources", []):
            if resource.get("Type") != resource_type:
                continue
            values = resource.get("Values", [])
            if isinstance(values, list) and values_cover(values, resource_arn, prefix=prefix):
                return True
    return False


def advanced_selector_covers(selectors: list[dict[str, Any]], resource_type: str,
                             resource_arn: str, *, prefix: bool = False) -> bool:
    for selector in selectors:
        fields = {
            item.get("Field"): item
            for item in selector.get("FieldSelectors", [])
            if isinstance(item, dict) and isinstance(item.get("Field"), str)
        }
        category = fields.get("eventCategory")
        resource = fields.get("resources.type")
        if not category or "Data" not in category.get("Equals", []):
            continue
        if not resource or resource_type not in resource.get("Equals", []):
            continue

        read_only = fields.get("readOnly")
        if read_only and "false" not in read_only.get("Equals", []) \
                and "true" in read_only.get("Equals", []):
            continue

        arn_filter = fields.get("resources.ARN")
        if arn_filter is None:
            return True
        exact = arn_filter.get("Equals", [])
        starts = arn_filter.get("StartsWith", [])
        if values_cover(exact, resource_arn, prefix=prefix) \
                or values_cover(starts, resource_arn, prefix=True):
            return True
    return False


def inspect_event_coverage(selector_response: dict[str, Any], bucket: str,
                           table_arn: str) -> dict[str, bool]:
    basic = selector_response.get("EventSelectors", [])
    advanced = selector_response.get("AdvancedEventSelectors", [])
    s3_target = f"arn:aws:s3:::{bucket}/"
    s3_ok = (
        basic_selector_covers(basic, "AWS::S3::Object", s3_target, prefix=True)
        or advanced_selector_covers(advanced, "AWS::S3::Object", s3_target, prefix=True)
    )
    ddb_ok = (
        basic_selector_covers(basic, "AWS::DynamoDB::Table", table_arn)
        or advanced_selector_covers(advanced, "AWS::DynamoDB::Table", table_arn)
    )
    return {"s3ObjectWrites": s3_ok, "dynamodbTableWrites": ddb_ok}


def make_report(config: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    blockers = [item["id"] for item in checks if item["status"] == "BLOCK"]
    warnings = [item["id"] for item in checks if item["status"] == "WARN"]
    return {
        "profile": PROFILE,
        "qualificationRunId": config["qualificationRunId"],
        "provider": "AWS",
        "accountId": config["accountId"],
        "region": config["region"],
        "result": "READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION" if not blockers else "BLOCKED",
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "apiOperationsAttempted": list(READ_ONLY_OPERATIONS),
        "readOnlyInspection": True,
        "resourceMutationsPerformed": False,
        "privilegedMutationAttemptsPerformed": False,
        "restoreOperationsPerformed": False,
        "productionApproval": False,
        "hostAdmissionEnabled": False,
        "limitations": [
            "A read-only preflight is not provider qualification and does not prove service behavior under concurrency, failure, restore or privileged attack.",
            "The IAM policy simulator and live denial tests are not run by this command.",
            "CloudTrail digest-chain signatures and log-file hashes still require independent verification after a real qualification event window.",
            "Identity separation, account ownership, trust-root governance and independent failure domains require independent evidence.",
        ],
    }


def inspect_aws(config: dict[str, Any], session: Any) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    account_id = config["accountId"]
    region = config["region"]
    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{config['dynamodbTableName']}"
    trail_arn = config["cloudTrailArn"]

    try:
        identity = session.client("sts", region_name=region).get_caller_identity()
        actual_account = identity.get("Account")
        actual_arn = identity.get("Arn", "")
        identity_ok = actual_account == account_id and actual_arn.startswith(config["expectedCallerArnPrefix"])
        add_check(checks, "AWS-IDENTITY-001", "PASS" if identity_ok else "BLOCK",
                  {"accountId": actual_account, "callerArn": actual_arn},
                  "Caller account and assumed-role ARN prefix match operator-pinned values."
                  if identity_ok else "Caller account or assumed-role ARN prefix does not match the pinned qualification identity.")
    except Exception as exc:
        add_check(checks, "AWS-IDENTITY-001", "BLOCK", {"errorCode": error_code(exc)},
                  "Could not authenticate the AWS caller identity.")
        return make_report(config, checks)

    try:
        ddb = session.client("dynamodb", region_name=region)
        response = ddb.describe_table(TableName=config["dynamodbTableName"])
        table = response.get("Table", {})
        observed_arn = table.get("TableArn")
        table_ok = observed_arn == table_arn and table.get("TableStatus") == "ACTIVE"
        add_check(checks, "AWS-WITNESS-001", "PASS" if table_ok else "BLOCK",
                  {"tableArn": observed_arn, "tableStatus": table.get("TableStatus")},
                  "DynamoDB table is ACTIVE in the pinned account and Region."
                  if table_ok else "DynamoDB table ARN, account, Region or ACTIVE state does not match.")
        sse = table.get("SSEDescription", {})
        sse_ok = sse.get("Status") == "ENABLED"
        add_check(checks, "AWS-WITNESS-002", "PASS" if sse_ok else "BLOCK",
                  {"status": sse.get("Status"), "type": sse.get("SSEType")},
                  "DynamoDB server-side encryption is enabled." if sse_ok
                  else "DynamoDB server-side encryption is not reported as enabled.")
        backups = ddb.describe_continuous_backups(TableName=config["dynamodbTableName"])
        pitr = backups.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {})
        pitr_status = pitr.get("PointInTimeRecoveryStatus")
        pitr_ok = pitr_status == "ENABLED"
        add_check(checks, "AWS-WITNESS-003", "PASS" if pitr_ok else "BLOCK",
                  {"pointInTimeRecoveryStatus": pitr_status},
                  "DynamoDB point-in-time recovery is enabled." if pitr_ok
                  else "DynamoDB point-in-time recovery must be enabled before qualification.")
    except Exception as exc:
        add_check(checks, "AWS-WITNESS-001", "BLOCK", {"errorCode": error_code(exc)},
                  "Could not inspect the pinned DynamoDB witness table and backup configuration.")

    evidence_bucket = config["evidenceBucketName"]
    try:
        s3 = session.client("s3", region_name=region)
        location = s3.get_bucket_location(Bucket=evidence_bucket).get("LocationConstraint")
        bucket_region = location or "us-east-1"
        region_ok = bucket_region == region
        add_check(checks, "AWS-EVIDENCE-001", "PASS" if region_ok else "BLOCK",
                  {"bucketRegion": bucket_region},
                  "Evidence bucket is in the pinned Region." if region_ok
                  else "Evidence bucket Region differs from the pinned qualification Region.")
        versioning = s3.get_bucket_versioning(
            Bucket=evidence_bucket, ExpectedBucketOwner=account_id
        )
        versioning_status = versioning.get("Status")
        versioning_ok = versioning_status == "Enabled"
        add_check(checks, "AWS-EVIDENCE-002", "PASS" if versioning_ok else "BLOCK",
                  {"versioningStatus": versioning_status},
                  "S3 versioning is enabled." if versioning_ok
                  else "S3 versioning must be Enabled; Suspended or absent is unacceptable.")
        lock = s3.get_object_lock_configuration(
            Bucket=evidence_bucket, ExpectedBucketOwner=account_id
        ).get("ObjectLockConfiguration", {})
        default_retention = lock.get("Rule", {}).get("DefaultRetention", {})
        retention_days = default_retention.get("Days", 0)
        retention_years = default_retention.get("Years", 0)
        duration_days = (retention_days or 0) + (retention_years or 0) * 365
        lock_ok = (
            lock.get("ObjectLockEnabled") == "Enabled"
            and default_retention.get("Mode") == "COMPLIANCE"
            and duration_days >= 7
        )
        add_check(checks, "AWS-EVIDENCE-003", "PASS" if lock_ok else "BLOCK",
                  {"objectLockEnabled": lock.get("ObjectLockEnabled"),
                   "defaultRetentionMode": default_retention.get("Mode"),
                   "defaultRetentionDaysEquivalent": duration_days},
                  "S3 Object Lock has a default COMPLIANCE retention of at least seven days."
                  if lock_ok else "S3 Object Lock must be enabled with default COMPLIANCE retention of at least seven days.")
        public_access = s3.get_public_access_block(
            Bucket=evidence_bucket, ExpectedBucketOwner=account_id
        ).get("PublicAccessBlockConfiguration", {})
        public_flags = (
            "BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets",
        )
        public_ok = all(public_access.get(flag) is True for flag in public_flags)
        add_check(checks, "AWS-EVIDENCE-004", "PASS" if public_ok else "BLOCK",
                  {flag: public_access.get(flag) for flag in public_flags},
                  "All four bucket-level S3 Block Public Access controls are enabled."
                  if public_ok else "All four bucket-level S3 Block Public Access controls must be explicitly enabled.")
        try:
            encryption = s3.get_bucket_encryption(
                Bucket=evidence_bucket, ExpectedBucketOwner=account_id
            ).get("ServerSideEncryptionConfiguration", {})
            rules = encryption.get("Rules", [])
            algorithm = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") if rules else None
            add_check(checks, "AWS-EVIDENCE-005", "PASS" if algorithm in {"AES256", "aws:kms", "aws:kms:dsse"} else "WARN",
                      {"defaultEncryptionAlgorithm": algorithm},
                      "An explicit S3 default encryption algorithm is configured."
                      if algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}
                      else "No recognized explicit default encryption rule was returned; confirm the bucket's effective default encryption before qualification.")
        except Exception as exc:
            add_check(checks, "AWS-EVIDENCE-005", "WARN", {"errorCode": error_code(exc)},
                      "Could not inspect explicit S3 default encryption; confirm effective encryption separately.")
    except Exception as exc:
        add_check(checks, "AWS-EVIDENCE-001", "BLOCK", {"errorCode": error_code(exc)},
                  "Could not inspect the pinned S3 evidence bucket, versioning, Object Lock and public-access controls.")

    try:
        cloudtrail = session.client("cloudtrail", region_name=region)
        trails = cloudtrail.describe_trails(
            trailNameList=[trail_arn], includeShadowTrails=False
        ).get("trailList", [])
        trail = next((item for item in trails if item.get("TrailARN") == trail_arn), None)
        if trail is None:
            add_check(checks, "AWS-AUDIT-001", "BLOCK", {"trailFound": False},
                      "The exact account/Region CloudTrail ARN was not returned.")
        else:
            trail_checks = (
                ("AWS-AUDIT-001", "IsMultiRegionTrail", True,
                 "CloudTrail must be a multi-Region trail."),
                ("AWS-AUDIT-002", "IncludeGlobalServiceEvents", True,
                 "CloudTrail must include global service events."),
                ("AWS-AUDIT-003", "LogFileValidationEnabled", True,
                 "CloudTrail log-file integrity validation must be enabled."),
            )
            for check_id, field, expected_value, description in trail_checks:
                ok = trail.get(field) is expected_value
                add_check(checks, check_id, "PASS" if ok else "BLOCK",
                          {field: trail.get(field)}, description if not ok else f"{field} is enabled.")
            trail_bucket_ok = trail.get("S3BucketName") == config["cloudTrailLogBucketName"]
            add_check(checks, "AWS-AUDIT-004", "PASS" if trail_bucket_ok else "BLOCK",
                      {"trailLogBucket": trail.get("S3BucketName"),
                       "expectedLogBucket": config["cloudTrailLogBucketName"]},
                      "Trail delivers to the separately pinned audit log bucket."
                      if trail_bucket_ok else "Trail destination bucket does not match the separately pinned audit log bucket.")
            try:
                status = cloudtrail.get_trail_status(Name=trail_arn)
                logging_ok = status.get("IsLogging") is True
                no_digest_error = not status.get("LatestDigestDeliveryError")
                add_check(checks, "AWS-AUDIT-005", "PASS" if logging_ok and no_digest_error else "BLOCK",
                          {"isLogging": status.get("IsLogging"),
                           "latestDeliveryError": status.get("LatestDeliveryError"),
                           "latestDigestDeliveryError": status.get("LatestDigestDeliveryError"),
                           "latestDigestDeliveryTime": status.get("LatestDigestDeliveryTime")},
                          "CloudTrail is logging and reports no latest digest-delivery error."
                          if logging_ok and no_digest_error
                          else "CloudTrail must be actively logging and have no latest digest-delivery error.")
                if not status.get("LatestDigestDeliveryTime"):
                    add_check(checks, "AWS-AUDIT-006", "WARN",
                              {"latestDigestDeliveryTime": None},
                              "No digest delivery timestamp is present yet; verify the first complete digest chain after a real event window.")
            except Exception as exc:
                add_check(checks, "AWS-AUDIT-005", "BLOCK", {"errorCode": error_code(exc)},
                          "Could not inspect CloudTrail logging and digest-delivery status.")

            try:
                selector_response = cloudtrail.get_event_selectors(TrailName=trail_arn)
                coverage = inspect_event_coverage(
                    selector_response, evidence_bucket, table_arn
                )
                for check_id, field, description in (
                    ("AWS-AUDIT-007", "s3ObjectWrites",
                     "CloudTrail must record write data events for objects in the exact evidence bucket."),
                    ("AWS-AUDIT-008", "dynamodbTableWrites",
                     "CloudTrail must record write data events for the exact DynamoDB witness table."),
                ):
                    ok = coverage[field]
                    add_check(checks, check_id, "PASS" if ok else "BLOCK",
                              {field: ok}, description if not ok else f"Required {field} coverage is present.")
            except Exception as exc:
                add_check(checks, "AWS-AUDIT-007", "BLOCK", {"errorCode": error_code(exc)},
                          "Could not inspect CloudTrail basic or advanced event selectors.")
    except Exception as exc:
        add_check(checks, "AWS-AUDIT-001", "BLOCK", {"errorCode": error_code(exc)},
                  "Could not inspect the pinned CloudTrail trail.")

    report = make_report(config, checks)
    report["resourcePins"] = {
        "dynamodbTableArn": table_arn,
        "evidenceBucketName": evidence_bucket,
        "cloudTrailArn": trail_arn,
        "cloudTrailLogBucketName": config["cloudTrailLogBucketName"],
    }
    return report


def write_new_report(path: Path, report: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise PreflightError("refusing to overwrite an existing or symbolic-link report path")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError as exc:
        raise PreflightError("report path was created concurrently; refusing overwrite") from exc


class FakeClient:
    def __init__(self, service: str, config: dict[str, Any], scenario: str = "success") -> None:
        self.service = service
        self.config = config
        self.scenario = scenario
        self.calls: list[str] = []

    def _called(self, name: str) -> None:
        self.calls.append(name)

    def get_caller_identity(self) -> dict[str, str]:
        self._called("get_caller_identity")
        return {"Account": self.config["accountId"],
                "Arn": self.config["expectedCallerArnPrefix"] + "session-fixture"}

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self._called("describe_table")
        return {"Table": {
            "TableArn": f"arn:aws:dynamodb:{self.config['region']}:{self.config['accountId']}:table/{self.config['dynamodbTableName']}",
            "TableStatus": "ACTIVE", "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS"},
        }}

    def describe_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        self._called("describe_continuous_backups")
        return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {
            "PointInTimeRecoveryStatus": "DISABLED" if self.scenario == "pitr-disabled" else "ENABLED"
        }}}

    def get_bucket_location(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_bucket_location")
        return {"LocationConstraint": self.config["region"]}

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_bucket_versioning")
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_object_lock_configuration")
        mode = "GOVERNANCE" if self.scenario == "governance-only" else "COMPLIANCE"
        return {"ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": mode, "Days": 14}},
        }}

    def get_public_access_block(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_public_access_block")
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}

    def get_bucket_encryption(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_bucket_encryption")
        return {"ServerSideEncryptionConfiguration": {"Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}
        }]}}

    def describe_trails(self, **kwargs: Any) -> dict[str, Any]:
        self._called("describe_trails")
        return {"trailList": [{
            "TrailARN": self.config["cloudTrailArn"],
            "IsMultiRegionTrail": True,
            "IncludeGlobalServiceEvents": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": self.config["cloudTrailLogBucketName"],
        }]}

    def get_trail_status(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_trail_status")
        return {"IsLogging": True, "LatestDigestDeliveryTime": 1,
                "LatestDigestDeliveryError": None, "LatestDeliveryError": None}

    def get_event_selectors(self, **kwargs: Any) -> dict[str, Any]:
        self._called("get_event_selectors")
        table_arn = f"arn:aws:dynamodb:{self.config['region']}:{self.config['accountId']}:table/{self.config['dynamodbTableName']}"
        return {
            "EventSelectors": [{
                "ReadWriteType": "All",
                "DataResources": [
                    {"Type": "AWS::S3::Object", "Values": [f"arn:aws:s3:::{self.config['evidenceBucketName']}/"]},
                    {"Type": "AWS::DynamoDB::Table", "Values": [table_arn]},
                ],
            }]
        }


class FakeSession:
    def __init__(self, config: dict[str, Any], scenario: str = "success") -> None:
        self.clients = {name: FakeClient(name, config, scenario)
                        for name in ("sts", "dynamodb", "s3", "cloudtrail")}

    def client(self, name: str, **kwargs: Any) -> FakeClient:
        return self.clients[name]


def fixture_config() -> dict[str, Any]:
    return {
        "profile": PROFILE,
        "qualificationRunId": "run-fixture-001",
        "accountId": "123456789012",
        "region": "ap-south-1",
        "expectedCallerArnPrefix": "arn:aws:sts::123456789012:assumed-role/SkyHighFenceReadOnly/",
        "dynamodbTableName": "sky-high-fence-witness",
        "evidenceBucketName": "sky-high-fence-evidence-fixture",
        "cloudTrailArn": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/sky-high-fence-audit",
        "cloudTrailLogBucketName": "sky-high-fence-cloudtrail-fixture",
    }


def self_test() -> None:
    config = fixture_config()
    session = FakeSession(config)
    report = inspect_aws(config, session)
    require(report["result"] == "READY_FOR_READ_ONLY_AWS_ADAPTER_IMPLEMENTATION",
            f"valid read-only fixture did not pass: {report['blockers']}")
    require(report["resourceMutationsPerformed"] is False
            and report["privilegedMutationAttemptsPerformed"] is False
            and report["restoreOperationsPerformed"] is False,
            "read-only fixture claimed a mutating operation")

    for scenario, blocker in (
        ("governance-only", "AWS-EVIDENCE-003"),
        ("pitr-disabled", "AWS-WITNESS-003"),
    ):
        candidate = inspect_aws(config, FakeSession(config, scenario))
        require(blocker in candidate["blockers"], f"unsafe fixture {scenario} did not block")

    bad_identity = FakeSession(config)
    bad_identity.clients["sts"].get_caller_identity = lambda: {
        "Account": "999999999999", "Arn": "arn:aws:sts::999999999999:assumed-role/Other/session"
    }
    blocked = inspect_aws(config, bad_identity)
    require(blocked["result"] == "BLOCKED" and len(blocked["checks"]) == 1,
            "wrong caller account did not stop resource inspection")

    bad_selectors = FakeSession(config)
    bad_selectors.clients["cloudtrail"].get_event_selectors = lambda **kwargs: {"EventSelectors": []}
    selector_report = inspect_aws(config, bad_selectors)
    require("AWS-AUDIT-007" in selector_report["blockers"]
            and "AWS-AUDIT-008" in selector_report["blockers"],
            "missing CloudTrail data-event selectors were not detected")

    try:
        malformed = dict(config, expectedCallerArnPrefix="arn:aws:iam::123456789012:role/NotAssumedRole")
        require(malformed["expectedCallerArnPrefix"].startswith(
            f"arn:aws:sts::{malformed['accountId']}:assumed-role/")
            and malformed["expectedCallerArnPrefix"].endswith("/"),
            "expectedCallerArnPrefix must pin an assumed-role ARN prefix")
    except PreflightError:
        pass
    else:
        raise AssertionError("malformed caller ARN prefix was accepted")

    print("FENCE-001 AWS read-only preflight self-test: PASS (1 valid fixture + 4 fail-closed checks)")
    print("Synthetic clients only; no AWS SDK credentials, account calls, resource mutations or production approval.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile-name")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.config or not args.output:
        parser.error("--config and --output are required outside --self-test")
    config = load_config(args.config)
    try:
        import boto3
    except ImportError as exc:
        raise SystemExit("boto3 is required only for live AWS inspection; install the pinned qualification requirements") from exc
    session = boto3.Session(profile_name=args.profile_name, region_name=config["region"])
    report = inspect_aws(config, session)
    write_new_report(args.output, report)
    print(json.dumps({
        "result": report["result"],
        "accountId": report["accountId"],
        "region": report["region"],
        "blockers": report["blockers"],
        "warnings": report["warnings"],
        "reportPath": str(args.output),
        "readOnlyInspection": True,
    }, indent=2))
    if report["blockers"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
