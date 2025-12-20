from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.aws import client
from aws_audit.models import CheckResult, Finding, Severity
from aws_audit.utils import log


def check_s3_public_access_block(ses) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        s3c = client(ses, "s3control")
        account_id = client(ses, "sts").get_caller_identity()["Account"]
        resp = s3c.get_public_access_block(AccountId=account_id)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        required = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        missing = [k for k in required if not cfg.get(k, False)]
        if missing:
            findings.append(
                Finding(
                    service="s3",
                    resource_id=f"account:{account_id}",
                    title="S3 Public Access Block not fully enabled (account)",
                    severity=Severity.HIGH,
                    detail=f"Missing/disabled settings: {', '.join(missing)}",
                    recommendation="Enable all S3 Public Access Block settings at account level.",
                    metadata={"config": cfg},
                )
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code == "NoSuchPublicAccessBlockConfiguration":
            findings.append(
                Finding(
                    service="s3",
                    resource_id="account",
                    title="S3 Public Access Block not configured (account)",
                    severity=Severity.HIGH,
                    detail="No account-level Public Access Block configuration found.",
                    recommendation="Configure S3 Public Access Block at account level.",
                )
            )
        else:
            msg = f"S3 account-level check skipped (permissions/error): {e}"
            log().warning(msg)
            warnings.append(msg)
            skipped = True
    except BotoCoreError as e:
        msg = f"S3 account-level check skipped (error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True
    return CheckResult(
        service="s3",
        name="account_public_access_block",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )


def check_s3_public_buckets(ses) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        s3 = client(ses, "s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            try:
                status = s3.get_bucket_policy_status(Bucket=name)
                is_public = status.get("PolicyStatus", {}).get("IsPublic", False)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code in {"NoSuchBucketPolicy", "NoSuchBucket"}:
                    is_public = False
                elif code == "AccessDenied":
                    warnings.append(f"Bucket {name}: access denied when reading policy status.")
                    continue
                else:
                    warnings.append(f"Bucket {name}: policy status check failed: {e}")
                    continue

            if is_public:
                findings.append(
                    Finding(
                        service="s3",
                        resource_id=name,
                        title="S3 bucket policy allows public access",
                        severity=Severity.HIGH,
                        detail=f"Bucket '{name}' policy is public.",
                        recommendation="Restrict bucket policy and enable Public Access Block.",
                    )
                )

            try:
                pab = s3.get_public_access_block(Bucket=name).get(
                    "PublicAccessBlockConfiguration", {}
                )
                missing = [
                    k
                    for k in [
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    ]
                    if not pab.get(k, False)
                ]
                if missing:
                    findings.append(
                        Finding(
                            service="s3",
                            resource_id=name,
                            title="S3 bucket Public Access Block incomplete",
                            severity=Severity.HIGH,
                            detail=f"Bucket '{name}' missing settings: {', '.join(missing)}",
                            recommendation="Enable full Public Access Block on the bucket.",
                            metadata={"missing": missing},
                        )
                    )
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(
                        Finding(
                            service="s3",
                            resource_id=name,
                            title="S3 bucket Public Access Block not configured",
                            severity=Severity.HIGH,
                            detail=f"Bucket '{name}' has no Public Access Block configuration.",
                            recommendation="Configure Public Access Block on the bucket.",
                        )
                    )
                elif code == "AccessDenied":
                    warnings.append(f"Bucket {name}: access denied for Public Access Block.")
                else:
                    warnings.append(f"Bucket {name}: error reading PAB: {e}")

    except (ClientError, BotoCoreError) as e:
        msg = f"S3 bucket-level check skipped (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True

    return CheckResult(
        service="s3",
        name="bucket_public_access",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )
