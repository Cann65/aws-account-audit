from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.aws import client
from aws_audit.models import CheckResult, Finding, Severity
from aws_audit.utils import log


def check_cloudfront_https(ses) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        cf = client(ses, "cloudfront")
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            for d in items:
                did = d.get("Id", "unknown")
                origins = d.get("Origins", {}).get("Items", [])
                default_behavior = d.get("DefaultCacheBehavior", {})
                vpp = default_behavior.get("ViewerProtocolPolicy", "unknown")
                if vpp in ("allow-all", "unknown"):
                    findings.append(
                        Finding(
                            service="cloudfront",
                            resource_id=did,
                            title="CloudFront does not enforce HTTPS",
                            severity=Severity.MEDIUM,
                            detail=f"Distribution {did} ViewerProtocolPolicy is '{vpp}'.",
                            recommendation="Set ViewerProtocolPolicy to 'redirect-to-https' or 'https-only'.",
                            metadata={"origins_count": len(origins)},
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        msg = f"CloudFront check skipped (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True
    return CheckResult(
        service="cloudfront",
        name="https_enforcement",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )
