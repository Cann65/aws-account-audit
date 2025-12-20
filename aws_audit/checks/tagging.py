from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.aws import client
from aws_audit.models import CheckResult, Finding, Severity
from aws_audit.utils import log


def check_tagging_gaps(ses, region: str, required_keys: list[str]) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        tagapi = client(ses, "resourcegroupstaggingapi", region=region)
        paginator = tagapi.get_paginator("get_resources")

        for page in paginator.paginate(ResourcesPerPage=50):
            for r in page.get("ResourceTagMappingList", []):
                arn = r.get("ResourceARN", "unknown")
                tags = {t["Key"]: t.get("Value", "") for t in r.get("Tags", [])}
                missing = [
                    k for k in required_keys if k not in tags or not str(tags.get(k, "")).strip()
                ]
                if missing:
                    findings.append(
                        Finding(
                            service="tagging",
                            resource_id=arn,
                            title="Missing required tags",
                            severity=Severity.LOW,
                            detail=f"Missing/empty tags: {', '.join(missing)}",
                            recommendation=f"Add tags {', '.join(required_keys)} to resources where applicable.",
                            metadata={
                                "region": region,
                                "present_tags": sorted(list(tags.keys()))[:20],
                            },
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        msg = f"Tagging check skipped in {region} (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True
    return CheckResult(
        service="tagging",
        name=f"tagging_gaps:{region}",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )
