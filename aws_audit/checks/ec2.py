from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.aws import client
from aws_audit.models import CheckResult, Finding, Severity
from aws_audit.utils import log

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def check_ec2_open_admin_ports(ses, region: str) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        ec2 = client(ses, "ec2", region=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sgid = sg.get("GroupId", "unknown")
                for perm in sg.get("IpPermissions", []):
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    if from_p is None or to_p is None:
                        continue
                    for port, label in ADMIN_PORTS.items():
                        if from_p <= port <= to_p:
                            for ipr in perm.get("IpRanges", []):
                                if ipr.get("CidrIp") == "0.0.0.0/0":
                                    findings.append(
                                        Finding(
                                            service="ec2",
                                            resource_id=sgid,
                                            title=f"Security group allows {label} from 0.0.0.0/0",
                                            severity=Severity.HIGH,
                                            detail=f"{sgid} allows {label} (port {port}) from the internet.",
                                            recommendation="Restrict inbound rules to trusted IP ranges or use SSM/bastion.",
                                            metadata={
                                                "region": region,
                                                "group_name": sg.get("GroupName"),
                                            },
                                        )
                                    )
    except (ClientError, BotoCoreError) as e:
        msg = f"EC2 check skipped in {region} (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True
    return CheckResult(
        service="ec2",
        name=f"open_admin_ports:{region}",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )
