from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.aws import client
from aws_audit.models import CheckResult, Finding, Severity
from aws_audit.utils import log


def check_iam_users_without_mfa(ses) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    try:
        iam = client(ses, "iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                user = u["UserName"]
                mfa = iam.list_mfa_devices(UserName=user).get("MFADevices", [])
                if not mfa:
                    findings.append(
                        Finding(
                            service="iam",
                            resource_id=user,
                            title="IAM user without MFA device",
                            severity=Severity.MEDIUM,
                            detail=f"User '{user}' has no MFA device assigned.",
                            recommendation="Assign an MFA device or remove unused IAM users.",
                        )
                    )
    except (ClientError, BotoCoreError) as e:
        msg = f"IAM check skipped (insufficient permissions or error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True
    return CheckResult(
        service="iam",
        name="users_without_mfa",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )


def _statements(doc: dict) -> list[dict]:
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    if isinstance(stmts, list):
        return [s for s in stmts if isinstance(s, dict)]
    return []


def _is_full_admin_statement(stmt: dict) -> bool:
    actions = stmt.get("Action") or stmt.get("NotAction")
    resources = stmt.get("Resource") or stmt.get("NotResource")

    def _has_wildcard(val: str | Iterable[str] | None) -> bool:
        if val is None:
            return False
        if isinstance(val, str):
            return val == "*"
        if isinstance(val, list):
            return "*" in val
        return False

    return _has_wildcard(actions) and _has_wildcard(resources)


def check_iam_admin_policies(ses) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False

    try:
        iam = client(ses, "iam")

        # Attached policies
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                user = u["UserName"]
                attached = iam.list_attached_user_policies(UserName=user).get(
                    "AttachedPolicies", []
                )
                for p in attached:
                    if p.get("PolicyName") == "AdministratorAccess":
                        findings.append(
                            Finding(
                                service="iam",
                                resource_id=user,
                                title="User has AdministratorAccess policy attached",
                                severity=Severity.HIGH,
                                detail=f"IAM user '{user}' is attached to AdministratorAccess.",
                                recommendation="Replace with least-privilege policy or remove user.",
                            )
                        )
                inline_names = iam.list_user_policies(UserName=user).get("PolicyNames", [])
                for pol_name in inline_names:
                    pol = iam.get_user_policy(UserName=user, PolicyName=pol_name)
                    doc = pol.get("PolicyDocument", {})
                    for stmt in _statements(doc):
                        if _is_full_admin_statement(stmt):
                            findings.append(
                                Finding(
                                    service="iam",
                                    resource_id=user,
                                    title="User inline policy allows *:*",
                                    severity=Severity.HIGH,
                                    detail=f"IAM user '{user}' inline policy '{pol_name}' allows * on *.",
                                    recommendation="Tighten inline policy to least privilege.",
                                )
                            )

        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for r in page.get("Roles", []):
                role = r["RoleName"]
                attached = iam.list_attached_role_policies(RoleName=role).get(
                    "AttachedPolicies", []
                )
                for p in attached:
                    if p.get("PolicyName") == "AdministratorAccess":
                        findings.append(
                            Finding(
                                service="iam",
                                resource_id=role,
                                title="Role has AdministratorAccess policy attached",
                                severity=Severity.HIGH,
                                detail=f"IAM role '{role}' is attached to AdministratorAccess.",
                                recommendation="Replace with least-privilege policy.",
                            )
                        )
                inline_names = iam.list_role_policies(RoleName=role).get("PolicyNames", [])
                for pol_name in inline_names:
                    pol = iam.get_role_policy(RoleName=role, PolicyName=pol_name)
                    doc = pol.get("PolicyDocument", {})
                    for stmt in _statements(doc):
                        if _is_full_admin_statement(stmt):
                            findings.append(
                                Finding(
                                    service="iam",
                                    resource_id=role,
                                    title="Role inline policy allows *:*",
                                    severity=Severity.HIGH,
                                    detail=f"IAM role '{role}' inline policy '{pol_name}' allows * on *.",
                                    recommendation="Tighten inline policy to least privilege.",
                                )
                            )

    except (ClientError, BotoCoreError) as e:
        msg = f"IAM admin policy check skipped (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True

    return CheckResult(
        service="iam",
        name="admin_policies",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )


def check_iam_access_keys(ses, max_age_days: int, inactive_days: int) -> CheckResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    skipped = False
    now = datetime.now(timezone.utc)
    max_age = timedelta(days=max_age_days)
    max_inactive = timedelta(days=inactive_days)

    try:
        iam = client(ses, "iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                user = u["UserName"]
                keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
                for key in keys:
                    kid = key["AccessKeyId"]
                    created = key.get("CreateDate")
                    age = (now - created) if created else timedelta.max

                    try:
                        last_used_resp = iam.get_access_key_last_used(AccessKeyId=kid)
                        last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    except (ClientError, BotoCoreError) as inner_e:
                        last_used = None
                        warn = f"Could not fetch last used for key {kid}: {inner_e}"
                        log().warning(warn)
                        warnings.append(warn)

                    last_used_age = (now - last_used) if last_used else timedelta.max

                    if age > max_age:
                        findings.append(
                            Finding(
                                service="iam",
                                resource_id=kid,
                                title="Access key older than policy",
                                severity=Severity.MEDIUM,
                                detail=f"Access key for user '{user}' is {age.days} days old.",
                                recommendation=f"Rotate access keys older than {max_age_days} days.",
                                metadata={"user": user, "created": created},
                            )
                        )
                    if last_used is None or last_used_age > max_inactive:
                        findings.append(
                            Finding(
                                service="iam",
                                resource_id=kid,
                                title="Access key unused or no last-used data",
                                severity=Severity.MEDIUM,
                                detail=f"Key for user '{user}' last used {last_used_age.days if last_used else 'never'} days ago.",
                                recommendation=f"Disable or rotate unused keys older than {inactive_days} days.",
                                metadata={"user": user, "last_used": last_used},
                            )
                        )
    except (ClientError, BotoCoreError) as e:
        msg = f"IAM access key check skipped (permissions/error): {e}"
        log().warning(msg)
        warnings.append(msg)
        skipped = True

    return CheckResult(
        service="iam",
        name="access_keys",
        findings=findings,
        warnings=warnings,
        skipped=skipped,
    )
