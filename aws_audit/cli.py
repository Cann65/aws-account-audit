from __future__ import annotations

import argparse
from pathlib import Path

from aws_audit.aws import get_account_id, list_regions, session
from aws_audit.checks import (
    check_cloudfront_https,
    check_ec2_open_admin_ports,
    check_iam_access_keys,
    check_iam_admin_policies,
    check_iam_users_without_mfa,
    check_s3_public_access_block,
    check_s3_public_buckets,
    check_tagging_gaps,
)
from aws_audit.config import load_config
from aws_audit.models import Report, Severity
from aws_audit.reporting.emit import emit_json, emit_template
from aws_audit.utils import log, setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aws_audit", description="AWS hygiene & security audit")
    p.add_argument("--config", help="Path to config.yaml", default=None)
    p.add_argument("--profile", help="AWS profile name (overrides config)", default=None)
    p.add_argument("--region", help="AWS region (overrides config)", default=None)
    p.add_argument("--regions", help="Comma-separated regions or 'all'", default=None)
    p.add_argument(
        "--format",
        action="append",
        dest="formats",
        choices=["json", "md", "html"],
        help="Output format (repeatable)",
    )
    p.add_argument("--verbose", action="store_true")
    p.add_argument(
        "--fail-on", default=None, help="Fail on severity >= (INFO/LOW/MEDIUM/HIGH/CRITICAL)"
    )
    p.add_argument("--no-exit-on-findings", action="store_true", help="Always exit 0")
    p.add_argument("--max-findings", type=int, default=None, help="Fail if total findings exceed N")
    p.add_argument(
        "--access-key-max-age-days", type=int, default=None, help="Flag keys older than N days"
    )
    p.add_argument(
        "--access-key-inactive-days", type=int, default=None, help="Flag keys unused for N days"
    )
    return p


def main() -> int:
    args = build_parser().parse_args()
    setup_logging(args.verbose)

    cfg = load_config(args.config)
    if args.profile:
        cfg.profile = args.profile
    if args.region:
        cfg.region = args.region
    if args.regions:
        cfg.regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.formats:
        cfg.formats = args.formats
    if args.fail_on:
        cfg.fail_on_severity = Severity.from_str(args.fail_on)
    if args.no_exit_on_findings:
        cfg.exit_on_findings = False
    if args.max_findings is not None:
        cfg.max_findings = args.max_findings
    if args.access_key_max_age_days is not None:
        cfg.access_key_max_age_days = args.access_key_max_age_days
    if args.access_key_inactive_days is not None:
        cfg.access_key_inactive_days = args.access_key_inactive_days

    ses = session(cfg.profile)
    account_id = get_account_id(ses)
    regions = cfg.regions or [cfg.region]
    if len(regions) == 1 and regions[0].lower() == "all":
        discovered = list_regions(ses)
        regions = discovered or [cfg.region]

    check_results = []
    check_results.append(check_iam_users_without_mfa(ses))
    check_results.append(
        check_iam_access_keys(ses, cfg.access_key_max_age_days, cfg.access_key_inactive_days)
    )
    check_results.append(check_iam_admin_policies(ses))
    check_results.append(check_s3_public_access_block(ses))
    check_results.append(check_s3_public_buckets(ses))
    check_results.append(check_cloudfront_https(ses))

    for region in regions:
        check_results.append(check_ec2_open_admin_ports(ses, region=region))
        check_results.append(check_tagging_gaps(ses, region=region, required_keys=cfg.tag_keys))

    findings = []
    for c in check_results:
        findings.extend(c.findings)

    findings = sorted(findings, key=lambda f: f.severity, reverse=True)

    report = Report(account_id=account_id, regions=regions, findings=findings, checks=check_results)

    out_dir: Path = cfg.output_dir
    base = out_dir / f"aws_audit_{account_id}"
    summary = report.summary()
    log().info(
        "Findings: %s | Worst: %s | Regions: %s",
        summary["total"],
        summary["worst"],
        ",".join(regions),
    )

    if "json" in cfg.formats:
        emit_json(report, base.with_suffix(".json"))
        log().info("Wrote %s", base.with_suffix(".json"))
    if "md" in cfg.formats:
        emit_template(report, "report.md.j2", base.with_suffix(".md"))
        log().info("Wrote %s", base.with_suffix(".md"))
    if "html" in cfg.formats:
        emit_template(report, "report.html.j2", base.with_suffix(".html"))
        log().info("Wrote %s", base.with_suffix(".html"))

    if not cfg.exit_on_findings:
        return 0

    if cfg.max_findings is not None and len(findings) > cfg.max_findings:
        return 2

    worst = max((f.severity for f in findings), default=Severity.INFO)
    if findings and worst >= cfg.fail_on_severity:
        return 2
    return 0
