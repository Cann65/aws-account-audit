from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aws_audit.models import Report


def _jinja_env() -> Environment:
    templates_dir = Path(__file__).parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def emit_json(report: Report, out_path: Path) -> None:
    summary = report.summary()

    def _json_default(o):
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)

    payload = {
        "account_id": report.account_id,
        "regions": report.regions,
        "summary": summary,
        "findings": [{**asdict(f), "severity": f.severity.name} for f in report.findings],
        "checks": [
            {
                "service": c.service,
                "name": c.name,
                "findings": len(c.findings),
                "severity_counts": c.severity_counts(),
                "warnings": c.warnings,
                "errors": c.errors,
                "skipped": c.skipped,
            }
            for c in report.checks
        ],
    }
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def emit_template(report: Report, template_name: str, out_path: Path) -> None:
    env = _jinja_env()
    tpl = env.get_template(template_name)
    summary = report.summary()
    content = tpl.render(
        account_id=report.account_id,
        regions=report.regions,
        summary=summary,
        findings=report.findings,
        checks=report.checks,
        service_counts=summary.get("by_service", {}),
    )
    out_path.write_text(content, encoding="utf-8")
