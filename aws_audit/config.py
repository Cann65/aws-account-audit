from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

from aws_audit.models import Severity


@dataclass
class Config:
    profile: str | None = None
    region: str = "eu-central-1"
    regions: list[str] = field(default_factory=list)
    formats: list[str] = field(default_factory=lambda: ["json"])
    output_dir: Path = Path("out")
    tag_keys: list[str] = field(default_factory=lambda: ["Owner", "Env"])
    fail_on_severity: Severity = Severity.MEDIUM
    exit_on_findings: bool = True
    max_findings: int | None = None
    access_key_max_age_days: int = 90
    access_key_inactive_days: int = 90


def load_config(config_path: str | None) -> Config:
    load_dotenv()
    cfg = Config()

    if config_path:
        p = Path(config_path)
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

        cfg.profile = data.get("profile", cfg.profile)
        cfg.region = data.get("region", cfg.region)
        cfg.regions = data.get("regions", cfg.regions)
        cfg.formats = data.get("formats", cfg.formats)
        cfg.output_dir = Path(data.get("output_dir", str(cfg.output_dir)))
        cfg.tag_keys = data.get("tag_keys", cfg.tag_keys)
        cfg.max_findings = data.get("max_findings", cfg.max_findings)
        cfg.access_key_max_age_days = int(
            data.get("access_key_max_age_days", cfg.access_key_max_age_days)
        )
        cfg.access_key_inactive_days = int(
            data.get("access_key_inactive_days", cfg.access_key_inactive_days)
        )

        if "fail_on_severity" in data:
            cfg.fail_on_severity = Severity.from_str(str(data["fail_on_severity"]))

        if "exit_on_findings" in data:
            cfg.exit_on_findings = bool(data["exit_on_findings"])

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    cfg.formats = [f.lower().strip() for f in cfg.formats]
    if cfg.regions:
        cfg.regions = [str(r).strip() for r in cfg.regions if str(r).strip()]
    if cfg.max_findings is not None:
        cfg.max_findings = int(cfg.max_findings)
    return cfg
    return cfg
