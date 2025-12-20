# AWS Account Hygiene & Security Report

Python CLI that scans an AWS account for common hygiene and security issues and produces JSON, Markdown, and HTML reports with severity scoring and remediation hints. Designed to run locally or in CI with clear exit codes. The goal is fast visibility into high-impact misconfigurations without requiring full compliance tooling.

## What it does
- **IAM**: users without MFA; stale/unused access keys; broad/admin-style permissions (heuristic)
- **S3**: account-level Public Access Block; bucket-level public exposure signals
- **EC2**: security groups open to the world on admin ports (22/3389)
- **CloudFront**: viewer protocol / HTTPS enforcement
- **Tagging**: missing required tags (for example Owner, Env)
- **Multi-region** support (`--regions <list>` or `--regions all`)

## Example output
Generated against a real AWS account (identifiers anonymized).

![AWS Audit HTML Report](docs/screenshots/aws-audit-html-report.png)

## Quickstart

### Requirements
- Python 3.10+
- AWS CLI configured (SSO or access keys)
- Read permissions for the services you want to scan

### Install
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -e ".[dev]"
```

### Run
```bash
python -m aws_audit --profile <PROFILE> --region eu-central-1 --format json --format md --format html
```

Outputs are written to `out/` as:
- `out/aws_audit_<account>.json`
- `out/aws_audit_<account>.md`
- `out/aws_audit_<account>.html`

### Authentication
Supports the standard AWS credential chain:
- AWS SSO profiles (recommended)
- Access keys
- Environment variables
- Instance/role credentials (for example EC2)

SSO example:
```bash
aws sso login --profile cann65-adminaccess
python -m aws_audit --profile cann65-adminaccess --region eu-central-1 --format html
```

### CLI flags worth knowing
- `--regions eu-central-1,eu-west-1` or `--regions all`
- `--fail-on MEDIUM` (default) sets the severity threshold for exit code 2
- `--max-findings 50` fails if total findings exceed N
- `--no-exit-on-findings` always exits 0
- `--access-key-max-age-days` / `--access-key-inactive-days` to tune IAM key checks

### Exit codes
- `0` success or findings below threshold
- `2` any finding at/above `--fail-on`, or total findings exceed `--max-findings`

## Development
- Lint/format: `ruff check . --fix && ruff format . && black .`
- Tests: `pytest -q`

## Permissions (read-only)
Recommended minimums: IAM list/get, S3 list/get (account PAB, bucket policy/PAB), EC2 describe security groups, CloudFront list distributions, Tagging API get resources, STS get caller identity. Missing permissions are reported as skipped checks with warnings.

## Non-goals
- This is not a full compliance or policy-as-code framework.
- It does not make changes to AWS resources (read-only by design).
- It focuses on common, high-signal misconfigurations.

## Repo hygiene for public sharing
- Do not commit real reports in `out/` (they contain account details).
- Keep secrets/credentials out of the repo (`.env`, `~/.aws/*`).
- Use anonymized screenshots for examples.

## Status / roadmap
- Current: IAM/S3/EC2/CloudFront/Tagging checks, multi-region, severity-based exit codes, JSON/MD/HTML output.
- Next ideas: masking mode (`--mask`) to anonymize IDs; richer IAM policy analysis; root MFA check.

## Why this project
Built as a practical security-focused Python project to demonstrate:
- AWS API usage with boto3
- CLI design and configuration handling
- Structured findings and reporting
- CI-friendly tooling with deterministic exit codes

## License
MIT
