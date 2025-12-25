# 🛡️ AWS Account Hygiene & Security Report

> **Lightweight security scanner for AWS — one command, instant results.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A Python CLI that scans your AWS account for common hygiene and security issues, generating JSON, Markdown, and HTML reports with severity scoring and remediation guidance.

**TL;DR**
```bash
pip install -e .
python -m aws_audit --profile my-profile --regions all --format html
# → Open out/aws_audit_<account>.html
⚡ Fast — typically seconds to a few minutes (depending on account size)
🔒 Read-only — no modifications to your AWS resources, ever
🚦 CI-friendly — exit codes for automated quality gates

🤔 Why This Tool?
There are excellent full-featured security scanners out there (Prowler, ScoutSuite, AWS Config Rules). So why another one?

Tool	Strengths	Trade-offs
Prowler	300+ checks, CIS/PCI compliance	Complex setup, long scan times, noisy output
ScoutSuite	Multi-cloud, comprehensive	Heavy dependencies, steep learning curve
AWS Config	Native, continuous monitoring	Costs money, requires setup per account
This tool	Fast, focused, zero config	Limited scope (by design)

This tool is for you if:

✅ You want a quick health check

✅ You need CI-friendly exit codes for automated gates

✅ You prefer actionable findings over compliance checklists

✅ You're onboarding a new AWS account and want a baseline

This tool is NOT for you if:

❌ You need full CIS/SOC2/PCI compliance reporting

❌ You want continuous monitoring (use AWS Config or GuardDuty)

❌ You need deep IAM policy analysis (use IAM Access Analyzer)

📑 Table of Contents
Features

Example Output

Quickstart

How It Works

CLI Reference

Severity Levels

Exit Codes

CI/CD Integration

Output Examples

Required Permissions

Troubleshooting

Performance

Development

Contributing

Non-Goals

Roadmap

License

🔍 Features
IAM Security
Check	Severity	Why It Matters
Users without MFA	HIGH	Compromised passwords = full account access
Access keys older than 90 days	MEDIUM	Long-lived credentials increase breach window
Unused access keys (30+ days)	LOW	Forgotten keys are attack vectors
Overly permissive policies (*:*)	HIGH	Violates least-privilege principle

S3 Security
Check	Severity	Why It Matters
Account public access block disabled	HIGH	Last line of defense against accidental exposure
Bucket-level public access	CRITICAL	Data breaches waiting to happen

EC2 / Network Security
Check	Severity	Why It Matters
Security groups open on port 22 (SSH)	HIGH	Brute-force attacks, unauthorized access
Security groups open on port 3389 (RDP)	HIGH	Common ransomware entry point

CloudFront
Check	Severity	Why It Matters
HTTP allowed (no HTTPS redirect)	MEDIUM	Man-in-the-middle attacks, data interception

Resource Hygiene
Check	Severity	Why It Matters
Missing required tags (Owner, Env)	INFO	Cost allocation, incident response, accountability

Multi-Region Support
Scan a single region, multiple regions, or all regions:

bash
Code kopieren
--region eu-central-1                       # Single region
--regions eu-central-1,eu-west-1,us-east-1  # Multiple regions
--regions all                               # All enabled regions
🖼️ Example Output


Generated against a real AWS account (identifiers anonymized).

🚀 Quickstart
Prerequisites
Python 3.10+

AWS CLI configured (SSO or access keys)

Read permissions for the services being scanned (see IAM policy)

Installation
bash
Code kopieren
git clone https://github.com/Cann65/aws-account-audit.git
cd aws-account-audit

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
First Scan
bash
Code kopieren
# Using AWS SSO (recommended)
aws sso login --profile my-profile
python -m aws_audit --profile my-profile --region eu-central-1 --format html

# Using environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
python -m aws_audit --region us-east-1 --format html

# Full scan with all outputs
python -m aws_audit \
  --profile prod \
  --regions all \
  --format json \
  --format md \
  --format html
Reports are written to out/:

text
Code kopieren
out/
├── aws_audit_123456789012.json
├── aws_audit_123456789012.md
└── aws_audit_123456789012.html
⚙️ How It Works
text
Code kopieren
┌─────────────────────────────────────────────────────────────────┐
│                         aws-audit CLI                           │
├─────────────────────────────────────────────────────────────────┤
│  1. Authenticate    → AWS credential chain (SSO/keys/role)      │
│  2. Discover        → List enabled regions (if --regions all)   │
│  3. Scan            → Run checks per service (paginators used)  │
│  4. Aggregate       → Collect findings, dedupe, assign severity │
│  5. Report          → Generate JSON/MD/HTML output              │
│  6. Exit            → Return code based on --fail-on threshold  │
└─────────────────────────────────────────────────────────────────┘
Key design decisions

Read-only: no modifications to AWS resources

Graceful degradation: missing permissions skip checks (with warnings)

Deterministic output: same input = same output (useful for diffing)

⚙️ CLI Reference
Flag	Default	Description
--profile	—	AWS CLI profile name
--region	—	Primary region
--regions	—	Regions to scan: eu-central-1,us-east-1 or all
--format	json	Output format(s): json, md, html (repeatable)
--fail-on	MEDIUM	Minimum severity to trigger exit code 2
--max-findings	—	Maximum findings before exit code 2
--no-exit-on-findings	false	Always exit 0 regardless of findings
--access-key-max-age-days	90	Access key age threshold
--access-key-inactive-days	30	Inactivity threshold for unused keys
--required-tags	Owner,Env	Comma-separated list of required tags
--output-dir	out/	Directory for report files

🎯 Severity Levels
Level	Meaning	Example	Action
CRITICAL	Immediate risk of data breach or compromise	Public S3 bucket	Fix within hours
HIGH	Significant security gap, likely exploitable	IAM user without MFA	Fix within days
MEDIUM	Security weakness	Old access keys	Fix within weeks
LOW	Minor issue	Unused credentials	Fix when convenient
INFO	Best-practice signal	Missing tags	Operational improvement

✅ Exit Codes
Code	Meaning
0	Success, or all findings below --fail-on threshold
2	Findings at or above --fail-on severity

Examples:

bash
Code kopieren
python -m aws_audit --fail-on HIGH
python -m aws_audit --no-exit-on-findings
python -m aws_audit --max-findings 10
🔄 CI/CD Integration
GitHub Actions
yaml
Code kopieren
name: AWS Security Audit

on:
  schedule:
    - cron: "0 6 * * 1"  # Every Monday at 6:00 UTC
  pull_request:
    paths:
      - "aws_audit/**"
      - "tests/**"
      - "pyproject.toml"
      - ".github/workflows/**"
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: "pip"

      - name: Install
        run: pip install -e .

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/SecurityAuditRole
          aws-region: eu-central-1

      - name: Run audit
        run: |
          python -m aws_audit \
            --regions all \
            --format json \
            --format html \
            --fail-on HIGH

      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-audit-${{ github.run_id }}
          path: out/
          retention-days: 30

      - name: Post summary
        if: always()
        run: |
          echo "## 🛡️ Security Audit Results" >> $GITHUB_STEP_SUMMARY
          ls -1 out/aws_audit_*.md | head -n 1 | xargs -I{} cat {} >> $GITHUB_STEP_SUMMARY
GitLab CI
yaml
Code kopieren
security-audit:
  image: python:3.11-slim
  stage: test
  script:
    - pip install -e .
    - python -m aws_audit --regions all --format html --fail-on HIGH
  artifacts:
    paths:
      - out/
    expire_in: 30 days
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
📊 Output Examples
JSON Finding
json
Code kopieren
{
  "id": "iam-001",
  "title": "IAM User without MFA",
  "severity": "HIGH",
  "resource": "arn:aws:iam::123456789012:user/deploy-bot",
  "region": "global",
  "description": "User has console access but no MFA device configured. This allows password-only authentication, which is vulnerable to credential theft.",
  "remediation": "Enable MFA for this user via the IAM Console.",
  "documentation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
  "tags": ["iam", "mfa", "authentication"]
}
Summary
json
Code kopieren
{
  "account_id": "123456789012",
  "account_alias": "my-company-prod",
  "scan_time": "2025-01-15T10:30:00Z",
  "scan_duration_seconds": 45,
  "regions_scanned": ["eu-central-1", "eu-west-1", "us-east-1"],
  "checks_executed": 12,
  "checks_skipped": 2,
  "summary": {
    "CRITICAL": 0,
    "HIGH": 3,
    "MEDIUM": 7,
    "LOW": 12,
    "INFO": 5
  }
}
🔐 Required Permissions
Minimal IAM Policy (verified)
The following policy is derived from the tool's actual boto3 calls and paginator operations (no unused permissions such as s3:GetBucketAcl).

json
Code kopieren
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AwsAccountAuditReadOnlyMinimal",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",

        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",

        "resourcegroupstaggingapi:GetResources",

        "cloudfront:ListDistributions",

        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",

        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
Using AWS Managed Policies
Alternatively, attach these managed policies (broader, convenient but not recommended in production):

arn:aws:iam::aws:policy/SecurityAudit

arn:aws:iam::aws:policy/ReadOnlyAccess

Prefer a dedicated read-only role with the minimal policy above; avoid broad policies in production environments.

🔧 Troubleshooting
Authentication Issues
Problem: NoCredentialsError: Unable to locate credentials

bash
Code kopieren
aws sts get-caller-identity
aws sso login --profile my-profile
Problem: ExpiredTokenException: The security token included in the request is expired

bash
Code kopieren
aws sso login --profile my-profile
Permission Issues
Problem: AccessDenied on specific checks

bash
Code kopieren
python -m aws_audit --profile my-profile --region eu-central-1 -v
⚡ Performance
Scan duration varies based on account size, number of resources, and regions scanned.

Rough estimates (small to medium accounts):

Scope	Duration
Single region, all checks	~15–30 seconds
All regions (~20), all checks	~2–5 minutes
IAM-only (global)	~5–10 seconds

Tips:

Use --regions to limit scope instead of all

Run during off-peak hours to avoid throttling

🧪 Development
bash
Code kopieren
git clone https://github.com/Cann65/aws-account-audit.git
cd aws-account-audit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
Code quality:

bash
Code kopieren
ruff check . --fix
ruff format .
mypy aws_audit/
Tests:

bash
Code kopieren
pytest -q
🤝 Contributing
Contributions are welcome!

Fork the repository

Create a branch: git checkout -b feature/my-feature

Make changes and add tests

Run checks: ruff check . && pytest

Commit and push

Open a Pull Request

🚫 Non-Goals
This tool intentionally does NOT:

❌ Modify AWS resources — read-only by design, no auto-remediation

❌ Replace compliance frameworks — use Prowler/Config for CIS, SOC2, PCI

❌ Provide continuous monitoring — point-in-time scan, not a daemon

❌ Cover all AWS services — focused on high-impact basics

❌ Support multi-account — one account at a time

📌 Roadmap
Planned
 --mask mode for anonymizing identifiers in reports

 Root account MFA check

 Extended IAM policy analysis (unused permissions)

 RDS public accessibility check

 EBS encryption check

 Lambda public URL check

 AWS Organizations multi-account support

 SARIF output for GitHub Security tab integration

📄 License
MIT © 2025

<p align="center"> <sub>Built with ❤️ as a practical security-focused Python project demonstrating AWS API usage, CLI design, and CI-friendly tooling.</sub> </p> ```
