# 🛡️ AWS Account Hygiene & Security Report

> **Lightweight security scanner for AWS — one command, instant results.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A Python CLI that scans your AWS account for common hygiene and security issues, generating JSON, Markdown, and HTML reports with severity scoring and remediation guidance.

**TL;DR:**
```bash
pip install -e .
python -m aws_audit --profile my-profile --regions all --format html
# → Open out/aws_audit_<account>.html
```

⚡ **Fast** — Full scan in under 2 minutes  
🔒 **Read-only** — No modifications to your AWS resources, ever  
🚦 **CI-friendly** — Exit codes for automated quality gates  

---

## 🤔 Why This Tool?

There are excellent full-featured security scanners out there (Prowler, ScoutSuite, AWS Config Rules). So why another one?

| Tool | Strengths | Trade-offs |
|------|-----------|------------|
| **Prowler** | 300+ checks, CIS/PCI compliance | Complex setup, long scan times, noisy output |
| **ScoutSuite** | Multi-cloud, comprehensive | Heavy dependencies, steep learning curve |
| **AWS Config** | Native, continuous monitoring | Costs money, requires setup per account |
| **This tool** | Fast, focused, zero config | Limited scope (by design) |

**This tool is for you if:**
- ✅ You want a quick health check in under 2 minutes
- ✅ You need CI-friendly exit codes for automated gates
- ✅ You prefer actionable findings over compliance checklists
- ✅ You're onboarding a new AWS account and want a baseline

**This tool is NOT for you if:**
- ❌ You need full CIS/SOC2/PCI compliance reporting
- ❌ You want continuous monitoring (use AWS Config or GuardDuty)
- ❌ You need deep IAM policy analysis (use IAM Access Analyzer)

---

## 📑 Table of Contents

- [Why This Tool?](#-why-this-tool)
- [Features](#-features)
- [Example Output](#-example-output)
- [Quickstart](#-quickstart)
- [How It Works](#-how-it-works)
- [CLI Reference](#-cli-reference)
- [Severity Levels](#-severity-levels)
- [Exit Codes](#-exit-codes)
- [CI/CD Integration](#-cicd-integration)
- [Output Examples](#-output-examples)
- [Required Permissions](#-required-permissions)
- [Troubleshooting](#-troubleshooting)
- [Performance](#-performance)
- [Development](#-development)
- [Contributing](#-contributing)
- [Non-Goals](#-non-goals)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## 🔍 Features

### IAM Security
| Check | Severity | Why It Matters |
|-------|----------|----------------|
| Users without MFA | HIGH | Compromised passwords = full account access |
| Access keys older than 90 days | MEDIUM | Long-lived credentials increase breach window |
| Unused access keys (30+ days) | LOW | Forgotten keys are attack vectors |
| Overly permissive policies (`*:*`) | HIGH | Violates least-privilege principle |

### S3 Security
| Check | Severity | Why It Matters |
|-------|----------|----------------|
| Account public access block disabled | HIGH | Last line of defense against accidental exposure |
| Bucket-level public access | CRITICAL | Data breaches waiting to happen |

### EC2 / Network Security
| Check | Severity | Why It Matters |
|-------|----------|----------------|
| Security groups open on port 22 (SSH) | HIGH | Brute-force attacks, unauthorized access |
| Security groups open on port 3389 (RDP) | HIGH | Common ransomware entry point |

### CloudFront
| Check | Severity | Why It Matters |
|-------|----------|----------------|
| HTTP allowed (no HTTPS redirect) | MEDIUM | Man-in-the-middle attacks, data interception |

### Resource Hygiene
| Check | Severity | Why It Matters |
|-------|----------|----------------|
| Missing required tags (`Owner`, `Env`) | INFO | Cost allocation, incident response, accountability |

### Multi-Region Support
Scan a single region, multiple regions, or all regions:
```bash
--region eu-central-1                       # Single region
--regions eu-central-1,eu-west-1,us-east-1  # Multiple regions
--regions all                               # All enabled regions
```

---

## 🖼️ Example Output

![AWS Audit HTML Report](docs/screenshots/aws-audit-html-report.png)

*Generated against a real AWS account (identifiers anonymized).*

---

## 🚀 Quickstart

### Prerequisites

- Python 3.10+
- AWS CLI configured (SSO or access keys)
- Read permissions for the services being scanned ([see IAM policy](#-required-permissions))

### Installation

```bash
# Clone the repository
git clone https://github.com/Cann65/aws-account-audit.git
cd aws-account-audit

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install -e ".[dev]"
```

### First Scan

```bash
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
```

Reports are written to `out/`:
```
out/
├── aws_audit_123456789012.json
├── aws_audit_123456789012.md
└── aws_audit_123456789012.html
```

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         aws-audit CLI                           │
├─────────────────────────────────────────────────────────────────┤
│  1. Authenticate    → AWS credential chain (SSO/keys/role)      │
│  2. Discover        → List enabled regions (if --regions all)   │
│  3. Scan            → Run checks in parallel per service        │
│  4. Aggregate       → Collect findings, dedupe, assign severity │
│  5. Report          → Generate JSON/MD/HTML output              │
│  6. Exit            → Return code based on --fail-on threshold  │
└─────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- **Read-only**: No modifications to your AWS resources, ever
- **Parallel scanning**: Services are scanned concurrently for speed
- **Graceful degradation**: Missing permissions skip checks (with warnings), don't fail
- **Deterministic output**: Same input = same output (for diffing over time)

---

## ⚙️ CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | — | AWS CLI profile name |
| `--region` | — | Primary region for global resources |
| `--regions` | — | Regions to scan: `eu-central-1,us-east-1` or `all` |
| `--format` | `json` | Output format(s): `json`, `md`, `html` (repeatable) |
| `--fail-on` | `MEDIUM` | Minimum severity to trigger exit code 2 |
| `--max-findings` | — | Maximum findings before exit code 2 |
| `--no-exit-on-findings` | `false` | Always exit 0 regardless of findings |
| `--access-key-max-age-days` | `90` | Age threshold for access key rotation warnings |
| `--access-key-inactive-days` | `30` | Inactivity threshold for unused key warnings |
| `--required-tags` | `Owner,Env` | Comma-separated list of required tags |
| `--output-dir` | `out/` | Directory for report files |

---

## 🎯 Severity Levels

| Level | Meaning | Example | Action |
|-------|---------|---------|--------|
| **CRITICAL** | Immediate risk of data breach or compromise | Public S3 bucket with sensitive data | Fix within hours |
| **HIGH** | Significant security gap, likely exploitable | IAM user without MFA, open SSH to world | Fix within days |
| **MEDIUM** | Security weakness, not immediately exploitable | Old access keys, missing HTTPS | Fix within weeks |
| **LOW** | Minor issue, defense-in-depth concern | Unused credentials, suboptimal config | Fix when convenient |
| **INFO** | Informational, best practice recommendation | Missing tags, documentation gaps | Nice to have |

---

## ✅ Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, or all findings below `--fail-on` threshold |
| `2` | Findings at or above `--fail-on` severity |

**Examples:**
```bash
# Fail CI only on CRITICAL or HIGH findings
python -m aws_audit --fail-on HIGH

# Never fail CI (reporting only)
python -m aws_audit --no-exit-on-findings

# Fail if more than 10 findings of any severity
python -m aws_audit --max-findings 10
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
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
      id-token: write   # Required for OIDC
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
          cat out/aws_audit_*.md >> $GITHUB_STEP_SUMMARY
```

### GitLab CI

```yaml
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
```

---

## 📊 Output Examples

### JSON Finding

```json
{
  "id": "iam-001",
  "title": "IAM User without MFA",
  "severity": "HIGH",
  "resource": "arn:aws:iam::123456789012:user/deploy-bot",
  "region": "global",
  "description": "User has console access but no MFA device configured. This allows password-only authentication, which is vulnerable to credential theft.",
  "remediation": "Enable MFA for this user via the IAM Console or CLI: aws iam enable-mfa-device",
  "documentation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
  "tags": ["iam", "mfa", "authentication"]
}
```

### Summary

```json
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
```

---

## 🔐 Required Permissions

### Minimal IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AuditReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:ListAllMyBuckets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "resourcegroupstaggingapi:GetResources",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Using AWS Managed Policies

Alternatively, attach these managed policies:
- `arn:aws:iam::aws:policy/SecurityAudit` (broader, but convenient)
- `arn:aws:iam::aws:policy/ReadOnlyAccess` (very broad, not recommended)

> **Note:** Missing permissions result in skipped checks with warnings, not failures.

---

## 🔧 Troubleshooting

### Authentication Issues

**Problem:** `NoCredentialsError: Unable to locate credentials`
```bash
# Check current identity
aws sts get-caller-identity

# If using SSO, ensure you're logged in
aws sso login --profile my-profile

# Verify profile exists
cat ~/.aws/config | grep -A5 "\[profile my-profile\]"
```

**Problem:** `ExpiredTokenException: The security token included in the request is expired`
```bash
# Re-authenticate
aws sso login --profile my-profile
# Or refresh credentials
aws sts get-session-token
```

### Permission Issues

**Problem:** `AccessDenied` on specific checks
```bash
# Run with verbose output to see which checks are skipped
python -m aws_audit --profile my-profile --region eu-central-1 -v

# Check what permissions your role has
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:role/MyRole \
  --action-names s3:GetAccountPublicAccessBlock
```

### Region Issues

**Problem:** `Could not connect to the endpoint URL`
```bash
# Check if region is enabled
aws ec2 describe-regions --query "Regions[].RegionName" --output table

# Some regions require opt-in
aws account get-region-opt-status --region-name af-south-1
```

### Report Generation Issues

**Problem:** HTML report not rendering correctly
- Ensure you're opening the file in a modern browser
- Check that the `out/` directory has write permissions
- Try regenerating with `--format html` only

---

## ⚡ Performance

Scan duration and API calls vary based on account size, number of resources, and regions scanned.

**Rough estimates (small to medium accounts):**

| Scope | Duration |
|-------|----------|
| Single region, all checks | ~15–30 seconds |
| All regions (~20), all checks | ~2–5 minutes |
| IAM-only (global) | ~5–10 seconds |

**Tips for faster scans:**
- Use `--regions` to limit scope instead of `all`
- Run during off-peak hours to avoid throttling

**Rate Limits:**
- The tool uses exponential backoff to handle AWS throttling
- For very large accounts (1000+ users, 100+ buckets), expect longer scan times

---

## 🧪 Development

### Setup

```bash
git clone https://github.com/Cann65/aws-account-audit.git
cd aws-account-audit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Code Quality

```bash
# Lint and auto-fix
ruff check . --fix

# Format
ruff format .

# Type checking
mypy aws_audit/

# All checks (pre-commit)
pre-commit run --all-files
```

### Testing

```bash
# Unit tests (no AWS credentials needed)
pytest tests/unit -v

# Integration tests (requires AWS credentials)
pytest tests/integration -v --profile test-account

# Coverage report
pytest --cov=aws_audit --cov-report=html
open htmlcov/index.html
```

### Adding a New Check

1. Create a new checker in `aws_audit/checks/`
2. Implement the `Check` protocol (see existing checks for examples)
3. Register the check in `aws_audit/checks/__init__.py`
4. Add tests in `tests/unit/checks/`
5. Update documentation

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make changes** and add tests
4. **Run checks**: `ruff check . && pytest`
5. **Commit**: `git commit -m 'Add: Description of change'`
6. **Push**: `git push origin feature/my-feature`
7. **Open a Pull Request**

### Commit Message Format

```
<type>: <description>

Types:
- Add: New feature
- Fix: Bug fix
- Docs: Documentation changes
- Refactor: Code changes that don't add features or fix bugs
- Test: Adding or updating tests
- Chore: Maintenance tasks
```

### What We're Looking For

- New security checks (with clear rationale)
- Performance improvements
- Better error messages
- Documentation improvements
- Bug fixes with regression tests

---

## 🚫 Non-Goals

This tool intentionally does NOT:

- ❌ **Modify AWS resources** — Read-only by design, no auto-remediation
- ❌ **Replace compliance frameworks** — Use Prowler/Config for CIS, SOC2, PCI
- ❌ **Provide continuous monitoring** — Point-in-time scan, not a daemon
- ❌ **Cover all AWS services** — Focused on high-impact basics
- ❌ **Support multi-account** — One account at a time (use AWS Organizations tools for fleet)

---

## 📌 Roadmap

### Completed
- [x] Core checks: IAM, S3, EC2, CloudFront, Tagging
- [x] Multi-region support
- [x] Severity-based exit codes
- [x] JSON / Markdown / HTML output

### Planned
- [ ] `--mask` mode for anonymizing identifiers in reports
- [ ] Root account MFA check
- [ ] Extended IAM policy analysis (unused permissions)
- [ ] RDS public accessibility check
- [ ] EBS encryption check
- [ ] Lambda public URL check
- [ ] AWS Organizations multi-account support
- [ ] SARIF output for GitHub Security tab integration
- [ ] Slack/Teams webhook notifications

### Maybe Someday
- [ ] Web UI for browsing historical reports
- [ ] Terraform/CloudFormation remediation snippets
- [ ] Custom check plugins

---

## 📄 License

[MIT](LICENSE) © 2025

---

<p align="center">
  <sub>Built with ❤️ as a practical security-focused Python project demonstrating AWS API usage, CLI design, and CI-friendly tooling.</sub>
</p>
