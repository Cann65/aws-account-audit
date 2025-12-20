# 🛡️ AWS Account Hygiene & Security Report

> **Leichtgewichtiger Security-Scanner für AWS – ein Befehl, sofort Ergebnisse.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonwebservices&logoColor=white)](https://aws.amazon.com/)

Python-CLI, die ein AWS-Konto auf gängige Hygiene- und Sicherheitsprobleme scannt und JSON-, Markdown- und HTML-Reports mit Severity-Scoring und Remediation-Hinweisen erstellt. Läuft lokal oder in CI mit klaren Exit-Codes. Ziel: schnelle Sichtbarkeit auf High-Impact-Fehlkonfigurationen ohne Full-Compliance-Tooling.

---

## 📑 Inhaltsverzeichnis

- [Features](#-features)
- [Example Output](#-example-output)
- [Quickstart](#-quickstart)
- [CLI Reference](#-cli-reference)
- [Exit Codes](#-exit-codes)
- [CI/CD Integration](#-cicd-integration)
- [Output Examples](#-output-examples)
- [Required Permissions](#-required-permissions)
- [Development](#-development)
- [Contributing](#-contributing)
- [Non-Goals](#-non-goals)
- [Roadmap](#-roadmap)
- [License](#-license)

---

## 🔍 Features

| Bereich          | Checks                                                                       |
| ---------------- | ---------------------------------------------------------------------------- |
| **IAM**          | User ohne MFA, veraltete/ungenutzte Access Keys, breite Admin-Berechtigungen |
| **S3**           | Account-Level Public Access Block, Bucket-Level Public Exposure              |
| **EC2**          | Security Groups offen auf Admin-Ports (22/3389)                              |
| **CloudFront**   | Viewer Protocol / HTTPS Enforcement                                          |
| **Tagging**      | Fehlende Required Tags (z.B. `Owner`, `Env`)                                 |
| **Multi-Region** | `--regions <list>` oder `--regions all`                                      |

---

## 🖼️ Example Output

![AWS Audit HTML Report](docs/screenshots/aws-audit-html-report.png)

_Generiert gegen ein echtes AWS-Konto (Identifier anonymisiert)._

---

## 🚀 Quickstart

### Voraussetzungen

- Python 3.10+
- AWS CLI konfiguriert (SSO oder Access Keys)
- Read-Permissions für die zu scannenden Services

### Installation

```bash
# Virtual Environment erstellen
python -m venv .venv

# Aktivieren
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate         # Windows

# Installieren
pip install -e ".[dev]"
```

### Ausführen

```bash
python -m aws_audit \
  --profile <PROFILE> \
  --region eu-central-1 \
  --format json \
  --format md \
  --format html
```

Outputs werden nach `out/` geschrieben:

- `out/aws_audit_<account>.json`
- `out/aws_audit_<account>.md`
- `out/aws_audit_<account>.html`

### Authentifizierung

Das Tool unterstützt die Standard-AWS-Credential-Chain:

| Methode                   | Beispiel                                     |
| ------------------------- | -------------------------------------------- |
| AWS SSO (empfohlen)       | `aws sso login --profile my-profile`         |
| Access Keys               | `~/.aws/credentials`                         |
| Environment Variables     | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| Instance/Role Credentials | EC2, ECS, Lambda                             |

---

## ⚙️ CLI Reference

| Flag                         | Default  | Beschreibung                                                 |
| ---------------------------- | -------- | ------------------------------------------------------------ |
| `--profile`                  | -        | AWS CLI Profil                                               |
| `--region`                   | -        | Primäre Region                                               |
| `--regions`                  | -        | Mehrere Regionen: `eu-central-1,eu-west-1` oder `all`        |
| `--format`                   | `json`   | Output-Format(e): `json`, `md`, `html` (mehrfach verwendbar) |
| `--fail-on`                  | `MEDIUM` | Severity-Schwelle für Exit Code 2                            |
| `--max-findings`             | -        | Max. Findings bevor Exit Code 2                              |
| `--no-exit-on-findings`      | `false`  | Immer Exit 0                                                 |
| `--access-key-max-age-days`  | `90`     | Max. Alter für Access Keys                                   |
| `--access-key-inactive-days` | `30`     | Inaktivitäts-Schwelle für Keys                               |

---

## ✅ Exit Codes

| Code | Bedeutung                                                    |
| ---- | ------------------------------------------------------------ |
| `0`  | Erfolg oder Findings unterhalb der Schwelle                  |
| `2`  | Finding(s) ≥ `--fail-on` oder `--max-findings` überschritten |

---

## 🔄 CI/CD Integration

### GitHub Actions Beispiel

```yaml
name: AWS Security Audit

on:
  schedule:
    - cron: "0 6 * * 1" # Jeden Montag um 6:00 UTC
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -e .

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/AuditRole
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
          name: audit-report
          path: out/
```

---

## 📊 Output Examples

### JSON Finding

```json
{
  "id": "iam-001",
  "title": "IAM User without MFA",
  "severity": "HIGH",
  "resource": "arn:aws:iam::<ACCOUNT_ID>:user/<USERNAME>",
  "region": "global",
  "description": "User has console access but no MFA device configured.",
  "remediation": "Enable MFA for this user via IAM Console or CLI.",
  "documentation": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
}
```

### Summary

```json
{
  "account_id": "<ACCOUNT_ID>",
  "scan_time": "<TIMESTAMP>",
  "regions_scanned": ["<REGION_1>", "<REGION_2>"],
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

Empfohlene Minimal-Berechtigungen (read-only):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "ec2:DescribeSecurityGroups",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "tag:GetResources",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Hinweis:** Fehlende Berechtigungen werden als übersprungene Checks mit Warnings gemeldet.

---

## 🧪 Development

```bash
# Lint & Format
ruff check . --fix
ruff format .

# Tests
pytest -q

# Type Checking (optional)
mypy aws_audit/
```

---

## 🤝 Contributing

Beiträge sind willkommen! So kannst du mitmachen:

1. **Fork** das Repository
2. **Branch** erstellen: `git checkout -b feature/mein-feature`
3. **Änderungen** committen: `git commit -m 'Add: Mein neues Feature'`
4. **Push** zum Branch: `git push origin feature/mein-feature`
5. **Pull Request** öffnen

### Guidelines

- Code muss `ruff` Checks bestehen
- Neue Features sollten Tests haben
- Dokumentation aktualisieren wenn nötig

---

## 🚫 Non-Goals

- ❌ Kein Full-Compliance oder Policy-as-Code Framework
- ❌ Keine Änderungen an AWS-Ressourcen (read-only by design)
- ❌ Fokus auf high-signal Fehlkonfigurationen, nicht auf Vollständigkeit

---

## 📌 Roadmap

- [x] IAM/S3/EC2/CloudFront/Tagging Checks
- [x] Multi-Region Support
- [x] Severity-basierte Exit Codes
- [x] JSON/MD/HTML Output
- [ ] `--mask` Mode zum Anonymisieren von IDs
- [ ] Erweiterte IAM Policy Analyse
- [ ] Root Account MFA Check
- [ ] AWS Organizations Support

---

## 📄 License

[MIT](LICENSE) © 2025

---

<p align="center">
  <sub>Built with ❤️ as a practical security-focused Python project demonstrating AWS API usage, CLI design, and CI-friendly tooling.</sub>
</p>
