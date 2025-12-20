from aws_audit.models import CheckResult, Finding, Report, Severity
from aws_audit.reporting.emit import emit_json, emit_template


def test_emit_outputs(tmp_path):
    report = Report(
        account_id="123",
        regions=["eu-central-1"],
        findings=[Finding("iam", "bob", "No MFA", Severity.MEDIUM, "d", "rec")],
        checks=[CheckResult(service="iam", name="demo", findings=[], warnings=[])],
    )
    out_json = tmp_path / "r.json"
    emit_json(report, out_json)
    assert out_json.exists()

    md = tmp_path / "r.md"
    emit_template(report, "report.md.j2", md)
    assert md.read_text(encoding="utf-8").startswith("# AWS Account")

    html = tmp_path / "r.html"
    emit_template(report, "report.html.j2", html)
    assert "<html" in html.read_text(encoding="utf-8")
