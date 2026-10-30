"""ATTACT report blob must be redacted like the finding rows."""

import json
from unittest.mock import patch

from ATTACT.models import Finding, Report


def test_report_json_redacts_finding_evidence(admin):
    from app.database import SessionLocal
    from app.services.attact_runner import run_and_persist

    secret = "api_key=SECRET1234567890abcdef"
    finding = Finding(check="info_disclosure", title="Error page",
                      status="potential", severity="Low", confidence="medium",
                      summary="s", evidence=f"error body contained {secret}",
                      remediation="fix")
    report = Report(target="http://127.0.0.1:9/",
                    timestamp="2026-01-01T00:00:00",
                    checks=["info_disclosure"], findings=[finding],
                    request_count=1)
    s = SessionLocal()
    try:
        with patch("app.services.attact_runner._run", return_value=report):
            assessment, _ = run_and_persist(
                db=s, target_url="http://127.0.0.1:9/",
                allowlist=["127.0.0.1"], confirm_authorized=True)
        assert secret not in assessment.report_json
        blob = json.loads(assessment.report_json)
        assert "[REDACTED]" in blob["findings"][0]["evidence"]
    finally:
        s.close()
