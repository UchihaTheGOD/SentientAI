"""Redaction: reports never carry credentials, cookies, or tokens."""

from ..reports import (export_scan_csv, export_scan_html, export_scan_json,
                       export_scan_pdf)
from ..scanner.engine import ScanResult
from ..scanner.findings import Finding, redact, redact_url

SECRET = "sk-live-abcdef123456"
COOKIE = "session=abc123secret"


def _result():
    finding = Finding(
        "Test finding", "Test", "High", "high", "suspected",
        "explanation", f"Authorization: Bearer {SECRET}; cookie {COOKIE}",
        "https://user:pass123@example.com/x?api_key=abcdef",
        "impact", "fix")
    return ScanResult(
        target="https://example.com/", started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:00:01", findings=[finding],
        summary={"High": 1, "total": 1}, requests_made=1, stopped=False,
        errors=[], timeline=[], limitations=[])


def test_redact_masks_secrets():
    text = redact(f"key={SECRET} and {COOKIE} and ghp_1234567890abcdefghij")
    assert SECRET not in text
    assert COOKIE not in text
    assert "ghp_1234567890abcdefghij" not in text
    assert "[REDACTED]" in text


def test_redact_url_strips_userinfo_and_keys():
    clean = redact_url("https://user:pass123@example.com/x?api_key=abcdef&ok=1")
    assert "pass123" not in clean
    assert "abcdef" not in clean
    assert "example.com" in clean
    assert "ok=1" in clean


def test_exports_contain_no_secrets(tmp_path):
    result = _result()
    for exporter, name in ((export_scan_html, "r.html"),
                           (export_scan_json, "r.json"),
                           (export_scan_csv, "r.csv"),
                           (export_scan_pdf, "r.pdf")):
        path = tmp_path / name
        exporter(result, path)
        blob = path.read_bytes()
        assert SECRET.encode() not in blob, name
        assert b"abc123secret" not in blob, name
        assert b"pass123" not in blob, name


def test_pdf_export_without_reportlab_reports_clearly(tmp_path, monkeypatch):
    import sys

    import security_lab.reports as reports

    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("no reportlab")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    try:
        import pytest

        with pytest.raises(RuntimeError, match="reportlab"):
            reports.export_scan_pdf(_result(), tmp_path / "x.pdf")
    finally:
        monkeypatch.undo()
