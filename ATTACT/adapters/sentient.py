"""Optional adapter: render an ATTACT JSON report as a context dict for SentientAI templates.

This never launches scans — it only formats an already-produced report for display.
Import path: from ATTACT.adapters.sentient import findings_for_template
"""
from __future__ import annotations
import json, pathlib
from typing import Any

def load_report(path: str|pathlib.Path) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

def findings_for_template(report: dict[str, Any], *, max_findings: int = 50) -> dict[str, Any]:
    findings = report.get("findings", [])[:max_findings]
    # bucket by status for template
    by_status: dict[str, list[dict[str,Any]]] = {"confirmed":[], "potential":[], "not_found":[], "not_run":[]}
    for f in findings:
        by_status.setdefault(f.get("status","not_run"), []).append(f)
    return {"report_meta": {k: report.get(k) for k in ("target","timestamp","checks","request_count","run_id","version")},
            "by_status": by_status, "limitations": report.get("limitations",[])}
