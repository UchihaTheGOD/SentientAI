"""Report rendering — terminal summary + JSON export."""
from __future__ import annotations
import json, pathlib
from .models import Report

def render_terminal(report: Report) -> str:
    lines=[]
    lines.append(f"ATTACT {report.version}  target={report.target}  run={report.run_id}")
    lines.append(f"time={report.timestamp}  checks={','.join(report.checks)}  requests={report.request_count}  elapsed={report.elapsed_ms}ms")
    lines.append(f"allowlist={report.allowlist if report.allowlist else '(loopback only)'}")
    lines.append("")
    # group by status
    for f in report.findings:
        tag={"confirmed":"[CONFIRMED]","potential":"[POTENTIAL]","not_found":"[OK]","not_run":"[NOT RUN]"}.get(f.status, f"[{f.status}]")
        lines.append(f"{tag} {f.check:16} {f.severity:8} conf={f.confidence:6}  {f.title}")
        lines.append(f"      {f.summary}")
        if f.evidence: lines.append(f"      evidence: {f.evidence[:500]}")
        if f.remediation: lines.append(f"      fix: {f.remediation}")
        lines.append("")
    lines.append("Limitations:")
    for lim in report.limitations: lines.append(f" - {lim}")
    return "\n".join(lines)

def write_json(report: Report, path: str|pathlib.Path) -> pathlib.Path:
    p=pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return p
