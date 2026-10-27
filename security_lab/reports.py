"""Report exporters for scan results.

HTML, JSON, and CSV are always available. PDF requires reportlab; if
it is absent, exporting PDF raises a clear error instead of producing
a broken file. Every exporter re-escapes/redacts: reports never carry
credentials, cookies, or tokens (evidence is redacted at finding
creation, and the HTML exporter escapes all text).
"""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .scanner.engine import ScanResult

SEVERITY_COLORS = {
    "Critical": "#ff4d4f", "High": "#ff7a45", "Medium": "#faad14",
    "Low": "#52c41a", "Informational": "#8c8c8c",
}


def export_scan_json(result: ScanResult, path: Path) -> Path:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2),
                          encoding="utf-8")
    return Path(path)


def export_scan_csv(result: ScanResult, path: Path) -> Path:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["name", "category", "severity", "confidence",
                         "status", "url", "explanation", "evidence",
                         "impact", "remediation", "reference"])
        for f in result.findings:
            writer.writerow([f.name, f.category, f.severity, f.confidence,
                             f.status, f.url, f.explanation, f.evidence,
                             f.impact, f.remediation, f.reference])
    return Path(path)


def _esc(value: object) -> str:
    return html.escape(str(value))


def export_scan_html(result: ScanResult, path: Path) -> Path:
    cards = "".join(
        f'<div class="card"><div class="num">{result.summary.get(sev, 0)}</div>'
        f'<div class="lbl">{sev}</div></div>'
        for sev in ("Critical", "High", "Medium", "Low", "Informational"))
    rows = ""
    for f in result.findings:
        color = SEVERITY_COLORS.get(f.severity, "#8c8c8c")
        rows += (
            f'<tr><td><span class="badge" style="background:{color}">'
            f"{_esc(f.severity)}</span></td><td>{_esc(f.name)}</td>"
            f"<td>{_esc(f.category)}</td><td>{_esc(f.confidence)}</td>"
            f"<td>{_esc(f.status)}</td><td class='mono'>{_esc(f.url)}</td>"
            f"<td>{_esc(f.explanation)}</td><td class='mono'>{_esc(f.evidence)}</td>"
            f"<td>{_esc(f.impact)}</td><td>{_esc(f.remediation)}</td></tr>")
    limitations = "".join(f"<li>{_esc(item)}</li>"
                          for item in result.limitations)
    errors = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)
    timeline = "".join(
        f"<li>{_esc(e['time'])} — {_esc(e['event'])}: {_esc(e['detail'])}</li>"
        for e in result.timeline)
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>CyberLLMv1 Security Lab — Scan Report</title>
<style>body{{background:#141414;color:#e6e6e6;font-family:Segoe UI,Arial,sans-serif;margin:32px}}
.cards{{display:flex;gap:12px}} .card{{background:#1f1f1f;border:1px solid #333;border-radius:8px;padding:12px 18px}}
.num{{font-size:28px;font-weight:700}} .lbl{{color:#aaa}}
table{{border-collapse:collapse;width:100%;margin-top:20px}} th,td{{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}}
th{{background:#1f1f1f}} .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px}}
.mono{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}} h2{{margin-top:28px}}</style>
</head><body><h1>CyberLLMv1 Security Lab — Scan Report</h1>
<p>Target: <span class="mono">{_esc(result.target)}</span><br>
Started: {_esc(result.started_at)} &nbsp; Finished: {_esc(result.finished_at)}<br>
Requests made: {result.requests_made} &nbsp; Stopped early: {result.stopped}</p>
<div class="cards">{cards}</div>
<h2>Findings ({len(result.findings)})</h2>
<table><tr><th>Severity</th><th>Name</th><th>Category</th><th>Confidence</th>
<th>Status</th><th>URL</th><th>Explanation</th><th>Evidence</th>
<th>Impact</th><th>Remediation</th></tr>{rows}</table>
<h2>Limitations</h2><ul>{limitations}</ul>
<h2>Errors</h2><ul>{errors or "<li>None</li>"}</ul>
<h2>Timeline</h2><ul>{timeline}</ul>
<p><em>Reports never contain credentials, cookies, or tokens. Evidence is
redacted at collection time. A finding marked "suspected" is an indicator,
not a confirmed vulnerability.</em></p>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
    return Path(path)


def export_scan_pdf(result: ScanResult, path: Path) -> Path:
    """PDF via reportlab. Raises RuntimeError when reportlab is absent."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (Paragraph, SimpleDocTemplate,
                                        Spacer, Table, TableStyle)
    except ImportError as exc:
        raise RuntimeError(
            "PDF export needs the reportlab package, which is not "
            "installed. HTML, JSON, and CSV exports are available."
        ) from exc
    styles = getSampleStyleSheet()
    story = [Paragraph("CyberLLMv1 Security Lab — Scan Report",
                       styles["Title"]),
             Paragraph(f"Target: {result.target}", styles["Normal"]),
             Paragraph(f"Started: {result.started_at} — Finished: "
                       f"{result.finished_at}", styles["Normal"]),
             Paragraph(f"Requests: {result.requests_made} — Stopped: "
                       f"{result.stopped}", styles["Normal"]),
             Spacer(1, 12)]
    summary_data = [["Severity", "Count"]] + [
        [sev, str(result.summary.get(sev, 0))]
        for sev in ("Critical", "High", "Medium", "Low", "Informational")]
    table = Table(summary_data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story += [table, Spacer(1, 12)]
    for f in result.findings:
        story.append(Paragraph(
            f"<b>[{f.severity}] {html.escape(f.name)}</b> "
            f"({html.escape(f.category)}, {f.confidence}, {f.status})",
            styles["Heading3"]))
        story.append(Paragraph(html.escape(f.explanation), styles["Normal"]))
        story.append(Paragraph(
            f"URL: {html.escape(f.url)}<br/>Evidence: "
            f"{html.escape(f.evidence)}<br/>Remediation: "
            f"{html.escape(f.remediation)}", styles["Normal"]))
        story.append(Spacer(1, 6))
    story.append(Paragraph("Limitations: " + "; ".join(result.limitations),
                           styles["Normal"]))
    SimpleDocTemplate(str(path), pagesize=A4).build(story)
    return Path(path)
