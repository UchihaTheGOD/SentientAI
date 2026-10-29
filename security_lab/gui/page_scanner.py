"""Tool 2 — Authorized Website Security Scanner.

Detection only. A scan starts only when the target is allowlisted
(or a loopback lab target with local-lab mode on) AND the operator
checks the authorization confirmation. The engine enforces the same
rules independently of this page.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGroupBox,
                               QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QProgressBar, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from ..lab_server import start_lab_server, stop_lab_server
from ..reports import (export_scan_csv, export_scan_html, export_scan_json,
                       export_scan_pdf)
from ..scanner.checks import ALL_CHECKS
from ..scanner.engine import ScanConfig, Scanner
from .context import AppContext
from .theme import severity_color
from .workers import ScanWorker


class ScannerPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker: ScanWorker | None = None
        self._result = None
        self._lab_server = None
        self._lab_thread = None
        self._lab_url = ""
        layout = QVBoxLayout(self)

        heading = QLabel("Authorized Website Security Scanner")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Detection only: GET requests plus one read-only TRACE echo "
            "probe, inert markers, no logins, no extraction, no "
            "destructive tests. A finding marked "
            "'suspected' is an indicator, not a confirmed vulnerability."))

        # -- target ---------------------------------------------------------
        target_box = QGroupBox("Target and authorization")
        target_layout = QVBoxLayout(target_box)
        row = QHBoxLayout()
        self.ed_target = QLineEdit()
        self.ed_target.setPlaceholderText("https://example.com/  (or a local lab URL)")
        row.addWidget(QLabel("Target URL:"))
        row.addWidget(self.ed_target, 1)
        target_layout.addLayout(row)
        row2 = QHBoxLayout()
        self.ed_allow = QLineEdit(", ".join(ctx.settings.allowlist))
        self.ed_allow.setPlaceholderText("Allowlisted hosts, comma separated")
        row2.addWidget(QLabel("Allowlist:"))
        row2.addWidget(self.ed_allow, 1)
        target_layout.addLayout(row2)
        self.ck_lab = QCheckBox(
            "Local-lab mode (loopback targets only, e.g. the lab below)")
        self.ck_lab.setChecked(ctx.settings.local_lab_enabled)
        target_layout.addWidget(self.ck_lab)
        self.ck_auth = QCheckBox(
            "I confirm I am authorized to test this target")
        target_layout.addWidget(self.ck_auth)
        row3 = QHBoxLayout()
        self.btn_lab = QPushButton("Start local lab")
        self.btn_lab_stop = QPushButton("Stop local lab")
        self.btn_lab_stop.setEnabled(False)
        row3.addWidget(self.btn_lab)
        row3.addWidget(self.btn_lab_stop)
        row3.addStretch()
        target_layout.addLayout(row3)
        self.lbl_lab = QLabel("")
        self.lbl_lab.setObjectName("muted")
        target_layout.addWidget(self.lbl_lab)
        layout.addWidget(target_box)
        self.btn_lab.clicked.connect(self.start_lab)
        self.btn_lab_stop.clicked.connect(self.stop_lab)

        # -- categories ------------------------------------------------------
        cat_box = QGroupBox("Check categories (all selected by default)")
        cat_layout = QVBoxLayout(cat_box)
        self.cat_checks: dict[str, QCheckBox] = {}
        for check in ALL_CHECKS:
            box = QCheckBox(f"{check['name']} ({check['id']})")
            box.setChecked(True)
            self.cat_checks[check["id"]] = box
            cat_layout.addWidget(box)
        layout.addWidget(cat_box)

        # -- run controls -----------------------------------------------------
        run_row = QHBoxLayout()
        self.btn_scan = QPushButton("Start scan")
        self.btn_stop = QPushButton("Stop scan")
        self.btn_stop.setEnabled(False)
        self.progress = QProgressBar()
        run_row.addWidget(self.btn_scan)
        run_row.addWidget(self.btn_stop)
        run_row.addWidget(self.progress, 1)
        layout.addLayout(run_row)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)

        # -- summary cards -----------------------------------------------------
        cards = QHBoxLayout()
        self.card_labels: dict[str, QLabel] = {}
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            lbl = QLabel(f"{sev}: 0")
            cards.addWidget(lbl)
            self.card_labels[sev] = lbl
        cards.addStretch()
        layout.addLayout(cards)

        # -- filters + table ----------------------------------------------------
        filt = QHBoxLayout()
        self.cb_sev = QComboBox()
        self.cb_sev.addItems(["All severities", "Critical", "High", "Medium",
                              "Low", "Informational"])
        self.cb_cat = QComboBox()
        self.cb_cat.addItems(["All categories"] +
                             [c["name"] for c in ALL_CHECKS])
        self.cb_status = QComboBox()
        self.cb_status.addItems(["All statuses", "suspected", "verified",
                                 "inconclusive"])
        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Search findings…")
        filt.addWidget(self.cb_sev)
        filt.addWidget(self.cb_cat)
        filt.addWidget(self.cb_status)
        filt.addWidget(self.ed_search, 1)
        layout.addLayout(filt)
        self.cb_sev.currentTextChanged.connect(self._render_table)
        self.cb_cat.currentTextChanged.connect(self._render_table)
        self.cb_status.currentTextChanged.connect(self._render_table)
        self.ed_search.textChanged.connect(self._render_table)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Name", "Category", "Confidence", "Status", "URL"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(
            self.table.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        layout.addWidget(self.table, 1)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(220)
        layout.addWidget(self.detail)

        exp_row = QHBoxLayout()
        self.btn_exp_html = QPushButton("Export HTML")
        self.btn_exp_json = QPushButton("Export JSON")
        self.btn_exp_csv = QPushButton("Export CSV")
        self.btn_exp_pdf = QPushButton("Export PDF")
        self.btn_case = QPushButton("Create case from selected finding")
        for btn in (self.btn_exp_html, self.btn_exp_json, self.btn_exp_csv,
                    self.btn_exp_pdf, self.btn_case):
            exp_row.addWidget(btn)
        exp_row.addStretch()
        layout.addLayout(exp_row)
        self.btn_exp_html.clicked.connect(lambda: self._export("html"))
        self.btn_exp_json.clicked.connect(lambda: self._export("json"))
        self.btn_exp_csv.clicked.connect(lambda: self._export("csv"))
        self.btn_exp_pdf.clicked.connect(lambda: self._export("pdf"))
        self.btn_case.clicked.connect(self._create_case)

    # -- lab ------------------------------------------------------------------
    def start_lab(self) -> None:
        if self._lab_server is not None:
            return
        try:
            server, thread, url = start_lab_server()
        except OSError as exc:
            self.lbl_lab.setText(f"Local lab failed to start: {exc}")
            return
        self._lab_server, self._lab_thread, self._lab_url = server, thread, url
        self.ed_target.setText(url)
        self.ck_lab.setChecked(True)
        allow = [h.strip() for h in self.ed_allow.text().split(",") if h.strip()]
        if "127.0.0.1" not in allow:
            allow.append("127.0.0.1")
            self.ed_allow.setText(", ".join(allow))
        self.lbl_lab.setText(f"Local lab running at {url} (training site)")
        self.btn_lab.setEnabled(False)
        self.btn_lab_stop.setEnabled(True)
        self.ctx.log_event("lab", f"local lab started at {url}", source="scanner")

    def stop_lab(self) -> None:
        if self._lab_server is not None:
            stop_lab_server(self._lab_server)
            self._lab_server = None
            self.lbl_lab.setText("Local lab stopped.")
        self.btn_lab.setEnabled(True)
        self.btn_lab_stop.setEnabled(False)

    # -- scan -------------------------------------------------------------------
    def start_scan(self) -> None:
        target = self.ed_target.text().strip()
        if not target:
            self.status_label.setText("Enter a target URL first.")
            return
        if not self.ck_auth.isChecked():
            self.status_label.setText(
                "Check the authorization confirmation before scanning.")
            return
        allowlist = [h.strip() for h in self.ed_allow.text().split(",")
                     if h.strip()]
        categories = {cid for cid, box in self.cat_checks.items()
                      if box.isChecked()}
        if not categories:
            self.status_label.setText("Select at least one category.")
            return
        config = ScanConfig(
            target=target, allowlist=allowlist,
            local_lab_enabled=self.ck_lab.isChecked(), authorized=True,
            categories=categories,
            rate_limit_seconds=self.ctx.settings.rate_limit_seconds,
            timeout_seconds=self.ctx.settings.request_timeout_seconds,
            max_requests=self.ctx.settings.max_requests_per_scan,
            max_workers=self.ctx.settings.max_workers,
            deadline_seconds=self.ctx.settings.scan_deadline_seconds)
        self.status_label.setText("Scanning…")
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)

        # Progress must cross from the worker thread to the GUI thread
        # via a Qt signal: calling setValue() directly from the scan
        # thread (the old code) is not thread-safe.
        holder: dict = {}

        def make_scanner():
            scanner = Scanner(config,
                              progress=lambda d, t, m: holder["worker"].progress.emit(d, t, m))
            return scanner

        worker = ScanWorker(make_scanner, self)
        holder["worker"] = worker
        worker.progress.connect(self._on_scan_progress)
        worker.finished.connect(lambda r, w=worker: self._scan_done(r, w))
        worker.error.connect(lambda m, w=worker: self._scan_error(m, w))
        self._worker = worker
        worker.start()

    def _on_scan_progress(self, done: int, total: int, _msg: str) -> None:
        self.progress.setValue(int(done / max(total, 1) * 100))

    def stop_scan(self) -> None:
        if self._worker is not None:
            self._worker.stop_scan()
            self.status_label.setText("Stopping scan…")

    def stop_all(self) -> None:
        """Stop any running scan (used when the window closes)."""
        if self._worker is not None:
            self._worker.stop_scan()

    def _scan_done(self, result, worker) -> None:
        # Ignore a late result from a worker that is no longer current
        # (e.g. an earlier scan stopped after a new one started).
        if worker is not self._worker:
            return
        self._worker = None
        self._result = result
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress.setValue(100)
        for sev, lbl in self.card_labels.items():
            lbl.setText(f"{sev}: {result.summary.get(sev, 0)}")
        self.status_label.setText(
            f"Scan finished: {len(result.findings)} finding(s), "
            f"{result.requests_made} request(s)"
            + (" (stopped early)" if result.stopped else "")
            + (f"; errors: {len(result.errors)}" if result.errors else ""))
        self.ctx.log_event("scan",
                           f"{result.target}: {len(result.findings)} findings",
                           source="scanner")
        self._render_table()

    def _scan_error(self, msg: str, worker) -> None:
        if worker is not self._worker:
            return
        self._worker = None
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_label.setText(f"Scan refused or failed: {msg}")

    def _filtered(self):
        if self._result is None:
            return []
        sev = self.cb_sev.currentText()
        cat = self.cb_cat.currentText()
        status = self.cb_status.currentText()
        query = self.ed_search.text().strip().lower()
        out = []
        for f in self._result.findings:
            if sev != "All severities" and f.severity != sev:
                continue
            if cat != "All categories" and f.category != cat:
                continue
            if status != "All statuses" and f.status != status:
                continue
            if query and query not in (f.name + f.url + f.category).lower():
                continue
            out.append(f)
        return out

    def _render_table(self) -> None:
        findings = self._filtered()
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev_item = QTableWidgetItem(f.severity)
            sev_item.setBackground(QColor(severity_color(f.severity)))
            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(f.name))
            self.table.setItem(row, 2, QTableWidgetItem(f.category))
            self.table.setItem(row, 3, QTableWidgetItem(f.confidence))
            self.table.setItem(row, 4, QTableWidgetItem(f.status))
            self.table.setItem(row, 5, QTableWidgetItem(f.url))

    def _selected_finding(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        findings = self._filtered()
        idx = rows[0].row()
        return findings[idx] if idx < len(findings) else None

    def _show_detail(self) -> None:
        f = self._selected_finding()
        if f is None:
            self.detail.setPlainText("")
            return
        self.detail.setPlainText(
            f"{f.name} [{f.severity} / {f.confidence} / {f.status}]\n"
            f"Category: {f.category}\nURL: {f.url}\n\n"
            f"Explanation: {f.explanation}\n\nEvidence: {f.evidence}\n\n"
            f"Impact: {f.impact}\n\nRemediation: {f.remediation}\n\n"
            f"Reference: {f.reference}")

    def _export(self, kind: str) -> None:
        if self._result is None:
            self.status_label.setText("Nothing to export yet — run a scan.")
            return
        default = str(self.ctx.dirs["reports"] / f"scan-report.{kind}")
        path, _ = QFileDialog.getSaveFileName(self, "Export report", default)
        if not path:
            return
        try:
            fn = {"html": export_scan_html, "json": export_scan_json,
                  "csv": export_scan_csv, "pdf": export_scan_pdf}[kind]
            fn(self._result, Path(path))
            self.status_label.setText(f"Report exported to {path}")
            self.ctx.log_event("report", f"scan report exported ({kind})",
                               source="scanner")
        except RuntimeError as exc:
            self.status_label.setText(str(exc))
        except OSError as exc:
            self.status_label.setText(f"Export failed: {exc}")

    def _create_case(self) -> None:
        f = self._selected_finding()
        if f is None:
            self.status_label.setText("Select a finding first.")
            return
        case = self.ctx.cases.create_from_finding(f)
        self.status_label.setText(f"Case #{case.id} created from finding.")
        self.ctx.log_event("case", f"case #{case.id} created: {f.name}",
                           source="scanner")
        if self.ctx.navigate:
            self.ctx.navigate("cases")
