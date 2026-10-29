"""Secondary pages: Reports, Cases, Demo, Diagnostics, Settings."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from ..config import save_settings
from ..diagnostics import run_diagnostics
from ..lab_server import start_lab_server, stop_lab_server
from ..scanner.engine import ScanConfig, Scanner
from .context import AppContext
from .dialogs import ask_text, confirm
from .theme import STATUS_COLORS
from .workers import DiagnosticsWorker, InferenceWorker, ScanWorker

# ---------------------------------------------------------------- reports
class ReportsPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        layout = QVBoxLayout(self)
        heading = QLabel("Reports & History")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Exported scan reports and evaluations saved under the data "
            "directory. Open a file to review it; nothing here contains "
            "credentials or tokens."))
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget, 1)
        row = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_open = QPushButton("Open selected")
        row.addWidget(self.btn_refresh)
        row.addWidget(self.btn_open)
        row.addStretch()
        layout.addLayout(row)
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_open.clicked.connect(self._open_selected)

        timeline_box = QGroupBox("Event timeline")
        t_layout = QVBoxLayout(timeline_box)
        self.timeline_view = QTextEdit()
        self.timeline_view.setReadOnly(True)
        t_layout.addWidget(self.timeline_view)
        layout.addWidget(timeline_box)

    def showEvent(self, event):  # noqa: N802 - Qt naming
        super().showEvent(event)
        self.refresh()

    def refresh(self) -> None:
        reports_dir = self.ctx.dirs["reports"]
        files = sorted(reports_dir.glob("*")) if reports_dir.exists() else []
        self.list_widget.clear()
        for path in files:
            if path.is_file():
                self.list_widget.addItem(str(path))
        entries = self.ctx.timeline.read_all(limit=200)
        self.timeline_view.setPlainText("\n".join(
            f"{e['time']} [{e['source']}] {e['event']}: {e['detail']}"
            for e in entries) or "No events recorded yet.")

    def _open_selected(self) -> None:
        item = self.list_widget.currentItem()
        if item is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(item.text()))


# ------------------------------------------------------------------ cases
class CasesPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        layout = QVBoxLayout(self)
        heading = QLabel("Case Management")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Track findings as cases. Do not paste secrets into notes."))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Title", "Severity", "Status", "Updated"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(
            self.table.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        layout.addWidget(self.table, 1)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(180)
        layout.addWidget(self.detail)
        row = QHBoxLayout()
        self.btn_status = QPushButton("Change status…")
        self.btn_note = QPushButton("Add note…")
        self.btn_export_json = QPushButton("Export cases JSON")
        self.btn_export_csv = QPushButton("Export cases CSV")
        self.btn_refresh = QPushButton("Refresh")
        for btn in (self.btn_status, self.btn_note, self.btn_export_json,
                    self.btn_export_csv, self.btn_refresh):
            row.addWidget(btn)
        row.addStretch()
        layout.addLayout(row)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        self.btn_status.clicked.connect(self._change_status)
        self.btn_note.clicked.connect(self._add_note)
        self.btn_export_json.clicked.connect(lambda: self._export("json"))
        self.btn_export_csv.clicked.connect(lambda: self._export("csv"))
        self.btn_refresh.clicked.connect(self.refresh)

    def showEvent(self, event):  # noqa: N802 - Qt naming
        super().showEvent(event)
        self.refresh()

    def refresh(self) -> None:
        cases = self.ctx.cases.cases
        self.table.setRowCount(len(cases))
        for row, case in enumerate(cases):
            self.table.setItem(row, 0, QTableWidgetItem(str(case.id)))
            self.table.setItem(row, 1, QTableWidgetItem(case.title))
            self.table.setItem(row, 2, QTableWidgetItem(case.severity))
            self.table.setItem(row, 3, QTableWidgetItem(case.status))
            self.table.setItem(row, 4, QTableWidgetItem(case.updated_at))
        counts = self.ctx.cases.summary_counts()
        self.status_label.setText(
            f"{counts['total']} case(s): " +
            ", ".join(f"{k} {v}" for k, v in counts.items() if k != "total"))

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        idx = rows[0].row()
        cases = self.ctx.cases.cases
        return cases[idx] if idx < len(cases) else None

    def _show_detail(self) -> None:
        case = self._selected()
        if case is None:
            self.detail.setPlainText("")
            return
        notes = "\n".join(
            f"{n['time']} {n['author']}: {n['text']}" for n in case.notes)
        self.detail.setPlainText(
            f"#{case.id} {case.title}\nURL: {case.url}\n"
            f"Finding: {case.finding_name}\nStatus: {case.status}\n"
            f"Evidence: {case.evidence}\n\nNotes:\n{notes or '(none)'}")

    def _change_status(self) -> None:
        case = self._selected()
        if case is None:
            self.status_label.setText("Select a case first.")
            return
        from PySide6.QtWidgets import QInputDialog

        options = ["New", "Investigating", "Accepted Risk", "Resolved"]
        choice, ok = QInputDialog.getItem(
            self, "Change status", "New status:", options,
            options.index(case.status) if case.status in options else 0, False)
        if not ok:
            return
        self.ctx.cases.set_status(case.id, choice)
        self.ctx.log_event("case", f"case #{case.id} -> {choice}",
                           source="cases")
        self.refresh()

    def _add_note(self) -> None:
        case = self._selected()
        if case is None:
            self.status_label.setText("Select a case first.")
            return
        note = ask_text(self, "Add note", "Note (never paste secrets here):")
        if note is None:
            return
        self.ctx.cases.add_note(case.id, note)
        self.refresh()
        self._show_detail()

    def _export(self, kind: str) -> None:
        default = str(self.ctx.dirs["reports"] / f"cases.{kind}")
        path, _ = QFileDialog.getSaveFileName(self, "Export cases", default)
        if not path:
            return
        try:
            if kind == "json":
                self.ctx.cases.export_json(Path(path))
            else:
                self.ctx.cases.export_csv(Path(path))
            self.status_label.setText(f"Cases exported to {path}")
        except OSError as exc:
            self.status_label.setText(f"Export failed: {exc}")


# ------------------------------------------------------------------- demo
SIM_SCENARIOS = {
    "Web scan (simulated)": {
        "log": "SIMULATED 203.0.113.153 GET /wp-login.php, /.env, /.git/config",
        "kind": "log",
        "expected": "Deterministic rules flag credential-file probing; "
                    "the model is expected to agree (likely_threat).",
    },
    "SSRF attempt (simulated)": {
        "log": "SIMULATED GET /fetch?u=http://169.254.169.254/latest/meta-data/",
        "kind": "http_request",
        "expected": "Metadata-endpoint rule fires; model expected "
                    "likely_threat (or needs_review with the rule override).",
    },
    "Credential probe (simulated)": {
        "log": "SIMULATED 203.0.113.153 GET /.aws/credentials, /id_rsa",
        "kind": "log",
        "expected": "Credential-file rule fires; model expected likely_threat.",
    },
    "Benign health check (simulated)": {
        "log": "SIMULATED web01 healthcheck: GET /healthz 200 12ms",
        "kind": "log",
        "expected": "No rule fires; model expected likely_benign.",
    },
}


class DemoPage(QWidget):
    """Guided classroom demo + attack-versus-detection simulator.

    Everything here is labelled SIMULATED. Traffic goes to the local
    lab only, and model/rule results are shown as measured when the
    backend is available, or as expected-from-design otherwise.
    """

    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker = None
        self._lab = None
        layout = QVBoxLayout(self)
        heading = QLabel("Classroom Demo & Attack-vs-Detection Simulator")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "SIMULATED events only. Nothing here touches a real website. "
            "The demo target is the local lab on 127.0.0.1."))
        steps = QLabel(
            "Guided demo:\n"
            "1. Start the local lab (button below).\n"
            "2. Run a scripted scan against it from the Scanner page, or "
            "press 'Run scripted lab scan' here.\n"
            "3. Pick a simulated scenario and run it.\n"
            "4. Compare the deterministic rule result with the model "
            "verdict, then read the defender next steps.")
        steps.setWordWrap(True)
        layout.addWidget(steps)
        row = QHBoxLayout()
        self.btn_lab = QPushButton("Start local lab")
        self.btn_scan = QPushButton("Run scripted lab scan")
        row.addWidget(self.btn_lab)
        row.addWidget(self.btn_scan)
        row.addStretch()
        layout.addLayout(row)
        self.lbl_lab = QLabel("")
        self.lbl_lab.setObjectName("muted")
        layout.addWidget(self.lbl_lab)
        self.cb_scenario = QComboBox()
        self.cb_scenario.addItems(list(SIM_SCENARIOS))
        layout.addWidget(self.cb_scenario)
        self.btn_sim = QPushButton("Run simulation")
        layout.addWidget(self.btn_sim)
        self.out = QTextEdit()
        self.out.setReadOnly(True)
        layout.addWidget(self.out, 1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        self.btn_lab.clicked.connect(self._start_lab)
        self.btn_scan.clicked.connect(self._scripted_scan)
        self.btn_sim.clicked.connect(self._run_simulation)

    def _start_lab(self) -> None:
        if self._lab is not None:
            return
        try:
            server, _thread, url = start_lab_server()
        except OSError as exc:
            self.lbl_lab.setText(f"Local lab failed to start: {exc}")
            return
        self._lab = (server, url)
        self.lbl_lab.setText(f"Local lab running at {url}")
        self.ctx.log_event("lab", f"demo lab started at {url}", source="demo")

    def stop_all(self) -> None:
        """Stop any running scripted scan (used when the window closes)."""
        if self._worker is not None and hasattr(self._worker, "stop_scan"):
            try:
                self._worker.stop_scan()
            except Exception:
                pass

    def _scripted_scan(self) -> None:
        if self._lab is None:
            self._start_lab()
        url = self._lab[1]
        config = ScanConfig(
            target=url, allowlist=["127.0.0.1"], local_lab_enabled=True,
            authorized=True, rate_limit_seconds=0.05, timeout_seconds=10)
        worker = ScanWorker(lambda: Scanner(config), self)
        worker.finished.connect(
            lambda r: self.status_label.setText(
                f"Scripted lab scan: {len(r.findings)} finding(s), "
                f"{r.requests_made} request(s). See the Scanner page for "
                "detail; this was a SIMULATED lab target."))
        worker.error.connect(
            lambda m: self.status_label.setText(f"Scripted scan failed: {m}"))
        self._worker = worker
        worker.start()

    def _simulation_results(self) -> dict[str, str]:
        """Run the scenario's rule screening + model call.

        Each call degrades to an explicit "not measured" string on
        failure; this method never raises for an API problem, so the
        demo never fabricates a measured result.
        """
        scenario = SIM_SCENARIOS[self.cb_scenario.currentText()]
        measured_rule = "not measured (sign in to run rule screening)"
        measured_model = "not measured (model unavailable or not signed in)"
        try:
            screen = self.ctx.client.screen(scenario["log"])
            findings = screen.get("findings", [])
            measured_rule = (
                f"{len(findings)} deterministic finding(s): "
                + "; ".join(f.get("rule", "?") for f in findings)
                if findings else "no deterministic finding fired")
        except Exception:
            pass
        try:
            api = self.ctx.client.analyze(scenario["log"], scenario["kind"])
            measured_model = (
                f"model classification={api.get('classification')} "
                f"(source: {api.get('decision_source')})")
        except Exception:
            pass
        return {
            "scenario": self.cb_scenario.currentText(),
            "log": scenario["log"],
            "expected": scenario["expected"],
            "rule": measured_rule,
            "model": measured_model,
        }

    def _run_simulation(self) -> None:
        # Network calls must not run on the GUI thread: a CPU inference
        # here used to freeze the whole window for minutes.
        self.status_label.setText("Running simulation…")
        worker = InferenceWorker(self._simulation_results, self)
        worker.finished.connect(self._simulation_done)
        worker.error.connect(
            lambda m: self.status_label.setText(f"Simulation failed: {m}"))
        self._worker = worker
        worker.start()

    def _simulation_done(self, res: dict) -> None:
        self.out.setPlainText(
            f"SIMULATED scenario: {res['scenario']}\n\n"
            f"Simulated event: {res['log']}\n\n"
            f"Expected detection (scenario design): {res['expected']}\n\n"
            f"Measured deterministic result: {res['rule']}\n\n"
            f"Measured model result: {res['model']}\n\n"
            "Defender next steps: confirm the finding in the real "
            "environment, block or rate-limit the source if the pattern "
            "repeats, review the affected service's logs, and record the "
            "outcome as a case. This simulation proves nothing about any "
            "real website.")
        self.status_label.setText("Simulation done (SIMULATED).")


# ------------------------------------------------------------ diagnostics
class DiagnosticsPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker = None
        layout = QVBoxLayout(self)
        heading = QLabel("Diagnostics & Self-Test")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "One click checks configuration, model artifacts, backend "
            "readiness, scanner safety, and report generation. Model "
            "inference is reported as untested when the backend does not "
            "report the model ready — never assumed."))
        self.btn_run = QPushButton("Run self-test")
        layout.addWidget(self.btn_run)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Check", "Status", "Detail", "Fix"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        self.btn_run.clicked.connect(self._run)

    def _run(self) -> None:
        self.btn_run.setEnabled(False)
        self.status_label.setText("Running self-test…")
        worker = DiagnosticsWorker(
            lambda progress: run_diagnostics(
                self.ctx.settings, self.ctx.data_dir, progress), self)
        worker.progress.connect(
            lambda name: self.status_label.setText(f"Checking: {name}…"))
        worker.finished.connect(self._done)
        worker.error.connect(
            lambda m: (self.status_label.setText(f"Self-test failed: {m}"),
                       self.btn_run.setEnabled(True)))
        self._worker = worker
        worker.start()

    def _done(self, results) -> None:
        self.btn_run.setEnabled(True)
        self.table.setRowCount(len(results))
        counts: dict[str, int] = {}
        for row, res in enumerate(results):
            counts[res.status] = counts.get(res.status, 0) + 1
            self.table.setItem(row, 0, QTableWidgetItem(res.name))
            status_item = QTableWidgetItem(res.status)
            status_item.setBackground(QColor(
                STATUS_COLORS.get(res.status, "#8c8c8c")))
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, QTableWidgetItem(res.detail))
            self.table.setItem(row, 3, QTableWidgetItem(res.fix))
        self.status_label.setText("Self-test done: " + ", ".join(
            f"{k} {v}" for k, v in counts.items()))
        self.ctx.log_event("diagnostics",
                           f"self-test: {counts}", source="diagnostics")


# --------------------------------------------------------------- settings
class SettingsPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        layout = QVBoxLayout(self)
        heading = QLabel("Settings")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        form = QFormLayout()
        self.ed_api_host = QLineEdit()
        self.ed_api_port = QLineEdit()
        self.ed_allow = QLineEdit()
        self.ck_lab = QCheckBox()
        self.ed_rate = QLineEdit()
        self.ed_timeout = QLineEdit()
        self.ed_max_req = QLineEdit()
        self.ed_workers = QLineEdit()
        self.ed_lab_user = QLineEdit()
        self.ed_lab_pass = QLineEdit()
        self.ed_lab_pass.setEchoMode(QLineEdit.Password)
        self._load_fields()
        form.addRow("API host:", self.ed_api_host)
        form.addRow("API port:", self.ed_api_port)
        form.addRow("Allowlist (comma separated):", self.ed_allow)
        form.addRow("Local-lab mode:", self.ck_lab)
        form.addRow("Min seconds between scan requests:", self.ed_rate)
        form.addRow("Scan request timeout (s):", self.ed_timeout)
        form.addRow("Max requests per scan:", self.ed_max_req)
        form.addRow("Max scan workers:", self.ed_workers)
        form.addRow("Lab account username:", self.ed_lab_user)
        form.addRow("Lab account password (local-only, see Settings note):",
                    self.ed_lab_pass)
        layout.addLayout(form)
        layout.addWidget(QLabel(
            "The lab password is a throwaway local credential for the "
            "SentientAI account this tool creates on your machine. It is "
            "never exported in reports. Leave it empty to sign in with "
            "your own login each session instead (kept in memory only)."))
        layout.addWidget(QLabel(f"Data directory: {ctx.data_dir}"))
        row = QHBoxLayout()
        self.btn_save = QPushButton("Save settings")
        self.btn_reset = QPushButton("Reset to defaults")
        row.addWidget(self.btn_save)
        row.addWidget(self.btn_reset)
        row.addStretch()
        layout.addLayout(row)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        layout.addStretch()
        self.btn_save.clicked.connect(self._save)
        self.btn_reset.clicked.connect(self._reset)

    def _load_fields(self) -> None:
        """Reload the form widgets from current settings."""
        s = self.ctx.settings
        self.ed_api_host.setText(s.api_host)
        self.ed_api_port.setText(str(s.api_port))
        self.ed_allow.setText(", ".join(s.allowlist))
        self.ck_lab.setChecked(s.local_lab_enabled)
        self.ed_rate.setText(str(s.rate_limit_seconds))
        self.ed_timeout.setText(str(s.request_timeout_seconds))
        self.ed_max_req.setText(str(s.max_requests_per_scan))
        self.ed_workers.setText(str(s.max_workers))
        self.ed_lab_user.setText(s.lab_username)
        self.ed_lab_pass.setText(s.lab_password)

    def _save(self) -> None:
        s = self.ctx.settings
        try:
            port = int(self.ed_api_port.text().strip())
            rate = float(self.ed_rate.text().strip())
            timeout = float(self.ed_timeout.text().strip())
            max_req = int(self.ed_max_req.text().strip())
            workers = int(self.ed_workers.text().strip())
        except ValueError:
            self.status_label.setText("Numeric fields must be numbers.")
            return
        if not 1 <= port <= 65535:
            self.status_label.setText("API port must be between 1 and 65535.")
            return
        if rate < 0:
            self.status_label.setText(
                "Min seconds between scan requests must be >= 0.")
            return
        if timeout <= 0:
            self.status_label.setText(
                "Scan request timeout must be > 0 seconds.")
            return
        if max_req < 1:
            self.status_label.setText("Max requests per scan must be >= 1.")
            return
        if workers < 1:
            self.status_label.setText("Max scan workers must be >= 1.")
            return
        s.api_host = self.ed_api_host.text().strip() or "127.0.0.1"
        s.api_port = port
        s.rate_limit_seconds = rate
        s.request_timeout_seconds = timeout
        s.max_requests_per_scan = max_req
        s.max_workers = workers
        s.api_base = f"http://{s.api_host}:{s.api_port}"
        s.allowlist = [h.strip() for h in self.ed_allow.text().split(",")
                       if h.strip()]
        s.local_lab_enabled = self.ck_lab.isChecked()
        s.lab_username = self.ed_lab_user.text().strip() or "seclab"
        s.lab_password = self.ed_lab_pass.text()
        save_settings(s, self.ctx.data_dir)
        self.ctx.apply_settings()
        self.status_label.setText("Settings saved.")

    def _reset(self) -> None:
        if not confirm(self, "Reset settings",
                       "Reset all settings to defaults? The lab password "
                       "will be cleared."):
            return
        from ..config import Settings as Fresh

        fresh = Fresh()
        self.ctx.settings.__dict__.update(fresh.__dict__)
        save_settings(self.ctx.settings, self.ctx.data_dir)
        self.ctx.apply_settings()
        self._load_fields()
        self.status_label.setText("Settings reset to defaults.")
