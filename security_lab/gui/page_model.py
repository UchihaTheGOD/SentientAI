"""Tool 3 — CyberLLMv1 Model Testing & Evaluation.

Runs the REAL model through the existing backend API. If the backend
is down, the model fails, or output is unparseable, the page shows
the real error — never a fabricated verdict. Confidence and MITRE
mappings appear only when the API actually returns them.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (QComboBox, QFileDialog, QGroupBox, QHBoxLayout,
                               QLabel, QPlainTextEdit, QProgressBar,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QTextEdit, QVBoxLayout, QWidget)

from ..client import BackendClient
from ..evaluation import (compare_baseline, export_eval_csv,
                          export_eval_json, load_cases, run_evaluation,
                          save_baseline)
from ..model import EXAMPLE_CASES, mark_abstained, shape_analysis
from .context import AppContext
from .workers import BatchWorker, InferenceWorker


class ModelTestingPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker = None
        self._shaped = None
        self._eval_result = None
        layout = QVBoxLayout(self)

        heading = QLabel("CyberLLMv1 Model Testing & Evaluation")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Real inference via the backend API. Sign in first (lab "
            "account from Settings, or your own SentientAI login)."))

        # -- sign-in -----------------------------------------------------------
        sign_row = QHBoxLayout()
        self.btn_signin = QPushButton("Sign in with lab account")
        self.btn_signin_own = QPushButton("Sign in with my own login…")
        self.lbl_auth = QLabel("Not signed in.")
        self.lbl_auth.setObjectName("muted")
        sign_row.addWidget(self.btn_signin)
        sign_row.addWidget(self.btn_signin_own)
        sign_row.addWidget(self.lbl_auth, 1)
        layout.addLayout(sign_row)
        self.btn_signin.clicked.connect(self._signin_lab)
        self.btn_signin_own.clicked.connect(self._signin_own)

        # -- single test ---------------------------------------------------------
        single = QGroupBox("Single analysis")
        s_layout = QVBoxLayout(single)
        row = QHBoxLayout()
        self.cb_kind = QComboBox()
        self.cb_kind.addItems(["log", "http_request", "url", "vulnerability"])
        self.cb_example = QComboBox()
        self.cb_example.addItems(["(type your own input)"] +
                                 [c["name"] for c in EXAMPLE_CASES])
        row.addWidget(QLabel("Kind:"))
        row.addWidget(self.cb_kind)
        row.addWidget(QLabel("Example:"))
        row.addWidget(self.cb_example, 1)
        s_layout.addLayout(row)
        self.cb_example.currentIndexChanged.connect(self._load_example)
        self.ed_input = QPlainTextEdit()
        self.ed_input.setPlaceholderText(
            "Paste a security log, HTTP request, URL, or vulnerability "
            "description…")
        s_layout.addWidget(self.ed_input)
        run_row = QHBoxLayout()
        self.btn_run = QPushButton("Run Inference")
        self.btn_abstain = QPushButton("Mark abstained (insufficient evidence)")
        self.btn_abstain.setEnabled(False)
        run_row.addWidget(self.btn_run)
        run_row.addWidget(self.btn_abstain)
        run_row.addStretch()
        s_layout.addLayout(run_row)
        self.btn_run.clicked.connect(self._run_inference)
        self.btn_abstain.clicked.connect(self._abstain)
        self.lbl_single = QLabel("")
        self.lbl_single.setObjectName("muted")
        s_layout.addWidget(self.lbl_single)
        self.out_raw = QTextEdit()
        self.out_raw.setReadOnly(True)
        self.out_raw.setPlaceholderText("Raw model output appears here.")
        self.out_parsed = QTextEdit()
        self.out_parsed.setReadOnly(True)
        self.out_parsed.setPlaceholderText("Parsed structured output appears here.")
        s_layout.addWidget(QLabel("Raw model response:"))
        s_layout.addWidget(self.out_raw)
        s_layout.addWidget(QLabel("Parsed structured output:"))
        s_layout.addWidget(self.out_parsed)
        layout.addWidget(single)

        # -- batch ---------------------------------------------------------------
        batch = QGroupBox("Batch evaluation (JSONL or CSV with expected labels)")
        b_layout = QVBoxLayout(batch)
        brow = QHBoxLayout()
        self.btn_pick = QPushButton("Choose file…")
        self.btn_batch = QPushButton("Run batch evaluation")
        self.lbl_batch_file = QLabel("No file chosen.")
        self.lbl_batch_file.setObjectName("muted")
        brow.addWidget(self.btn_pick)
        brow.addWidget(self.btn_batch)
        brow.addWidget(self.lbl_batch_file, 1)
        b_layout.addLayout(brow)
        self.progress = QProgressBar()
        b_layout.addWidget(self.progress)
        self.out_metrics = QTextEdit()
        self.out_metrics.setReadOnly(True)
        self.out_metrics.setPlaceholderText(
            "Metrics appear here. Without ground-truth labels the result "
            "is reported as 'not evaluated', never as a fabricated score.")
        b_layout.addWidget(self.out_metrics)
        brow2 = QHBoxLayout()
        self.btn_exp_eval_json = QPushButton("Export evaluation JSON")
        self.btn_exp_eval_csv = QPushButton("Export evaluation CSV")
        self.btn_save_base = QPushButton("Save as baseline")
        self.btn_cmp_base = QPushButton("Compare with baseline…")
        for btn in (self.btn_exp_eval_json, self.btn_exp_eval_csv,
                    self.btn_save_base, self.btn_cmp_base):
            brow2.addWidget(btn)
        brow2.addStretch()
        b_layout.addLayout(brow2)
        layout.addWidget(batch)
        self._batch_path: Path | None = None
        self.btn_pick.clicked.connect(self._pick_batch)
        self.btn_batch.clicked.connect(self._run_batch)
        self.btn_exp_eval_json.clicked.connect(
            lambda: self._export_eval("json"))
        self.btn_exp_eval_csv.clicked.connect(
            lambda: self._export_eval("csv"))
        self.btn_save_base.clicked.connect(self._save_baseline)
        self.btn_cmp_base.clicked.connect(self._compare_baseline)
        layout.addStretch()

    # -- auth -------------------------------------------------------------------
    def _ensure_client(self) -> BackendClient:
        return self.ctx.client

    def _signin_lab(self) -> None:
        s = self.ctx.settings
        if not s.lab_password:
            self.lbl_auth.setText(
                "No lab password saved in Settings. Save one there, or use "
                "'my own login'.")
            return
        client = self._ensure_client()
        try:
            ok, msg = client.ensure_lab_user(s.lab_username, s.lab_password)
        except Exception as exc:
            self.lbl_auth.setText(f"Lab sign-in failed: {exc}")
            return
        self.lbl_auth.setText(
            f"Signed in as {s.lab_username}." if ok else f"Sign-in failed: {msg}")

    def _signin_own(self) -> None:
        from .dialogs import ask_text

        username = ask_text(self, "Sign in", "SentientAI username:")
        if username is None:
            return
        password = ask_text(self, "Sign in", "Password (kept in memory only):")
        if password is None:
            return
        client = self._ensure_client()
        try:
            ok, msg = client.login(username.strip(), password)
        except Exception as exc:
            self.lbl_auth.setText(f"Sign-in failed: {exc}")
            return
        self.lbl_auth.setText(
            f"Signed in as {username.strip()}." if ok else f"Sign-in failed: {msg}")

    # -- single -------------------------------------------------------------------
    def _load_example(self, index: int) -> None:
        if index <= 0:
            return
        case = EXAMPLE_CASES[index - 1]
        self.cb_kind.setCurrentText(case["kind"])
        self.ed_input.setPlainText(case["text"])
        self.lbl_single.setText(
            f"Example: {case['name']} — {case['note']} "
            f"(illustrative expected label: {case['expected']})")

    def _run_inference(self) -> None:
        text = self.ed_input.toPlainText().strip()
        if not text:
            self.lbl_single.setText("Enter input text first.")
            return
        kind = self.cb_kind.currentText()
        client = self._ensure_client()
        self.lbl_single.setText("Running inference… (this takes a while on CPU)")
        self.btn_run.setEnabled(False)

        def do_it() -> dict:
            readiness = client.readiness()
            api = client.analyze(text, kind)
            return shape_analysis(api, readiness=readiness)

        worker = InferenceWorker(do_it, self)
        worker.finished.connect(self._inference_done)
        worker.error.connect(self._inference_error)
        self._worker = worker
        worker.start()

    def _inference_done(self, shaped: dict) -> None:
        self.btn_run.setEnabled(True)
        self._shaped = shaped
        self.btn_abstain.setEnabled(True)
        self.out_raw.setPlainText(shaped.get("raw_output") or "(no raw output returned)")
        mitre = shaped.get("mitre")
        parsed = (
            f"Classification: {shaped['classification']}\n"
            f"Model classification: {shaped.get('model_classification')}\n"
            f"Confidence: {shaped.get('confidence') or 'not provided by the model'}\n"
            f"Decision source: {shaped['decision_source']}\n"
            f"Needs review: {shaped['needs_review']}\n"
            f"Device: {shaped.get('device') or 'unknown'} / "
            f"quantization: {shaped.get('quantization') or 'unknown'}\n"
            f"Output tokens: {shaped.get('output_tokens')}\n"
            f"Latency: {shaped.get('latency_ms')} ms\n"
            f"Truncated: {shaped['truncated']} / Parse OK: {shaped['parse_ok']}\n"
            f"MITRE mapping: {mitre if mitre else 'not provided by the model'}\n\n"
            f"Summary: {shaped.get('summary')}\n\n"
            f"Indicators: {'; '.join(shaped.get('indicators') or [])}\n\n"
            f"Reasoning: {shaped.get('reasoning')}\n\n"
            f"Limitations: {'; '.join(shaped.get('limitations') or [])}\n\n"
            f"Recommended actions: {'; '.join(shaped.get('recommended_actions') or [])}\n\n"
            f"Deterministic findings: {shaped.get('deterministic_findings')}\n"
            f"Note: {shaped.get('note')}")
        self.out_parsed.setPlainText(parsed)
        self.lbl_single.setText(
            f"Verdict: {shaped['classification']} "
            f"(source: {shaped['decision_source']}; "
            f"latency {shaped.get('latency_ms')} ms; "
            f"tokens {shaped.get('output_tokens')})")
        self.ctx.log_event("inference",
                           f"{shaped['classification']} via "
                           f"{shaped['decision_source']}", source="model-testing")

    def _inference_error(self, msg: str) -> None:
        self.btn_run.setEnabled(True)
        self.lbl_single.setText(f"Inference failed (real error): {msg}")
        self.out_raw.setPlainText("")
        self.out_parsed.setPlainText(
            "No verdict: the backend or model did not return one. "
            "See the error above; nothing has been fabricated.")

    def _abstain(self) -> None:
        if self._shaped is None:
            return
        self._shaped = mark_abstained(self._shaped)
        self.lbl_single.setText("Marked abstained: insufficient evidence.")
        self.out_parsed.setPlainText(
            self.out_parsed.toPlainText() +
            "\n\nAnalyst abstained: insufficient evidence for a verdict.")

    # -- batch ----------------------------------------------------------------------
    def _pick_batch(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose evaluation file", "",
            "Evaluation files (*.jsonl *.csv)")
        if path:
            self._batch_path = Path(path)
            self.lbl_batch_file.setText(path)

    def _run_batch(self) -> None:
        if self._batch_path is None:
            self.lbl_batch_file.setText("Choose a file first.")
            return
        try:
            cases = load_cases(self._batch_path)
        except Exception as exc:
            self.lbl_batch_file.setText(f"Could not read file: {exc}")
            return
        if not cases:
            self.lbl_batch_file.setText("File contains no cases.")
            return
        client = self._ensure_client()
        self.progress.setValue(0)
        self.btn_batch.setEnabled(False)

        def do_batch(progress):
            return run_evaluation(
                lambda text, kind: client.analyze(text, kind),
                cases,
                progress=lambda d, t: progress.emit(d, t))

        worker = BatchWorker(do_batch, self)
        worker.progress.connect(
            lambda d, t: self.progress.setValue(int(d / max(t, 1) * 100)))
        worker.finished.connect(self._batch_done)
        worker.error.connect(self._batch_error)
        self._worker = worker
        worker.start()

    def _batch_error(self, msg: str) -> None:
        self.btn_batch.setEnabled(True)
        self.lbl_batch_file.setText(f"Batch failed: {msg}")

    def _batch_done(self, result) -> None:
        self.btn_batch.setEnabled(True)
        self._eval_result = result
        self.progress.setValue(100)
        m = result.metrics
        if m is None:
            text = ("Not evaluated: no ground-truth labels were present in "
                    "the file, so no accuracy or recall is reported.\n\n")
        else:
            text = (
                f"Cases: {m['total']} (decided {m['decided']}, abstained "
                f"{m['abstained']}, errors {m['errors']})\n"
                f"Accuracy: {m['accuracy']}\n"
                f"Threat recall: {m['threat_recall']}\n"
                f"False-positive rate: {m['false_positive_rate']}\n\n"
                f"Per class: {m['per_class']}\n\n"
                f"Per kind: {m['per_kind']}\n\n"
                f"Confusion matrix (expected -> predicted):\n{m['confusion_matrix']}\n")
        text += "\n".join(
            f"{c.name}: expected={c.expected} predicted={c.predicted}"
            + (f" error={c.error}" if c.error else "")
            for c in result.cases)
        self.out_metrics.setPlainText(text)
        self.lbl_batch_file.setText(
            f"Batch finished: {len(result.cases)} case(s).")
        self.ctx.log_event("evaluation",
                           f"batch: {len(result.cases)} cases",
                           source="model-testing")

    def _export_eval(self, kind: str) -> None:
        if self._eval_result is None:
            self.lbl_batch_file.setText("Run a batch evaluation first.")
            return
        default = str(self.ctx.dirs["reports"] /
                      f"evaluation.{kind}")
        path, _ = QFileDialog.getSaveFileName(self, "Export evaluation", default)
        if not path:
            return
        try:
            if kind == "json":
                export_eval_json(self._eval_result, Path(path))
            else:
                export_eval_csv(self._eval_result, Path(path))
            self.lbl_batch_file.setText(f"Evaluation exported to {path}")
        except OSError as exc:
            self.lbl_batch_file.setText(f"Export failed: {exc}")

    def _save_baseline(self) -> None:
        if self._eval_result is None:
            self.lbl_batch_file.setText("Run a batch evaluation first.")
            return
        path = self.ctx.dirs["reports"] / "evaluation-baseline.json"
        try:
            save_baseline(self._eval_result, path)
        except OSError as exc:
            self.lbl_batch_file.setText(f"Baseline save failed: {exc}")
            return
        self.lbl_batch_file.setText(f"Baseline saved to {path}")

    def _compare_baseline(self) -> None:
        if self._eval_result is None:
            self.lbl_batch_file.setText("Run a batch evaluation first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose baseline JSON", "",
            "JSON files (*.json)")
        if not path:
            return
        try:
            diff = compare_baseline(self._eval_result, Path(path))
        except Exception as exc:
            self.lbl_batch_file.setText(f"Comparison failed: {exc}")
            return
        self.out_metrics.setPlainText(
            f"Regression comparison: {diff['verdict']}\n"
            f"Metric deltas: {diff['metric_deltas']}\n"
            f"Improvements: {diff['improvements']}\n"
            f"Regressions: {diff['regressions']}\n"
            f"Unchanged: {len(diff['unchanged'])} case(s)")
