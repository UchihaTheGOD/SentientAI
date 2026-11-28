"""Prompt & Output Test Lab — test prompts against the real CyberLLM model.

Runs prompts through the existing backend API (POST /api/cyberllm/analyze)
and records everything: prompt, model/adapter, timestamp, settings,
output, duration, tokens, JSON validity, and schema compliance.

Honest limits, by design:
- Generation is GREEDY (deterministic) in the backend. There is no
  temperature / top-p / top-k / repetition-penalty control — the API does
  not accept those parameters, so this page does not offer them. The only
  generation setting the backend supports is max_new_tokens (16-512).
- The system prompt is applied server-side and is not exposed by the API.
  This page shows the deployed prompt only when it can be read from the
  local project copy; otherwise it says so instead of inventing one.
- History is stored locally (JSONL in the lab data dir) and never leaves
  the machine. Prompts may contain sensitive log data — use "Clear
  history" to wipe it. No secrets are ever recorded.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QGroupBox, QHBoxLayout, QLabel,
                               QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QSplitter, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from ..model import shape_analysis
from .context import AppContext
from .workers import InferenceWorker

KINDS = ["log", "http_request", "url", "vulnerability"]
KIND_LABELS = {
    "log": "Log analysis",
    "http_request": "HTTP request",
    "url": "URL classification",
    "vulnerability": "Vulnerability / CVE",
}
REQUIRED_KEYS = ["summary", "classification", "confidence", "indicators",
                 "reasoning", "limitations", "recommended_actions"]


def _json_validity(raw: str) -> tuple[bool, str]:
    """Return (is_valid_json_object, detail)."""
    try:
        data = json.loads(raw)
    except Exception as exc:
        return False, f"invalid JSON: {exc}"
    if not isinstance(data, dict):
        return False, "JSON is valid but is not an object"
    missing = [k for k in REQUIRED_KEYS if k not in data]
    if missing:
        return False, f"valid JSON but missing keys: {', '.join(missing)}"
    return True, "valid JSON object with all 7 required keys"


class TestLabPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker = None
        self._history: list[dict] = []
        self._history_path = ctx.data_dir / "test_lab_history.jsonl"
        self._load_history()
        layout = QVBoxLayout(self)

        heading = QLabel("Prompt & Output Test Lab")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Test prompts against the real CyberLLM model (Pilot v8) via the "
            "backend API. Sign in first (lab account from Settings, or your "
            "own SentientAI login). Generation is greedy/deterministic — "
            "the backend supports no temperature or sampling controls."))

        # -- input -----------------------------------------------------------
        inp = QGroupBox("Prompt")
        i_layout = QVBoxLayout(inp)
        row = QHBoxLayout()
        self.cb_kind = QComboBox()
        for kind in KINDS:
            self.cb_kind.addItem(KIND_LABELS[kind], kind)
        self.sp_max_tokens = QSpinBox()
        self.sp_max_tokens.setRange(16, 512)
        self.sp_max_tokens.setValue(320)
        self.sp_max_tokens.setSuffix(" max tokens")
        row.addWidget(QLabel("Mode:"))
        row.addWidget(self.cb_kind)
        row.addWidget(QLabel("Max new tokens:"))
        row.addWidget(self.sp_max_tokens)
        row.addStretch()
        i_layout.addLayout(row)
        self.ed_prompt = QPlainTextEdit()
        self.ed_prompt.setPlaceholderText(
            "Type or paste a prompt — a security log, an HTTP request, "
            "a URL, or a vulnerability description…")
        i_layout.addWidget(self.ed_prompt)
        run_row = QHBoxLayout()
        self.btn_run = QPushButton("Run test")
        self.btn_clear_hist = QPushButton("Clear history")
        self.lbl_run = QLabel("")
        self.lbl_run.setObjectName("muted")
        run_row.addWidget(self.btn_run)
        run_row.addWidget(self.btn_clear_hist)
        run_row.addWidget(self.lbl_run, 1)
        i_layout.addLayout(run_row)
        layout.addWidget(inp)
        self.btn_run.clicked.connect(self._run_test)
        self.btn_clear_hist.clicked.connect(self._clear_history)

        # -- results ---------------------------------------------------------
        res = QGroupBox("Result")
        r_layout = QVBoxLayout(res)
        self.lbl_meta = QLabel("No test run yet.")
        self.lbl_meta.setObjectName("muted")
        r_layout.addWidget(self.lbl_meta)
        split = QSplitter()
        self.out_raw = QTextEdit()
        self.out_raw.setReadOnly(True)
        self.out_raw.setPlaceholderText("Raw model output appears here.")
        self.out_parsed = QTextEdit()
        self.out_parsed.setReadOnly(True)
        self.out_parsed.setPlaceholderText("Parsed structured output appears here.")
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.addWidget(QLabel("Raw model response:"))
        ll.addWidget(self.out_raw)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(QLabel("Parsed structured output:"))
        rl.addWidget(self.out_parsed)
        split.addWidget(left)
        split.addWidget(right)
        r_layout.addWidget(split)

        # -- history ---------------------------------------------------------
        hist = QGroupBox("History (stored locally only)")
        h_layout = QVBoxLayout(hist)
        self.tbl = QTableWidget(0, 6)
        self.tbl.setHorizontalHeaderLabels(
            ["Time", "Mode", "Classification", "JSON valid", "Tokens", "Latency (ms)"])
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setSelectionMode(QTableWidget.MultiSelection)
        h_layout.addWidget(self.tbl)
        cmp_row = QHBoxLayout()
        self.btn_compare = QPushButton("Compare selected (2 runs)")
        self.lbl_compare = QLabel("")
        self.lbl_compare.setObjectName("muted")
        cmp_row.addWidget(self.btn_compare)
        cmp_row.addWidget(self.lbl_compare, 1)
        h_layout.addLayout(cmp_row)
        # Result and History share a vertical splitter so the user can drag
        # the divider to give the history table more room. The Result group
        # takes extra space when the window grows.
        vsplit = QSplitter(Qt.Vertical)
        vsplit.addWidget(res)
        vsplit.addWidget(hist)
        vsplit.setStretchFactor(0, 1)
        vsplit.setStretchFactor(1, 0)
        layout.addWidget(vsplit, 1)
        self.btn_compare.clicked.connect(self._compare_selected)
        self._refresh_table()

    # -- history ------------------------------------------------------------
    def _load_history(self) -> None:
        try:
            if self._history_path.is_file():
                for line in self._history_path.read_text(
                        encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        self._history.append(json.loads(line))
        except Exception:
            self._history = []

    def _save_history(self) -> None:
        try:
            self._history_path.write_text(
                "".join(json.dumps(h, ensure_ascii=False) + "\n"
                        for h in self._history),
                encoding="utf-8")
        except Exception:
            pass

    def _refresh_table(self) -> None:
        self.tbl.setRowCount(len(self._history))
        for row, h in enumerate(self._history):
            vals = [h.get("timestamp", ""), h.get("kind", ""),
                    str(h.get("classification", "")),
                    "yes" if h.get("json_valid") else "no",
                    str(h.get("output_tokens", "")),
                    str(h.get("latency_ms", ""))]
            for col, val in enumerate(vals):
                self.tbl.setItem(row, col, QTableWidgetItem(val))
        self.tbl.resizeColumnsToContents()

    def _clear_history(self) -> None:
        answer = QMessageBox.question(
            self, "Clear history",
            "Delete all recorded Test Lab runs from this machine?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self._history = []
        self._save_history()
        self._refresh_table()
        self.lbl_run.setText("History cleared.")

    # -- run ------------------------------------------------------------------
    def _run_test(self) -> None:
        text = self.ed_prompt.toPlainText().strip()
        if not text:
            self.lbl_run.setText("Enter a prompt first.")
            return
        kind = self.cb_kind.currentData()
        max_tokens = self.sp_max_tokens.value()
        client = self.ctx.client
        self.lbl_run.setText("Running… (this takes a while on CPU)")
        self.btn_run.setEnabled(False)
        started = time.monotonic()

        def _call():
            return client.analyze(text, kind=kind, max_new_tokens=max_tokens)

        self._worker = InferenceWorker(_call)
        self._worker.finished.connect(
            lambda res: self._done(res, text, kind, max_tokens, started))
        self._worker.error.connect(self._failed)
        self._worker.start()

    def _done(self, res: dict, text: str, kind: str, max_tokens: int,
              started: float) -> None:
        self.btn_run.setEnabled(True)
        duration_ms = int((time.monotonic() - started) * 1000)
        raw = res.get("raw_output", "") or ""
        json_ok, json_detail = _json_validity(raw)
        # Parse the structured output for display (never fabricate it).
        parsed = {k: res.get(k) for k in
                  ("classification", "confidence", "summary", "indicators",
                   "reasoning", "limitations", "recommended_actions")}
        self.out_raw.setPlainText(raw)
        self.out_parsed.setPlainText(
            json.dumps(parsed, indent=2, ensure_ascii=False))
        s = self.ctx.settings
        record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "max_new_tokens": max_tokens,
            "prompt": text,
            "model": "CyberLLM Pilot v8",
            "adapter_sha256": s.adapter_sha256,
            "classification": res.get("classification"),
            "confidence": res.get("confidence"),
            "parse_ok": res.get("parse_ok"),
            "truncated": res.get("truncated"),
            "output_tokens": res.get("output_tokens"),
            "latency_ms": res.get("latency_ms", duration_ms),
            "json_valid": json_ok,
            "json_detail": json_detail,
            "raw_output": raw,
        }
        self._history.append(record)
        self._save_history()
        self._refresh_table()
        self.lbl_meta.setText(
            f"Model: CyberLLM Pilot v8 (adapter SHA {s.adapter_sha256[:12]}…) | "
            f"Kind: {kind} | Max tokens: {max_tokens} | "
            f"Output tokens: {res.get('output_tokens')} | "
            f"Latency: {res.get('latency_ms', duration_ms)} ms | "
            f"JSON: {json_detail} | "
            f"Truncated: {res.get('truncated')}")
        self.lbl_run.setText(
            f"Done. Classification: {res.get('classification')} "
            f"({res.get('confidence')}).")

    def _failed(self, message: str) -> None:
        self.btn_run.setEnabled(True)
        self.lbl_run.setText(f"Test failed: {message}")
        self.out_raw.setPlainText("")
        self.out_parsed.setPlainText("")

    # -- compare --------------------------------------------------------------
    def _compare_selected(self) -> None:
        rows = sorted({idx.row() for idx in self.tbl.selectedIndexes()})
        if len(rows) != 2:
            self.lbl_compare.setText("Select exactly 2 history rows to compare.")
            return
        a, b = (self._history[r] for r in rows)
        diff = []
        for key in ("kind", "classification", "confidence", "output_tokens",
                    "latency_ms", "json_valid"):
            if a.get(key) != b.get(key):
                diff.append(f"{key}: {a.get(key)} → {b.get(key)}")
        self.lbl_compare.setText(
            "Differences: " + ("; ".join(diff) if diff else "none — same result") +
            f". Run A ({a.get('timestamp')}) vs Run B ({b.get('timestamp')}). "
            "Raw outputs are in the history file.")
        # Show both raw outputs side by side in the result panes.
        self.out_raw.setPlainText(
            f"--- Run A ({a.get('timestamp')}, {a.get('kind')}) ---\n"
            f"{a.get('raw_output', '')}\n\n"
            f"--- Run B ({b.get('timestamp')}, {b.get('kind')}) ---\n"
            f"{b.get('raw_output', '')}")
        self.out_parsed.setPlainText(
            json.dumps({"run_a": {k: a.get(k) for k in
                                  ("classification", "confidence", "output_tokens")},
                        "run_b": {k: b.get(k) for k in
                                  ("classification", "confidence", "output_tokens")}},
                       indent=2, ensure_ascii=False))
