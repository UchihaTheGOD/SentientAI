"""Tool 1 — Website & Model Control Center.

Manages the existing SentientAI backend: start/stop/restart, health,
readiness, GPU/system stats, model-path configuration, adapter SHA
verification, diagnostics entry point, and backend logs. The model
itself is never loaded here; loading happens inside the backend.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QPlainTextEdit, QPushButton, QVBoxLayout,
                               QWidget)

from .. import backend as backend_mod
from ..config import save_settings
from ..tunnel import (OFFICIAL_DOWNLOADS, PROVIDER_AUTH, build_command,
                      detect_providers, save_ngrok_authtoken, start_tunnel)
from .context import AppContext
from .workers import BackendWorker, InferenceWorker


class ControlCenterPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._worker = None
        layout = QVBoxLayout(self)

        heading = QLabel("Website & Model Control Center")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Manages the existing SentientAI backend. The model loads "
            "inside the backend; this page never loads weights itself."))
        self.status_label = QLabel("Backend status: unknown")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)

        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("Start backend")
        self.btn_stop = QPushButton("Stop backend")
        self.btn_restart = QPushButton("Restart backend")
        self.btn_refresh = QPushButton("Refresh status")
        self.btn_open_site = QPushButton("Open website")
        for btn in (self.btn_start, self.btn_stop, self.btn_restart,
                    self.btn_refresh, self.btn_open_site):
            btn_row.addWidget(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)
        self.btn_start.clicked.connect(lambda: self._backend_action("start"))
        self.btn_stop.clicked.connect(lambda: self._backend_action("stop"))
        self.btn_restart.clicked.connect(lambda: self._backend_action("restart"))
        self.btn_refresh.clicked.connect(self.refresh_status)
        self.btn_open_site.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(self.ctx.settings.api_base)))

        # -- status grid -------------------------------------------------
        status_box = QGroupBox("Backend health")
        form = QFormLayout(status_box)
        self.lbl_running = QLabel("—")
        self.lbl_readiness = QLabel("—")
        self.lbl_device = QLabel("—")
        self.lbl_quant = QLabel("—")
        self.lbl_load = QLabel("—")
        self.lbl_rss = QLabel("—")
        self.lbl_gpu = QLabel("—")
        self.lbl_sys = QLabel("—")
        for label, widget in (
                ("Running:", self.lbl_running),
                ("Readiness:", self.lbl_readiness),
                ("Device:", self.lbl_device),
                ("Quantization:", self.lbl_quant),
                ("Load time:", self.lbl_load),
                ("Backend RSS:", self.lbl_rss),
                ("GPU:", self.lbl_gpu),
                ("CPU / RAM:", self.lbl_sys)):
            form.addRow(label, widget)
        layout.addWidget(status_box)

        # -- configuration ------------------------------------------------
        cfg_box = QGroupBox("Configuration (saved to settings.json)")
        cfg = QFormLayout(cfg_box)
        self.ed_project = QLineEdit(self.ctx.settings.project_root)
        self.ed_python = QLineEdit(self.ctx.settings.backend_python)
        self.ed_host = QLineEdit(self.ctx.settings.api_host)
        self.ed_port = QLineEdit(str(self.ctx.settings.api_port))
        self.ed_model_root = QLineEdit(self.ctx.settings.model_root)
        self.ed_base = QLineEdit(self.ctx.settings.base_dir)
        self.ed_adapter = QLineEdit(self.ctx.settings.adapter_dir)
        self.ed_sha = QLineEdit(self.ctx.settings.adapter_sha256)
        self.cb_device = QComboBox()
        self.cb_device.addItems(["auto", "cpu", "cuda"])
        self.cb_device.setCurrentText(self.ctx.settings.device)
        self.ck_8bit = QCheckBox("Load in 8-bit (CUDA only, needs bitsandbytes)")
        self.ck_8bit.setChecked(self.ctx.settings.load_in_8bit)
        btn_browse_root = QPushButton("Browse…")
        btn_browse_py = QPushButton("Browse…")
        btn_browse_root.clicked.connect(
            lambda: self._browse_dir(self.ed_project))
        btn_browse_py.clicked.connect(
            lambda: self._browse_file(self.ed_python))
        row_root = QHBoxLayout()
        row_root.addWidget(self.ed_project)
        row_root.addWidget(btn_browse_root)
        row_py = QHBoxLayout()
        row_py.addWidget(self.ed_python)
        row_py.addWidget(btn_browse_py)
        cfg.addRow("Project root:", row_root)
        cfg.addRow("Backend Python:", row_py)
        cfg.addRow("API host:", self.ed_host)
        cfg.addRow("API port:", self.ed_port)
        cfg.addRow("Model root (optional):", self.ed_model_root)
        cfg.addRow("Base model dir (optional):", self.ed_base)
        cfg.addRow("Adapter dir (optional):", self.ed_adapter)
        cfg.addRow("Expected adapter SHA-256:", self.ed_sha)
        cfg.addRow("Device:", self.cb_device)
        cfg.addRow("", self.ck_8bit)
        btn_cfg = QHBoxLayout()
        self.btn_save = QPushButton("Save settings")
        self.btn_sha = QPushButton("Verify adapter SHA + artifacts")
        self.btn_diag = QPushButton("Run diagnostics")
        btn_cfg.addWidget(self.btn_save)
        btn_cfg.addWidget(self.btn_sha)
        btn_cfg.addWidget(self.btn_diag)
        btn_cfg.addStretch()
        cfg.addRow("", btn_cfg)
        self.lbl_cfg_status = QLabel("")
        self.lbl_cfg_status.setObjectName("muted")
        cfg.addRow("", self.lbl_cfg_status)
        layout.addWidget(cfg_box)
        self.btn_save.clicked.connect(self.save_settings)
        self.btn_sha.clicked.connect(self.verify_artifacts)
        self.btn_diag.clicked.connect(
            lambda: self.ctx.navigate("diagnostics")
            if self.ctx.navigate else None)

        # -- tunnel manager ------------------------------------------------
        # Expose the local website publicly via Cloudflare Tunnel, ngrok,
        # Pinggy, or zrok. The provider binary must be installed by the
        # user from its official source (Pinggy needs no install: it uses
        # the stock ssh client). No token is stored here — ngrok/zrok use
        # their own one-time setup, and a Pinggy Pro token is held in
        # memory only for the tunnel session. Starting a tunnel shows a
        # pre-exposure warning first — the site must not be shared until
        # auth, admin routes, and debug settings are checked.
        tunnel_box = QGroupBox("Tunnel Manager — public access (optional)")
        t_layout = QVBoxLayout(tunnel_box)
        self.lbl_tunnel_providers = QLabel("Checking providers…")
        self.lbl_tunnel_providers.setObjectName("muted")
        t_layout.addWidget(self.lbl_tunnel_providers)
        self.lbl_tunnel_warn = QLabel(
            "Warning: starting a tunnel makes the website reachable from the "
            "internet. Before sharing, confirm: authentication is on, there "
            "are no default accounts, admin routes require admin, debug is "
            "off, and no secrets are in the repo. The tunnel only ever "
            "forwards to this machine's local backend.")
        self.lbl_tunnel_warn.setWordWrap(True)
        t_layout.addWidget(self.lbl_tunnel_warn)
        self.lbl_tunnel_auth = QLabel("")
        self.lbl_tunnel_auth.setObjectName("muted")
        self.lbl_tunnel_auth.setWordWrap(True)
        t_layout.addWidget(self.lbl_tunnel_auth)
        t_row = QHBoxLayout()
        self.cb_tunnel_provider = QComboBox()
        self.cb_tunnel_provider.addItems(
            ["cloudflared", "ngrok", "pinggy", "zrok"])
        self.cb_tunnel_provider.currentTextChanged.connect(
            self._on_tunnel_provider_changed)
        self.cb_tunnel_mode = QComboBox()
        self.cb_tunnel_mode.addItems(["temporary", "persistent"])
        self.ed_tunnel_name = QLineEdit()
        self.ed_tunnel_name.setPlaceholderText(
            "Tunnel/domain name (persistent mode only)")
        self.ed_tunnel_token = QLineEdit()
        self.ed_tunnel_token.setEchoMode(QLineEdit.Password)
        self.ed_tunnel_token.setPlaceholderText(
            "Pinggy Pro token (persistent Pinggy only — never saved)")
        self.btn_tunnel_save_ngrok = QPushButton("Save ngrok authtoken")
        self.btn_tunnel_save_ngrok.setToolTip(
            "Runs `ngrok config add-authtoken <token>` once. The token is "
            "stored in ngrok's own config, never by this app.")
        self.btn_tunnel_start = QPushButton("Start tunnel")
        self.btn_tunnel_stop = QPushButton("Stop tunnel")
        self.btn_tunnel_stop.setEnabled(False)
        for w in (QLabel("Provider:"), self.cb_tunnel_provider,
                  QLabel("Mode:"), self.cb_tunnel_mode,
                  self.ed_tunnel_name, self.ed_tunnel_token,
                  self.btn_tunnel_save_ngrok,
                  self.btn_tunnel_start, self.btn_tunnel_stop):
            t_row.addWidget(w)
        t_row.addStretch()
        t_layout.addLayout(t_row)
        self.lbl_tunnel_url = QLabel("No tunnel running.")
        self.lbl_tunnel_url.setObjectName("muted")
        self.lbl_tunnel_url.setWordWrap(True)
        t_layout.addWidget(self.lbl_tunnel_url)
        layout.addWidget(tunnel_box)
        self._tunnel = None
        # Watchdog: polls the tunnel process on the GUI thread and reports
        # it the moment it dies, so the label never waits forever for a
        # URL from a dead provider. Started when a tunnel starts, stopped
        # when it stops.
        self._tunnel_watchdog = QTimer(self)
        self._tunnel_watchdog.setInterval(1000)
        self._tunnel_watchdog.timeout.connect(self._check_tunnel_alive)
        self.btn_tunnel_save_ngrok.clicked.connect(self._save_ngrok_authtoken)
        self.btn_tunnel_start.clicked.connect(self._start_tunnel)
        self.btn_tunnel_stop.clicked.connect(self._stop_tunnel)
        self._refresh_tunnel_providers()
        self._refresh_tunnel_token_ui()

        # -- logs ----------------------------------------------------------
        log_box = QGroupBox("Backend logs")
        log_layout = QVBoxLayout(log_box)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        log_layout.addWidget(self.log_view)
        self.btn_log = QPushButton("Refresh logs")
        self.btn_log.clicked.connect(self.refresh_logs)
        log_layout.addWidget(self.btn_log)
        layout.addWidget(log_box)
        self._log_timer = QTimer(self)
        self._log_timer.setInterval(2000)
        self._log_timer.timeout.connect(self.refresh_logs)
        layout.addStretch()

    def showEvent(self, event):  # noqa: N802 - Qt naming
        super().showEvent(event)
        self._log_timer.start()
        # Settings are the source of truth: another page (or a reset)
        # may have changed them since this page last showed, and a
        # stale field saved again would silently overwrite that change.
        self._refresh_fields()
        self.refresh_status()

    def _refresh_fields(self) -> None:
        """Reload the configuration widgets from current settings."""
        s = self.ctx.settings
        self.ed_project.setText(s.project_root)
        self.ed_python.setText(s.backend_python)
        self.ed_host.setText(s.api_host)
        self.ed_port.setText(str(s.api_port))
        self.ed_model_root.setText(s.model_root)
        self.ed_base.setText(s.base_dir)
        self.ed_adapter.setText(s.adapter_dir)
        self.ed_sha.setText(s.adapter_sha256)
        self.cb_device.setCurrentText(s.device)
        self.ck_8bit.setChecked(s.load_in_8bit)

    def hideEvent(self, event):  # noqa: N802 - Qt naming
        super().hideEvent(event)
        self._log_timer.stop()

    # -- helpers -----------------------------------------------------------
    def _browse_dir(self, edit: QLineEdit) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose folder")
        if path:
            edit.setText(path)

    def _browse_file(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose Python")
        if path:
            edit.setText(path)

    def _set_busy(self, busy: bool) -> None:
        for btn in (self.btn_start, self.btn_stop, self.btn_restart,
                    self.btn_refresh):
            btn.setEnabled(not busy)

    def _backend_action(self, action: str) -> None:
        self._set_busy(True)
        self.status_label.setText(f"Backend status: {action}…")
        fn = {"start": self.ctx.backend.start,
              "stop": self.ctx.backend.stop,
              "restart": self.ctx.backend.restart}[action]
        worker = BackendWorker(fn, self)
        worker.finished.connect(self._backend_done)
        worker.error.connect(self._backend_error)
        worker.finished.connect(lambda *_: self._set_busy(False))
        self._worker = worker
        worker.start()

    def _backend_done(self, ok: bool, msg: str) -> None:
        self.status_label.setText(f"Backend status: {msg}")
        self.ctx.log_event("backend", msg, source="control-center")
        self.refresh_status()

    def _backend_error(self, msg: str) -> None:
        self.status_label.setText(f"Backend status: error: {msg}")
        self._set_busy(False)

    def refresh_status(self) -> None:
        def collect() -> dict:
            state = self.ctx.backend.state()
            gpu = backend_mod.gpu_info(
                backend_mod.find_backend_python(
                    self.ctx.settings,
                    backend_mod.find_project_root(self.ctx.settings))
                if backend_mod.find_project_root(self.ctx.settings)
                else None)
            return {"state": state, "gpu": gpu,
                    "sys": backend_mod.system_stats()}

        worker = InferenceWorker(collect, self)
        worker.finished.connect(self._show_status)
        worker.error.connect(
            lambda m: self.status_label.setText(f"Status error: {m}"))
        self._worker = worker
        worker.start()

    def _show_status(self, data: dict) -> None:
        state = data["state"]
        readiness = state.readiness or {}
        self.lbl_running.setText(
            f"{'Yes' if state.running else 'No'}"
            + (f" (pid {state.pid})" if state.pid else ""))
        self.lbl_readiness.setText(
            f"{readiness.get('state', 'unknown')}"
            + (f" — {readiness.get('reason')}" if readiness.get("reason") else ""))
        self.lbl_device.setText(str(readiness.get("device", "—")))
        self.lbl_quant.setText(str(readiness.get("quantization", "—")))
        load_ms = readiness.get("load_ms")
        self.lbl_load.setText(f"{load_ms} ms" if load_ms is not None else "—")
        rss = readiness.get("rss_mb")
        self.lbl_rss.setText(f"{rss} MB" if rss is not None else "—")
        gpu = data["gpu"]
        if gpu.get("available"):
            self.lbl_gpu.setText(
                f"{gpu.get('name')} via {gpu.get('source')} "
                f"(VRAM total {gpu.get('vram_total')}, "
                f"used {gpu.get('vram_used')})")
        else:
            self.lbl_gpu.setText(
                f"Unavailable ({gpu.get('detail', 'no GPU report')})")
        sysinfo = data["sys"]
        if "cpu_percent" in sysinfo:
            self.lbl_sys.setText(
                f"CPU {sysinfo['cpu_percent']}% — RAM "
                f"{sysinfo['ram_used_gb']}/{sysinfo['ram_total_gb']} GB "
                f"({sysinfo['ram_percent']}%)")
        else:
            self.lbl_sys.setText(sysinfo.get("detail", "—"))
        self.status_label.setText(
            "Backend status: " + ("running" if state.running else "not running"))

    def refresh_logs(self) -> None:
        lines = list(self.ctx.backend.log_lines)
        if lines:
            self.log_view.setPlainText("\n".join(lines[-200:]))
        else:
            # An empty view previously gave no hint that logs are only
            # tailed for backends this GUI started; a backend started
            # elsewhere logs to its own console, not here.
            self.log_view.setPlainText(
                "(No backend log lines captured — logs are tailed only "
                "while this GUI runs the backend. A backend started "
                "elsewhere logs to its own console.)")

    def save_settings(self) -> None:
        s = self.ctx.settings
        s.project_root = self.ed_project.text().strip()
        s.backend_python = self.ed_python.text().strip()
        s.api_host = self.ed_host.text().strip() or "127.0.0.1"
        try:
            port = int(self.ed_port.text().strip())
        except ValueError:
            self.lbl_cfg_status.setText("API port must be a number.")
            return
        if not 1 <= port <= 65535:
            self.lbl_cfg_status.setText(
                "API port must be between 1 and 65535.")
            return
        s.api_port = port
        s.api_base = f"http://{s.api_host}:{s.api_port}"
        s.model_root = self.ed_model_root.text().strip()
        s.base_dir = self.ed_base.text().strip()
        s.adapter_dir = self.ed_adapter.text().strip()
        s.adapter_sha256 = self.ed_sha.text().strip()
        s.device = self.cb_device.currentText()
        s.load_in_8bit = self.ck_8bit.isChecked()
        save_settings(s, self.ctx.data_dir)
        self.ctx.apply_settings()
        self.lbl_cfg_status.setText("Settings saved.")
        self.ctx.log_event("settings", "control-center settings saved",
                           source="control-center")

    def verify_artifacts(self) -> None:
        self.lbl_cfg_status.setText("Checking artifacts…")

        def check() -> dict:
            root = backend_mod.find_project_root(self.ctx.settings)
            if root is None:
                return {"error": "project root not found"}
            result = backend_mod.check_artifacts(self.ctx.settings, root)
            return {"missing": result.missing,
                    "sha": result.adapter_sha_status,
                    "base": result.base_dir,
                    "adapter": result.adapter_dir}

        worker = InferenceWorker(check, self)
        worker.finished.connect(self._show_artifacts)
        worker.error.connect(
            lambda m: self.lbl_cfg_status.setText(f"Artifact check error: {m}"))
        self._worker = worker
        worker.start()

    def _show_artifacts(self, data: dict) -> None:
        if "error" in data:
            self.lbl_cfg_status.setText(data["error"])
            return
        if data["missing"]:
            self.lbl_cfg_status.setText(
                "Missing/invalid: " + "; ".join(data["missing"]))
        else:
            self.lbl_cfg_status.setText(
                f"Artifacts OK — base: {data['base']}; adapter: "
                f"{data['adapter']} (SHA {data['sha']}). Note: the loader "
                "re-verifies the SHA at load time.")

    # -- tunnel manager ---------------------------------------------------
    def _refresh_tunnel_providers(self) -> None:
        lines = []
        for st in detect_providers():
            if st.installed:
                lines.append(f"{st.name}: installed"
                             + (f" ({st.version})" if st.version else ""))
            else:
                lines.append(
                    f"{st.name}: NOT installed — official download: "
                    f"{OFFICIAL_DOWNLOADS[st.name]}")
        self.lbl_tunnel_providers.setText(" | ".join(lines))
        self._refresh_tunnel_auth_note()

    def _refresh_tunnel_auth_note(self) -> None:
        provider = self.cb_tunnel_provider.currentText()
        self.lbl_tunnel_auth.setText(
            PROVIDER_AUTH.get(provider, ""))

    def _on_tunnel_provider_changed(self) -> None:
        self._refresh_tunnel_auth_note()
        self._refresh_tunnel_token_ui()

    def _refresh_tunnel_token_ui(self) -> None:
        """Label the token field for the selected provider, so a pasted
        token is never silently ignored.

        The token field means something different per provider: for
        ngrok it is the authtoken to save (via the Save button, into
        ngrok's own config); for Pinggy Pro it is the SSH username for
        that one tunnel; for Cloudflare/zrok there is no token field
        at all — their setup happens once outside this app.
        """
        provider = self.cb_tunnel_provider.currentText()
        self.btn_tunnel_save_ngrok.setVisible(provider == "ngrok")
        if provider == "ngrok":
            self.ed_tunnel_token.setPlaceholderText(
                "ngrok authtoken — click 'Save ngrok authtoken' first "
                "(stored in ngrok's config, not by this app)")
            self.ed_tunnel_token.setEnabled(True)
        elif provider == "pinggy":
            self.ed_tunnel_token.setPlaceholderText(
                "Pinggy Pro token (persistent Pinggy only — never saved)")
            self.ed_tunnel_token.setEnabled(True)
        elif provider == "cloudflared":
            self.ed_tunnel_token.setPlaceholderText(
                "No token field for Cloudflare (run "
                "`cloudflared tunnel login` once)")
            self.ed_tunnel_token.setEnabled(False)
        else:  # zrok
            self.ed_tunnel_token.setPlaceholderText(
                "No token field for zrok (run `zrok enable <token>` once)")
            self.ed_tunnel_token.setEnabled(False)

    def _save_ngrok_authtoken(self) -> None:
        token = self.ed_tunnel_token.text().strip()
        if not token:
            self.lbl_tunnel_url.setText(
                "Paste your ngrok authtoken in the token field first, "
                "then click 'Save ngrok authtoken'.")
            return
        try:
            saved = save_ngrok_authtoken(token)
        except Exception as exc:
            self.lbl_tunnel_url.setText(
                f"Could not save the ngrok authtoken: {exc}")
            return
        # The token now lives in ngrok's own config, never in this app.
        self.ed_tunnel_token.clear()
        self.lbl_tunnel_url.setText(
            "ngrok authtoken saved"
            + (f" ({saved})" if saved else "")
            + ". Start the tunnel with the token field empty.")

    def _check_tunnel_alive(self) -> None:
        """Watchdog (GUI thread): if the tunnel process died, say so.

        The provider only gets ~1s to fail fast in start_tunnel; a
        later death (e.g. ngrok failing auth) used to leave the label
        stuck on "Waiting for the provider to report its public URL…"
        forever. The tunnel module records the exit code and last
        output lines in Tunnel.failure_reason; this reads it.
        """
        tunnel = self._tunnel
        if tunnel is None:
            self._tunnel_watchdog.stop()
            return
        if tunnel.running:
            return
        self._tunnel_watchdog.stop()
        self._tunnel = None
        self.btn_tunnel_stop.setEnabled(False)
        self.btn_tunnel_start.setEnabled(True)
        if tunnel.public_url:
            self.lbl_tunnel_url.setText(
                f"Tunnel stopped — the public URL {tunnel.public_url} no "
                "longer works (the tunnel process exited).")
        elif tunnel.failure_reason:
            self.lbl_tunnel_url.setText(
                f"Tunnel stopped: {tunnel.failure_reason}")
        else:
            self.lbl_tunnel_url.setText(
                f"Tunnel stopped (provider: {tunnel.provider}, mode: "
                f"{tunnel.mode}). The tunnel process exited without "
                "reporting a public URL.")

    def _start_tunnel(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        if self._tunnel is not None and self._tunnel.running:
            self.lbl_tunnel_url.setText("A tunnel is already running.")
            return
        provider = self.cb_tunnel_provider.currentText()
        mode = self.cb_tunnel_mode.currentText()
        name = self.ed_tunnel_name.text().strip()
        token = self.ed_tunnel_token.text().strip()
        if provider == "ngrok" and token:
            # The token field is never passed to ngrok on start — ngrok
            # only reads its own saved config. Refuse rather than
            # silently ignore the pasted token (the trap that left a
            # tunnel stuck on "Waiting…" with no error).
            self.lbl_tunnel_url.setText(
                "That token is not used for ngrok tunnels. Click 'Save "
                "ngrok authtoken' to save it to ngrok's own config "
                "(once), then start the tunnel with the field empty.")
            return
        if mode == "persistent" and not name and provider != "pinggy":
            self.lbl_tunnel_url.setText(
                "Persistent mode needs a tunnel/domain name. For Cloudflare, "
                "create one first with `cloudflared tunnel create <name>`; "
                "for ngrok, enter a reserved domain; for zrok, enter a "
                "reserved share token.")
            return
        if provider == "pinggy" and mode == "persistent" and not token:
            self.lbl_tunnel_url.setText(
                "Pinggy persistent mode needs your Pinggy Pro token "
                "(paste it in the token field — it is never saved). "
                "For no-token sharing use temporary mode.")
            return
        answer = QMessageBox.question(
            self, "Start public tunnel?",
            "This makes the local website reachable from the internet via "
            f"{provider} ({mode}). Confirm you checked: authentication is "
            "on, no default accounts, admin routes require admin, debug is "
            "off, and no secrets are in the repo.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.lbl_tunnel_url.setText("Starting tunnel…")
        self.btn_tunnel_start.setEnabled(False)
        try:
            tunnel = start_tunnel(
                provider, mode, self.ctx.settings.api_base,
                tunnel_name=name, token=token,
                on_url=lambda url: self.lbl_tunnel_url.setText(
                    f"Public URL: {url}  (provider: {provider}, mode: {mode})"))
        except Exception as exc:
            self.lbl_tunnel_url.setText(f"Tunnel failed to start: {exc}")
            self.btn_tunnel_start.setEnabled(True)
            return
        self._tunnel = tunnel
        # Clear the token field once the tunnel is running: it is held
        # only by the running process, never stored in the app.
        self.ed_tunnel_token.clear()
        self.btn_tunnel_stop.setEnabled(True)
        # Watch the process: if it dies later without a URL, the
        # watchdog reports the exit instead of waiting forever.
        self._tunnel_watchdog.start()
        if tunnel.public_url:
            self.lbl_tunnel_url.setText(
                f"Public URL: {tunnel.public_url}  (provider: {provider}, "
                f"mode: {mode})")
        else:
            self.lbl_tunnel_url.setText(
                f"Tunnel running (provider: {provider}, mode: {mode}, "
                f"pid {tunnel.pid}). Waiting for the provider to report "
                "its public URL…")

    def _stop_tunnel(self) -> None:
        self._tunnel_watchdog.stop()
        if self._tunnel is not None:
            try:
                self._tunnel.stop()
            except Exception:
                pass
            self._tunnel = None
        self.btn_tunnel_stop.setEnabled(False)
        self.btn_tunnel_start.setEnabled(True)
        self.lbl_tunnel_url.setText("No tunnel running.")
