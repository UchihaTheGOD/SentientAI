"""Tool 4 — User Management (administrators only).

All actions go through the admin-only JSON API; the backend enforces
authorization, the last-admin guard, and self-lockout guards. This
page never displays password hashes, token versions, or session
material, and never simulates a successful operation: a failed
request shows the backend's error.
"""

from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox,
                               QFormLayout, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from ..client import AdminRequiredError
from .context import AppContext
from .dialogs import ask_text, confirm


class CreateUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create user")
        layout = QFormLayout(self)
        self.ed_user = QLineEdit()
        self.ed_email = QLineEdit()
        self.ed_pass = QLineEdit()
        self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_pass2 = QLineEdit()
        self.ed_pass2.setEchoMode(QLineEdit.Password)
        self.cb_role = QComboBox()
        self.cb_role.addItems(["user", "admin"])
        layout.addRow("Username:", self.ed_user)
        layout.addRow("Email:", self.ed_email)
        layout.addRow("Password:", self.ed_pass)
        layout.addRow("Confirm password:", self.ed_pass2)
        layout.addRow("Role:", self.cb_role)
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self):
        return (self.ed_user.text().strip(), self.ed_email.text().strip(),
                self.ed_pass.text(), self.ed_pass2.text(),
                self.cb_role.currentText())


class UserManagementPage(QWidget):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self._users: list[dict] = []
        layout = QVBoxLayout(self)

        heading = QLabel("User Management")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        layout.addWidget(QLabel(
            "Administrators only. All actions are enforced by the "
            "backend; a 403 here means the signed-in account is not an "
            "administrator. Passwords are never displayed or logged."))

        # -- admin sign-in ------------------------------------------------
        sign_row = QHBoxLayout()
        self.ed_admin_user = QLineEdit()
        self.ed_admin_user.setPlaceholderText("Admin username")
        self.ed_admin_pass = QLineEdit()
        self.ed_admin_pass.setEchoMode(QLineEdit.Password)
        self.ed_admin_pass.setPlaceholderText(
            "Admin password (memory only, never saved)")
        self.btn_admin_login = QPushButton("Sign in as administrator")
        self.lbl_admin = QLabel("Not signed in as administrator.")
        self.lbl_admin.setObjectName("muted")
        sign_row.addWidget(self.ed_admin_user)
        sign_row.addWidget(self.ed_admin_pass)
        sign_row.addWidget(self.btn_admin_login)
        sign_row.addWidget(self.lbl_admin, 1)
        layout.addLayout(sign_row)
        self.btn_admin_login.clicked.connect(self._admin_login)

        # -- stats ----------------------------------------------------------
        stats_row = QHBoxLayout()
        self.lbl_total = QLabel("Total: —")
        self.lbl_active = QLabel("Active: —")
        self.lbl_susp = QLabel("Suspended: —")
        self.lbl_admins = QLabel("Admins: —")
        for lbl in (self.lbl_total, self.lbl_active, self.lbl_susp,
                    self.lbl_admins):
            stats_row.addWidget(lbl)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # -- filters ----------------------------------------------------------
        filt = QHBoxLayout()
        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("Search username or email…")
        self.cb_role = QComboBox()
        self.cb_role.addItems(["All roles", "user", "admin"])
        self.cb_status = QComboBox()
        self.cb_status.addItems(["All statuses", "active", "suspended",
                                 "inactive"])
        self.cb_sort = QComboBox()
        self.cb_sort.addItems(["recent", "username", "role"])
        self.btn_refresh = QPushButton("Refresh")
        filt.addWidget(self.ed_search, 1)
        filt.addWidget(self.cb_role)
        filt.addWidget(self.cb_status)
        filt.addWidget(self.cb_sort)
        filt.addWidget(self.btn_refresh)
        layout.addLayout(filt)
        self.btn_refresh.clicked.connect(self.refresh)
        self.ed_search.textChanged.connect(self.refresh)
        self.cb_role.currentTextChanged.connect(self.refresh)
        self.cb_status.currentTextChanged.connect(self.refresh)
        self.cb_sort.currentTextChanged.connect(self.refresh)

        # -- table ------------------------------------------------------------
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Username", "Email", "Role", "Active", "Suspended"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(
            self.table.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        layout.addWidget(self.table, 1)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(180)
        layout.addWidget(self.detail)

        # -- actions -----------------------------------------------------------
        act = QHBoxLayout()
        self.btn_create = QPushButton("Create user…")
        self.btn_promote = QPushButton("Promote to admin")
        self.btn_demote = QPushButton("Demote to user")
        self.btn_activate = QPushButton("Activate")
        self.btn_deactivate = QPushButton("Deactivate")
        self.btn_suspend = QPushButton("Suspend…")
        self.btn_unsuspend = QPushButton("Unsuspend")
        self.btn_reset = QPushButton("Initiate password reset")
        self.btn_audit = QPushButton("Show audit events")
        for btn in (self.btn_create, self.btn_promote, self.btn_demote,
                    self.btn_activate, self.btn_deactivate, self.btn_suspend,
                    self.btn_unsuspend, self.btn_reset, self.btn_audit):
            act.addWidget(btn)
        act.addStretch()
        layout.addLayout(act)
        self.status_label = QLabel("")
        self.status_label.setObjectName("muted")
        layout.addWidget(self.status_label)
        self.btn_create.clicked.connect(self._create_user)
        self.btn_promote.clicked.connect(
            lambda: self._role_action("admin", "Promote"))
        self.btn_demote.clicked.connect(
            lambda: self._role_action("user", "Demote"))
        self.btn_activate.clicked.connect(
            lambda: self._active_action(True))
        self.btn_deactivate.clicked.connect(
            lambda: self._active_action(False))
        self.btn_suspend.clicked.connect(self._suspend_action)
        self.btn_unsuspend.clicked.connect(
            lambda: self._unsuspend_action())
        self.btn_reset.clicked.connect(self._reset_action)
        self.btn_audit.clicked.connect(self._audit_action)
        self._set_actions_enabled(False)

    # -- helpers ---------------------------------------------------------------
    def _set_actions_enabled(self, enabled: bool) -> None:
        for btn in (self.btn_create, self.btn_promote, self.btn_demote,
                    self.btn_activate, self.btn_deactivate, self.btn_suspend,
                    self.btn_unsuspend, self.btn_reset, self.btn_audit,
                    self.btn_refresh):
            btn.setEnabled(enabled)

    def _admin_login(self) -> None:
        username = self.ed_admin_user.text().strip()
        password = self.ed_admin_pass.text()
        if not username or not password:
            self.lbl_admin.setText("Enter an admin username and password.")
            return
        client = self.ctx.admin_client
        try:
            ok, msg = client.login(username, password)
        except Exception as exc:
            self.lbl_admin.setText(f"Admin sign-in failed: {exc}")
            return
        if not ok:
            self.lbl_admin.setText(f"Admin sign-in failed: {msg}")
            return
        # Prove admin rights with a real call before enabling actions.
        try:
            client.list_users(per_page=1)
        except AdminRequiredError:
            self.lbl_admin.setText(
                "Signed in, but this account is not an administrator (403).")
            return
        except Exception as exc:
            self.lbl_admin.setText(f"Admin check failed: {exc}")
            return
        self.lbl_admin.setText(f"Signed in as administrator {username}.")
        self._set_actions_enabled(True)
        self.refresh()

    def _selected(self) -> dict | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows or not self._users:
            return None
        idx = rows[0].row()
        return self._users[idx] if idx < len(self._users) else None

    def _show_detail(self) -> None:
        user = self._selected()
        if user is None:
            self.detail.setPlainText("")
            return
        self.detail.setPlainText(
            f"ID: {user['id']}\nUsername: {user['username']}\n"
            f"Email: {user['email']}\nRole: {user['role']}\n"
            f"Active: {user['is_active']} / Suspended: {user['is_suspended']}\n"
            f"Can sign in: {user['can_sign_in']}\n"
            f"Created: {user['created_at']}\n"
            "Note: password hashes, token versions, and session material "
            "are never returned by the API and never shown here.")

    def _call(self, fn, success: str):
        """Run an admin call, showing the backend's error on failure."""
        try:
            result = fn()
        except AdminRequiredError:
            self.status_label.setText(
                "Administrative access denied (403). Sign in as an "
                "administrator.")
            return None
        except Exception as exc:
            self.status_label.setText(f"Request failed: {exc}")
            return None
        self.status_label.setText(success)
        return result

    # -- data ----------------------------------------------------------------------
    def refresh(self) -> None:
        role = self.cb_role.currentText()
        status = self.cb_status.currentText()
        data = self._call(
            lambda: self.ctx.admin_client.list_users(
                q=self.ed_search.text().strip(),
                role="" if role == "All roles" else role,
                status="" if status == "All statuses" else status,
                sort=self.cb_sort.currentText()),
            "User list refreshed.")
        if data is None:
            return
        self._users = data["users"]
        self.lbl_total.setText(f"Total: {data['total']}")
        self.lbl_active.setText(f"Active: {data['active']}")
        self.lbl_susp.setText(f"Suspended: {data['suspended']}")
        self.lbl_admins.setText(f"Admins: {data['admins']}")
        self.table.setRowCount(len(self._users))
        for row, u in enumerate(self._users):
            self.table.setItem(row, 0, QTableWidgetItem(str(u["id"])))
            self.table.setItem(row, 1, QTableWidgetItem(u["username"]))
            self.table.setItem(row, 2, QTableWidgetItem(u["email"]))
            self.table.setItem(row, 3, QTableWidgetItem(u["role"]))
            self.table.setItem(row, 4, QTableWidgetItem(str(u["is_active"])))
            self.table.setItem(row, 5, QTableWidgetItem(str(u["is_suspended"])))

    # -- actions ---------------------------------------------------------------------
    def _create_user(self) -> None:
        dialog = CreateUserDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        username, email, password, password2, role = dialog.values()
        if password != password2:
            self.status_label.setText("Passwords do not match.")
            return
        result = self._call(
            lambda: self.ctx.admin_client.create_user(
                username, email, password, role),
            f"User {username} created.")
        if result is not None:
            self.ctx.log_event("user-admin", f"created user {username}",
                               source="user-management")
            self.refresh()

    def _role_action(self, role: str, verb: str) -> None:
        user = self._selected()
        if user is None:
            self.status_label.setText("Select a user first.")
            return
        if not confirm(self, f"{verb} user",
                       f"{verb} {user['username']} to role '{role}'?"):
            return
        result = self._call(
            lambda: self.ctx.admin_client.set_user_role(user["id"], role),
            f"{user['username']} is now '{role}'.")
        if result is not None:
            self.ctx.log_event("user-admin",
                               f"{verb.lower()} {user['username']} to {role}",
                               source="user-management")
            self.refresh()

    def _active_action(self, active: bool) -> None:
        user = self._selected()
        if user is None:
            self.status_label.setText("Select a user first.")
            return
        verb = "Activate" if active else "Deactivate"
        if not confirm(self, verb, f"{verb} account {user['username']}?"):
            return
        result = self._call(
            lambda: self.ctx.admin_client.set_user_active(user["id"], active),
            f"{user['username']} active={active}.")
        if result is not None:
            self.ctx.log_event("user-admin",
                               f"{verb.lower()} {user['username']}",
                               source="user-management")
            self.refresh()

    def _suspend_action(self) -> None:
        user = self._selected()
        if user is None:
            self.status_label.setText("Select a user first.")
            return
        reason = ask_text(self, "Suspend user",
                          f"Reason for suspending {user['username']} (optional):")
        if reason is None:
            return
        result = self._call(
            lambda: self.ctx.admin_client.set_user_suspended(
                user["id"], True, reason or None),
            f"{user['username']} suspended.")
        if result is not None:
            self.ctx.log_event("user-admin",
                               f"suspended {user['username']}",
                               source="user-management")
            self.refresh()

    def _unsuspend_action(self) -> None:
        user = self._selected()
        if user is None:
            self.status_label.setText("Select a user first.")
            return
        if not confirm(self, "Unsuspend",
                       f"Unsuspend account {user['username']}?"):
            return
        result = self._call(
            lambda: self.ctx.admin_client.set_user_suspended(user["id"], False),
            f"{user['username']} unsuspended.")
        if result is not None:
            self.refresh()

    def _reset_action(self) -> None:
        user = self._selected()
        if user is None:
            self.status_label.setText("Select a user first.")
            return
        if not confirm(self, "Password reset",
                       f"Initiate the existing password-reset flow for "
                       f"{user['username']} ({user['email']})? The user "
                       "receives a reset link if email delivery is "
                       "configured; no token is shown here."):
            return
        result = self._call(
            lambda: self.ctx.admin_client.initiate_password_reset(user["id"]),
            "Password reset initiated (generic response; see backend "
            "email configuration for delivery).")
        if result is not None:
            self.ctx.log_event("user-admin",
                               f"password reset initiated for {user['username']}",
                               source="user-management")

    def _audit_action(self) -> None:
        user = self._selected()
        data = self._call(
            lambda: self.ctx.admin_client.audit_events(
                limit=50,
                user_id=user["id"] if user else None),
            "Audit events loaded.")
        if data is None:
            return
        lines = []
        for e in data["events"]:
            lines.append(
                f"{e['created_at']} {e['event_type']} "
                f"actor={e['actor_label']} target={e['target_type']}:"
                f"{e['target_id']} {e['detail'] or ''}")
        self.detail.setPlainText("\n".join(lines) if lines else
                                 "No audit events found.")
