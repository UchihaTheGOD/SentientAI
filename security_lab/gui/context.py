"""Shared application context handed to every page.

Pages never construct their own backend/client objects: they use the
ones here, so tests can substitute stubs and the GUI stays consistent
(a settings change updates the live objects, not a copy).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..backend import BackendManager
from ..cases import CaseStore
from ..client import BackendClient
from ..config import Settings, ensure_data_dirs
from ..timeline import Timeline


@dataclass
class AppContext:
    settings: Settings
    data_dir: Path
    backend: BackendManager
    client: BackendClient
    admin_client: BackendClient
    cases: CaseStore
    timeline: Timeline
    navigate: Callable[[str], None] | None = None
    dirs: dict[str, Path] = field(default_factory=dict)

    @classmethod
    def create(cls, settings: Settings,
               data_dir: Path | None = None) -> "AppContext":
        from ..config import user_data_dir

        base = data_dir or user_data_dir()
        dirs = ensure_data_dirs(base)
        backend = BackendManager(settings, base)
        client = BackendClient(settings.api_base)
        admin_client = BackendClient(settings.api_base)
        return cls(
            settings=settings, data_dir=base, backend=backend,
            client=client, admin_client=admin_client,
            cases=CaseStore(base / "cases.json"),
            timeline=Timeline(base / "timeline.jsonl"),
            dirs=dirs,
        )

    def apply_settings(self) -> None:
        """Push edited settings into the live backend/client objects."""
        self.backend.settings = self.settings
        self.client.api_base = self.settings.api_base
        self.admin_client.api_base = self.settings.api_base

    def log_event(self, event: str, detail: str = "", source: str = "") -> None:
        try:
            self.timeline.append(event, detail, source)
        except Exception:
            pass
