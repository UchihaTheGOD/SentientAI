"""Model download manager for the CyberLLMv1 Security Lab.

Downloads the CyberLLM base model and the pilot v8 adapter into the
configured model directory, with progress reporting, cancellation,
resume, disk-space checks, and SHA-256 verification.

This module has NO PySide6 dependency so it can be unit-tested without
a GUI. The GUI drives it from a QThread worker (see gui/workers.py).

Sources:
- Base model (Qwen/Qwen3-1.7B, ~4.06 GB): Hugging Face, anonymous,
  resumable via huggingface_hub.snapshot_download. No credentials needed.
- Adapter (pilot v8, ~82 MB): two sources, in priority order:
  1. A public HTTPS URL (Settings.adapter_source_url). When set, each
     adapter file is downloaded over plain HTTPS with Range-resume and
     no credentials. This is the preferred source once the artifact is
     publicly hosted (Kaggle public dataset, HF repo, or GitHub Release).
  2. Kaggle CLI (Settings.adapter_source_url empty): `kaggle datasets
     download` per file, which needs ~/.kaggle/kaggle.json credentials.
     Kept as the fallback while the artifact is still private.

Safety rules:
- Never mark an unverified adapter as ready: the SHA-256 check is fatal
  on mismatch, and a missing/empty expected SHA refuses to verify.
- Never overwrite a file that already validates (same size + SHA for the
  adapter; HF snapshot_download resumes/skips for the base).
- Downloads go into the configured base_dir / adapter_dir only — never
  into the default HF cache (~/.cache/huggingface).
- A download that is cancelled or fails leaves partial files in place;
  re-running resumes them (HF) or skips the files that already exist
  (adapter), so nothing has to start from zero.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# Known sizes (verified 2026-11-20). Base: Qwen/Qwen3-1.7B index total.
BASE_SIZE_BYTES = 4_063_479_808
# Adapter: adapter_model.safetensors 69,782,384 + tokenizer/config files.
ADAPTER_SIZE_BYTES = 82_000_000
# Free-space margin on top of the download size.
DISK_MARGIN_BYTES = 500_000_000

# Kaggle adapter files: (kaggle filename, canonical filename in adapter_dir).
ADAPTER_FILES = [
    ("adapter_17b_datav32_adapter_config.json", "adapter_config.json"),
    ("adapter_17b_datav32_adapter_model.safetensors", "adapter_model.safetensors"),
    ("adapter_17b_datav32_chat_template.jinja", "chat_template.jinja"),
    ("adapter_17b_datav32_tokenizer.json", "tokenizer.json"),
    ("adapter_17b_datav32_tokenizer_config.json", "tokenizer_config.json"),
]

KAGGLE_DATASET = "uchihamadarum/cyber-llm-artifacts"

# Model states (also used by the GUI status label).
STATE_MISSING = "Missing"
STATE_INCOMPLETE = "Incomplete"
STATE_DOWNLOADED = "Downloaded"
STATE_VERIFIED = "Verified"
STATE_CORRUPTED = "Corrupted"
STATE_FAILED = "Failed"

ProgressCallback = Callable[[int, int, str], None]  # downloaded, total, message


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dir_size(path: Path) -> int:
    """Total bytes of all files under a directory (0 if missing)."""
    total = 0
    if not path.is_dir():
        return 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            pass
    return total


def check_disk_space(target_dir: Path, needed_bytes: int) -> tuple[bool, int]:
    """Return (enough_space, free_bytes) for a download into target_dir."""
    target_dir.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(target_dir).free
    return free >= needed_bytes + DISK_MARGIN_BYTES, free


def verify_adapter(adapter_dir: Path, expected_sha256: str) -> tuple[bool, str, str]:
    """Verify the adapter weights file against the expected SHA-256.

    Returns (ok, actual_sha, message). Fails closed: an empty expected
    SHA, a missing file, or a mismatch all return ok=False.
    """
    weights = adapter_dir / "adapter_model.safetensors"
    if not expected_sha256:
        return False, "", "no expected adapter SHA-256 configured; refusing to verify"
    if not weights.is_file():
        return False, "", f"adapter weights missing: {weights}"
    actual = sha256_file(weights)
    if actual.lower() != expected_sha256.strip().lower():
        return False, actual, (
            f"adapter SHA-256 mismatch: expected {expected_sha256[:16]}…, "
            f"got {actual[:16]}… — refusing to treat this as pilot v8"
        )
    return True, actual, f"adapter SHA-256 matches pilot v8 ({actual[:16]}…)"


def model_state(base_dir: Path, adapter_dir: Path,
                expected_sha256: str) -> str:
    """Best-effort state of the model on disk (no network, no loading)."""
    base_ok = (base_dir / "config.json").is_file() and bool(
        list(base_dir.glob("model*.safetensors"))
        or list(base_dir.glob("*.safetensors"))
    )
    adapter_file = adapter_dir / "adapter_model.safetensors"
    adapter_present = adapter_file.is_file()
    if not base_ok and not adapter_present:
        return STATE_MISSING
    if not base_ok or not adapter_present:
        return STATE_INCOMPLETE
    ok, _, _ = verify_adapter(adapter_dir, expected_sha256)
    return STATE_VERIFIED if ok else STATE_CORRUPTED


@dataclass
class DownloadResult:
    ok: bool
    message: str
    base_downloaded: bool = False
    adapter_downloaded: bool = False
    adapter_verified: bool = False


class DownloadCancelled(Exception):
    """Raised when the user cancels a download."""


def _check_cancel(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise DownloadCancelled("download cancelled by user")


def download_base(base_dir: Path, base_model_id: str, base_revision: str,
                  progress: Optional[ProgressCallback] = None,
                  cancel: Optional[threading.Event] = None) -> None:
    """Download the base model into base_dir via huggingface_hub.

    Resumable: snapshot_download skips files that are already complete.
    Progress is reported by polling the directory size, because
    snapshot_download does not expose a byte callback.
    """
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise RuntimeError(
            "huggingface_hub is not installed; the desktop app needs it "
            "for model downloads (pip install huggingface_hub)"
        ) from exc

    base_dir.mkdir(parents=True, exist_ok=True)
    _check_cancel(cancel)

    # Poll the directory size in a background thread for progress.
    stop_poll = threading.Event()
    total = BASE_SIZE_BYTES
    downloaded = {"bytes": dir_size(base_dir)}

    def _poll() -> None:
        while not stop_poll.wait(0.5):
            downloaded["bytes"] = dir_size(base_dir)
            if progress is not None:
                progress(downloaded["bytes"], total,
                         "Downloading base model (Qwen3-1.7B)…")

    poller = threading.Thread(target=_poll, daemon=True)
    poller.start()
    try:
        snapshot_download(
            repo_id=base_model_id,
            revision=base_revision,
            local_dir=str(base_dir),
            local_dir_use_symlinks=False,
        )
    finally:
        stop_poll.set()
        poller.join(timeout=2)
    _check_cancel(cancel)
    if progress is not None:
        progress(dir_size(base_dir), total, "Base model downloaded.")


def _download_url_resumable(url: str, target: Path,
                            progress: Optional[ProgressCallback],
                            cancel: Optional[threading.Event],
                            total_hint: int = 0) -> None:
    """Download one file over HTTPS with Range-resume and progress."""
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = target.stat().st_size if target.is_file() else 0
    req = urllib.request.Request(url)
    if existing:
        req.add_header("Range", f"bytes={existing}-")
    with urllib.request.urlopen(req, timeout=60) as resp:
        # A server that ignores Range returns 200 and the full file;
        # restart from zero in that case rather than appending garbage.
        if resp.status == 200 and existing:
            existing = 0
            mode = "wb"
        else:
            mode = "ab" if existing else "wb"
        total = total_hint
        content_length = resp.headers.get("Content-Length")
        if content_length:
            total = existing + int(content_length)
        downloaded = existing
        with target.open(mode) as out:
            while True:
                _check_cancel(cancel)
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                downloaded += len(chunk)
                if progress is not None and total:
                    progress(downloaded, total,
                             f"Downloading {target.name}…")
    _check_cancel(cancel)


def download_adapter(adapter_dir: Path, expected_sha256: str,
                     source_url: str = "",
                     progress: Optional[ProgressCallback] = None,
                     cancel: Optional[threading.Event] = None) -> None:
    """Download the pilot v8 adapter into adapter_dir.

    If source_url is set, each file is fetched over plain HTTPS from
    <source_url>/<canonical_filename> (public source, no credentials).
    The public source hosts the files under their canonical names, e.g.
    https://huggingface.co/Uchiha80971/CyberLLM-v8/resolve/main/adapter_model.safetensors.
    Otherwise the Kaggle CLI is used (needs ~/.kaggle/kaggle.json).
    Files that already exist are skipped; the SHA check runs after.
    """
    adapter_dir.mkdir(parents=True, exist_ok=True)
    _check_cancel(cancel)
    if source_url:
        base_url = source_url.rstrip("/")
        for kaggle_name, canonical in ADAPTER_FILES:
            target = adapter_dir / canonical
            if target.is_file():
                continue
            _download_url_resumable(
                f"{base_url}/{canonical}", target, progress, cancel,
                total_hint=ADAPTER_SIZE_BYTES,
            )
    else:
        for kaggle_name, canonical in ADAPTER_FILES:
            target = adapter_dir / canonical
            if target.is_file():
                continue
            result = subprocess.run(
                ["kaggle", "datasets", "download",
                 "-d", KAGGLE_DATASET, "-f", kaggle_name,
                 "-p", str(adapter_dir)],
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Kaggle download failed for {kaggle_name} "
                    f"(exit {result.returncode}). The adapter needs Kaggle "
                    "credentials (~/.kaggle/kaggle.json) unless a public "
                    "download URL is configured in Settings."
                )
            downloaded = adapter_dir / kaggle_name
            if downloaded.is_file() and downloaded != target:
                downloaded.rename(target)
            _check_cancel(cancel)
    # Verify: fatal on mismatch, missing file, or empty expected SHA.
    ok, _, message = verify_adapter(adapter_dir, expected_sha256)
    if not ok:
        raise RuntimeError(message)
    if progress is not None:
        progress(ADAPTER_SIZE_BYTES, ADAPTER_SIZE_BYTES, message)


def download_all(base_dir: Path, adapter_dir: Path,
                 base_model_id: str, base_revision: str,
                 expected_sha256: str, source_url: str = "",
                 progress: Optional[ProgressCallback] = None,
                 cancel: Optional[threading.Event] = None) -> DownloadResult:
    """Download base + adapter, verify the adapter, return a result.

    Skips the parts that are already present and verified. Raises
    DownloadCancelled on cancel, RuntimeError on failure.
    """
    # Disk-space check first: base + adapter + margin.
    need_base = not (base_dir / "config.json").is_file()
    need_adapter = not (adapter_dir / "adapter_model.safetensors").is_file()
    needed = (BASE_SIZE_BYTES if need_base else 0) + (
        ADAPTER_SIZE_BYTES if need_adapter else 0)
    if needed:
        ok_space, free = check_disk_space(
            base_dir.parent if base_dir.parent.is_dir() else base_dir, needed)
        if not ok_space:
            raise RuntimeError(
                f"Not enough disk space: need ~{needed / 1e9:.1f} GB plus "
                f"a {DISK_MARGIN_BYTES / 1e9:.1f} GB margin, but only "
                f"{free / 1e9:.1f} GB free."
            )
    base_done = False
    adapter_done = False
    if need_base:
        download_base(base_dir, base_model_id, base_revision, progress, cancel)
        base_done = True
    else:
        base_done = True
    if need_adapter:
        download_adapter(adapter_dir, expected_sha256, source_url,
                         progress, cancel)
        adapter_done = True
    else:
        # Adapter already present: still verify it before calling it done.
        ok, _, message = verify_adapter(adapter_dir, expected_sha256)
        if not ok:
            raise RuntimeError(message)
        adapter_done = True
    return DownloadResult(
        ok=True,
        message="CyberLLM model ready: base + pilot v8 adapter verified.",
        base_downloaded=base_done,
        adapter_downloaded=adapter_done,
        adapter_verified=True,
    )
