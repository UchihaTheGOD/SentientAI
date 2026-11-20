# PyInstaller spec for the CyberLLMv1 Security Lab (Windows).
#
# Build from the SentientAI project root with:
#   pyinstaller --noconfirm security_lab/packaging/security-lab.spec
# or simply run security_lab/packaging/build_windows.bat.
#
# The exe bundles the GUI (PySide6) + requests + reportlab only.
# It does NOT bundle the SentientAI backend, its dependencies, or any
# model weights: the backend runs from the user's project Python/venv
# and the weights from the user's model directory (see BUILD_GUIDE.md).
# That is deliberate — weights are multi-GB and backend code is the
# user's own project, not something to freeze into an exe.

from pathlib import Path

repo_root = Path(SPECPATH).parent.parent
entry = repo_root / "security_lab" / "__main__.py"

block_cipher = None

a = Analysis(
    [str(entry)],
    pathex=[str(repo_root)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="CyberLLMv1-Security-Lab",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI app: no console window on double-click
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
