#!/usr/bin/env python3
"""Import (or update) the local MITRE ATT&CK Enterprise dataset.

Source: github.com/mitre-attack/attack-stix-data (STIX 2.1 bundles).
Usage:
    python scripts/import_mitre.py [--version 20.0] [--from-file path.json]
    python scripts/import_mitre.py --version 21.0   # future update

Safety rules (from the mission spec):
- The bundle is stored at a VERSIONED filename, never overwritten in
  place: a new version gets its own file, so the previous dataset is
  preserved even if the update fails midway.
- The manifest pointer is updated ONLY after the new bundle parses and
  its x-mitre-collection version matches the requested version.
- A re-download of an already-installed version with a DIFFERENT hash
  aborts instead of silently replacing data.
- No live MITRE call is ever made per event; this script is the only
  network touchpoint, run by an operator at import/update time.
- LICENSE.txt is bundled verbatim next to the dataset (MITRE Terms of
  Use require any copy to reproduce the copyright designation and the
  license itself). Attribution shown in the app:
  "© 2026 The MITRE Corporation. This work is reproduced and distributed
  with the permission of The MITRE Corporation."
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA_DIR = REPO / "app" / "data" / "mitre"
BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
ATTRIBUTION = ("© 2026 The MITRE Corporation. This work is reproduced and "
               "distributed with the permission of The MITRE Corporation.")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "SentientAI-mitre-import"})
    with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def _validate_bundle(path: Path, version: str) -> dict:
    """Parse + verify. Returns the collection object. Raises on failure."""
    with open(path, encoding="utf-8") as f:
        bundle = json.load(f)
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("not a STIX bundle (missing type/objects)")
    collections = [o for o in bundle["objects"] if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise ValueError(f"expected exactly 1 x-mitre-collection, found {len(collections)}")
    coll = collections[0]
    if str(coll.get("x_mitre_version")) != str(version):
        raise ValueError(
            f"collection version {coll.get('x_mitre_version')!r} != requested {version!r}")
    if len(bundle["objects"]) < 10000:
        raise ValueError(f"suspiciously small bundle: {len(bundle['objects'])} objects")
    return coll


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", default="20.0")
    ap.add_argument("--from-file", help="install a locally downloaded bundle instead of fetching")
    ap.add_argument("--data-dir", default=str(DATA_DIR))
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"enterprise-attack-{args.version}.json"
    bundle_path = data_dir / bundle_name
    manifest_path = data_dir / "manifest.json"

    existing_manifest = {}
    if manifest_path.exists():
        existing_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if args.from_file:
        import shutil
        tmp = data_dir / f".{bundle_name}.tmp"
        shutil.copyfile(args.from_file, tmp)
        coll = _validate_bundle(tmp, args.version)
        new_sha = _sha256(tmp)
        if bundle_path.exists() and _sha256(bundle_path) != new_sha:
            tmp.unlink()
            print(f"REFUSING: {bundle_name} already installed with a different hash.", file=sys.stderr)
            return 2
        tmp.replace(bundle_path)
    else:
        tmp = data_dir / f".{bundle_name}.tmp"
        _download(f"{BASE_URL}/enterprise-attack/{bundle_name}", tmp)
        try:
            coll = _validate_bundle(tmp, args.version)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        new_sha = _sha256(tmp)
        if bundle_path.exists() and _sha256(bundle_path) != new_sha:
            tmp.unlink()
            print(f"REFUSING: {bundle_name} already installed with a different hash.", file=sys.stderr)
            return 2
        tmp.replace(bundle_path)
        # LICENSE.txt bundled verbatim (small text file, tracked).
        _download(f"{BASE_URL}/LICENSE.txt", data_dir / "LICENSE.txt")

    previous = existing_manifest.get("version")
    history = existing_manifest.get("previous_versions", [])
    if previous and previous != args.version and previous not in history:
        history.append(previous)
    manifest = {
        "dataset": "enterprise-attack",
        "version": args.version,
        "bundle_file": bundle_name,
        "bundle_sha256": new_sha,
        "bundle_bytes": bundle_path.stat().st_size,
        "bundle_modified": coll.get("modified"),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "source_url": f"{BASE_URL}/enterprise-attack/{bundle_name}",
        "license_file": "LICENSE.txt",
        "license_sha256": _sha256(data_dir / "LICENSE.txt") if (data_dir / "LICENSE.txt").exists() else None,
        "attribution": ATTRIBUTION,
        "previous_versions": history,
    }
    with open(bundle_path, encoding="utf-8") as f:
        manifest["object_count"] = len(json.load(f)["objects"])
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Installed Enterprise ATT&CK {args.version}: {bundle_name} "
          f"({manifest['bundle_bytes']} bytes, sha256 {new_sha[:16]}…, "
          f"{manifest['object_count']} objects, collection modified {coll.get('modified')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
