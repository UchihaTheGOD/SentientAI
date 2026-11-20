"""Promotion gate for a CyberLLM candidate adapter — approval + rollback.

This script NEVER trains and NEVER auto-promotes. It is a gate:

1. Check mode (default): verifies the candidate adapter SHA, the
   approval file (approver, decision="approved", evaluation report
   path) and that the evaluation report exists. Exits non-zero and
   changes nothing if any check fails.
2. Apply mode (--apply --confirm "I APPROVE"): only after check mode
   passes, backs up the current cyberLLMv1/adapter to --backup-dir,
   copies the candidate adapter files in, verifies the SHA after copy,
   and writes a promotion record (previous SHA, new SHA, approver,
   backup location) to <backup-dir>/promotion.json.
3. Rollback mode (--rollback --backup-dir DIR): restores adapter files
   from a backup made by apply mode and verifies the previous SHA.

The production model (cyberLLMv1/adapter) is preserved until an approved
replacement exists: apply mode refuses to run without a backup dir,
and rollback is the documented recovery path. If the candidate fails
its frozen-benchmark acceptance criteria, the approval file must not
say "approved" — this script does not evaluate a model itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.services.cyberllm_loader import resolve_cyberllm_paths  # noqa: E402

ADAPTER_FILES = (
    "adapter_config.json",
    "adapter_model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "chat_template.jinja",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_candidate(candidate_dir: Path, approval_path: Path) -> dict:
    if not (candidate_dir / "adapter_model.safetensors").is_file():
        raise SystemExit(f"candidate adapter weights missing: {candidate_dir}")
    if not (candidate_dir / "adapter_config.json").is_file():
        raise SystemExit(f"candidate adapter_config.json missing: {candidate_dir}")
    if not approval_path.is_file():
        raise SystemExit(f"approval file missing: {approval_path}")
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    if approval.get("decision") != "approved":
        raise SystemExit(f"approval decision is not 'approved': {approval.get('decision')}")
    if not approval.get("approver"):
        raise SystemExit("approval file has no approver")
    eval_path = approval.get("evaluation_report")
    if not eval_path or not Path(eval_path).is_file():
        raise SystemExit(f"evaluation report missing: {eval_path}")
    return {
        "candidate_sha256": sha256(candidate_dir / "adapter_model.safetensors"),
        "approver": approval["approver"],
        "evaluation_report": eval_path,
    }


def apply_candidate(candidate_dir: Path, approval: dict, backup_dir: Path) -> dict:
    paths = resolve_cyberllm_paths()
    adapter_dir = paths.adapter_dir
    backup_dir.mkdir(parents=True, exist_ok=True)
    previous_sha = None
    if (adapter_dir / "adapter_model.safetensors").is_file():
        previous_sha = sha256(adapter_dir / "adapter_model.safetensors")
        for name in ADAPTER_FILES:
            src = adapter_dir / name
            if src.is_file():
                shutil.copy2(src, backup_dir / name)
    (backup_dir / "rollback.json").write_text(
        json.dumps({"previous_sha256": previous_sha, "adapter_dir": str(adapter_dir)}, indent=2),
        encoding="utf-8",
    )
    adapter_dir.mkdir(parents=True, exist_ok=True)
    for name in ADAPTER_FILES:
        src = candidate_dir / name
        if src.is_file():
            shutil.copy2(src, adapter_dir / name)
    new_sha = sha256(adapter_dir / "adapter_model.safetensors")
    if new_sha != approval["candidate_sha256"]:
        raise SystemExit(f"SHA mismatch after copy: {new_sha} != {approval['candidate_sha256']}")
    record = {
        "previous_sha256": previous_sha,
        "new_sha256": new_sha,
        "approver": approval["approver"],
        "evaluation_report": approval["evaluation_report"],
        "backup_dir": str(backup_dir),
    }
    # Promotion record lives with the backup, not in the repo tree, so a
    # test or dry run can never create stray files in the project.
    (backup_dir / "promotion.json").write_text(
        json.dumps(record, indent=2, sort_keys=True), encoding="utf-8"
    )
    return record


def rollback(backup_dir: Path) -> dict:
    info = json.loads((backup_dir / "rollback.json").read_text(encoding="utf-8"))
    adapter_dir = Path(info["adapter_dir"])
    for name in ADAPTER_FILES:
        src = backup_dir / name
        if src.is_file():
            shutil.copy2(src, adapter_dir / name)
    restored = sha256(adapter_dir / "adapter_model.safetensors")
    if info.get("previous_sha256") and restored != info["previous_sha256"]:
        raise SystemExit(f"rollback SHA mismatch: {restored} != {info['previous_sha256']}")
    return {"restored_sha256": restored, "adapter_dir": str(adapter_dir)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", default=None)
    parser.add_argument("--approval", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup-dir", default=None)
    parser.add_argument("--confirm", default=None)
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args(argv)
    if args.rollback:
        if not args.backup_dir:
            print("--rollback requires --backup-dir")
            return 2
        print(json.dumps(rollback(Path(args.backup_dir)), indent=2))
        return 0
    if not args.candidate_dir or not args.approval:
        print("--candidate-dir and --approval are required")
        return 2
    approval = check_candidate(Path(args.candidate_dir), Path(args.approval))
    print(f"CHECK OK: candidate SHA {approval['candidate_sha256'][:16]}… approver {approval['approver']}")
    if not args.apply:
        print("Not applied: rerun with --apply --backup-dir DIR --confirm 'I APPROVE' to promote.")
        return 0
    if args.confirm != "I APPROVE" or not args.backup_dir:
        print("--apply requires --backup-dir and --confirm 'I APPROVE'")
        return 2
    record = apply_candidate(Path(args.candidate_dir), approval, Path(args.backup_dir))
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
