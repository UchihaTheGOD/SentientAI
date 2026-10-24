#!/usr/bin/env python3
"""Make a dataset manifest (hashes, license, labels, processing history)."""
import argparse, hashlib, json, pathlib, datetime
from pathlib import Path

def sha256(p: Path) -> str:
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(1<<20), b''): h.update(chunk)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True)
    ap.add_argument('--source', required=True)
    ap.add_argument('--license', default='unknown')
    ap.add_argument('--raw-dir', default=None)
    ap.add_argument('--out', default=None)
    args=ap.parse_args()
    raw = Path(args.raw_dir) if args.raw_dir else Path(f"datasets/raw/{args.dataset}")
    if not raw.exists():
        raw = Path(f"datasets/raw")
    files=[]
    for p in Path("datasets/raw").rglob("*"):
        if p.is_file():
            files.append({"path": str(p), "sha256": sha256(p), "bytes": p.stat().st_size})
    manifest={
        "dataset": args.dataset,
        "source": args.source,
        "download_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "license": args.license,
        "files": files,
        "record_count": None,
        "available_labels": [],
        "processing_history": [],
        "intended_use": "SentinelAI tasks 1-12 (see datasets/DATASET_REQUIREMENTS.md)",
        "known_limitations": []
    }
    out = Path(args.out) if args.out else Path(f"datasets/manifests/{args.dataset}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f"Wrote {out} ({len(files)} files)")

if __name__=='__main__':
    main()
