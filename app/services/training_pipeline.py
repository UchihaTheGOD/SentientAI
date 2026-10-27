"""Candidate training / evaluation / deployment pipeline (Phase 6)."""
from __future__ import annotations
import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import logging
logger = logging.getLogger("sentientai.training")
from app.models.sentinel_incident import SentinelIncident

# lightweight smoke train: never run multi-hour automatically
# Project-root-relative (not cwd-relative): candidate promotion must not
# depend on which directory the server was launched from.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CANDIDATE_DIR = _PROJECT_ROOT / "local_models" / "sentinel" / "candidates"
ACTIVE_PTR = _PROJECT_ROOT / "local_models" / "sentinel" / "active_candidate.txt"

def collect_reviewed_example(db, incident: SentinelIncident) -> Optional[dict]:
    if incident.status not in ("confirmed_threat","false_positive"):
        return None
    # dedup by log_text hash
    digest = hashlib.sha256((incident.log_text or "").strip().lower().encode("utf-8")).hexdigest()
    return {"incident_id": incident.id, "log_text": incident.log_text, "label": incident.status, "dedup": digest, "fused_verdict": incident.fused_verdict}

def build_dataset(reviewed_incidents: list[SentinelIncident]) -> tuple[list[dict], list[dict]]:
    # deduplicate, validate
    seen = set()
    train = []
    eval_set = []
    for inc in reviewed_incidents:
        if not inc.log_text or len(inc.log_text.strip()) < 4:
            continue
        d = hashlib.sha256(inc.log_text.strip().lower().encode("utf-8")).hexdigest()
        if d in seen:
            continue
        seen.add(d)
        # label mapping
        rec = {"instruction": "Classify security log", "input": inc.log_text[:1500], "output": inc.status, "incident_id": inc.id}
        # simple split: 80 train / 20 eval
        if len(train) < max(1, int(len(reviewed_incidents)*0.8)) or len(eval_set) >= len(train)//4:
            train.append(rec)
        else:
            eval_set.append(rec)
    return train, eval_set

def evaluate_candidate(train: list[dict], eval_set: list[dict]) -> dict:
    # Lightweight stub evaluation — real training would fine-tune and score
    # Report that dataset is insufficient unless thresholds met
    n_train = len(train); n_eval = len(eval_set)
    if n_train < 20 or n_eval < 5:
        return {"status":"insufficient_data","n_train":n_train,"n_eval":n_eval,"precision":None,"recall":None,"f1":None,"note":"Need >=20 train and >=5 eval; insufficient labeled reviewed incidents"}
    # dummy metrics
    return {"status":"evaluated","n_train":n_train,"n_eval":n_eval,"precision":0.5,"recall":0.5,"f1":0.5,"fp_rate":0.5,"fn_rate":0.5,"note":"smoke metrics; real fine-tune not run automatically"}

def save_candidate(train: list[dict], eval_set: list[dict], metrics: dict) -> Path:
    CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = CANDIDATE_DIR / f"candidate_{ts}.json"
    payload = {"created_at": ts, "train": train, "eval": eval_set, "metrics": metrics}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path

def list_candidates() -> list[Path]:
    if not CANDIDATE_DIR.exists():
        return []
    return sorted(CANDIDATE_DIR.glob("candidate_*.json"))

def approve_candidate(candidate_path: Path, approver_id: int) -> bool:
    # explicit approval: write active pointer
    ACTIVE_PTR.parent.mkdir(parents=True, exist_ok=True)
    ACTIVE_PTR.write_text(str(candidate_path.resolve()), encoding="utf-8")
    logger.info("Candidate approved %s by %s", candidate_path, approver_id)
    return True

def active_candidate() -> Optional[Path]:
    if ACTIVE_PTR.exists():
        p = Path(ACTIVE_PTR.read_text(encoding="utf-8").strip())
        if p.exists():
            return p
    return None

def rollback() -> bool:
    if ACTIVE_PTR.exists():
        ACTIVE_PTR.unlink()
        return True
    return False
