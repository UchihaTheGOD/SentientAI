"""Local MITRE ATT&CK lookups (Stage 4).

Reads ONLY the locally imported STIX 2.1 bundle (see
app/data/mitre/README.md and scripts/import_mitre.py). No network call
is made here, ever — not per event, not per lookup. If the dataset is
missing, every resolution fails closed to "Unknown / Not mapped".

Validation discipline (mission spec):
- An ID must normalize to T#### or T####.### and resolve to an
  attack-pattern whose mitre-attack external_id matches, with the
  sub-technique flag matching the ID shape.
- Revoked or deprecated objects are REJECTED. A revoked object may
  carry a revoked-by relationship; the replacement is reported, never
  silently substituted.
- Tactic claims are verified against the technique's own
  kill_chain_phases; sub-technique parents via subtechnique-of.
- Official reference URLs come from the object's own
  external_references, never hand-built.
- Analytics link to strategies through their external_references URL
  (.../detectionstrategies/DET####), NOT through relationships: the
  v20.0 bundle contains zero relationships touching analytics.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "app" / "data" / "mitre"
MANIFEST_PATH = DATA_DIR / "manifest.json"
INDEX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
             "/master/index.json")

_ID_RE = re.compile(r"^T(\d{4})(?:\.(\d{3}))?$")
_DET_URL_RE = re.compile(r"/detectionstrategies/(DET\d+)#")

NOT_MAPPED = "Unknown / Not mapped"


def normalize_id(raw: str) -> Optional[str]:
    """'t1110.001' -> 'T1110.001' (case/whitespace only). Short forms
    like 'T1110.1' are malformed, not padded: padding could silently
    turn a typo into a different real technique."""
    if not raw or not isinstance(raw, str):
        return None
    m = _ID_RE.match(raw.strip().upper())
    if not m:
        return None
    base, sub = m.group(1), m.group(2)
    return f"T{base}" + (f".{sub}" if sub else "")


def _mitre_ref(obj: dict) -> Optional[dict]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


class MitreAttack:
    """In-memory indexes over one STIX bundle. Build via load_default()
    (manifest-driven) or directly from an objects list (tests)."""

    def __init__(self, objects: list, manifest: Optional[dict] = None):
        self.objects = objects
        self.manifest = manifest or {}
        self._by_stix_id: dict[str, dict] = {}
        self._technique_by_id: dict[str, dict] = {}
        self._tactic_by_shortname: dict[str, dict] = {}
        self._revoked_by: dict[str, str] = {}
        self._detects: dict[str, list[str]] = {}  # stix id -> related stix ids
        # Stage 6: index subtechnique-of at load instead of scanning all
        # 26,690 objects per resolve() (was ~4.3ms per call, now ~µs).
        self._subtechnique_parent: dict[str, str] = {}  # child stix id -> parent stix id
        for obj in objects:
            self._by_stix_id[obj["id"]] = obj
            typ = obj.get("type")
            if typ == "attack-pattern":
                ref = _mitre_ref(obj)
                if ref:
                    self._technique_by_id[ref["external_id"]] = obj
            elif typ == "x-mitre-tactic":
                short = obj.get("x_mitre_shortname")
                if short:
                    self._tactic_by_shortname[short] = obj
            elif typ == "relationship":
                rel = obj.get("relationship_type")
                if rel == "revoked-by":
                    self._revoked_by[obj["source_ref"]] = obj["target_ref"]
                elif rel == "detects":
                    self._detects.setdefault(obj["source_ref"], []).append(obj["target_ref"])
                    self._detects.setdefault(obj["target_ref"], []).append(obj["source_ref"])
                elif rel == "subtechnique-of":
                    self._subtechnique_parent[obj["source_ref"]] = obj["target_ref"]

    # -- loading ---------------------------------------------------------
    @classmethod
    def load_default(cls) -> "MitreAttack":
        """Manifest -> versioned bundle file. Raises FileNotFoundError
        when the dataset has not been imported (callers fail closed)."""
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        bundle_path = DATA_DIR / manifest["bundle_file"]
        with open(bundle_path, encoding="utf-8") as f:
            bundle = json.load(f)
        return cls(bundle["objects"], manifest)

    # -- dataset info / staleness ---------------------------------------
    def dataset_info(self) -> dict:
        valid_patterns = [o for o in self.objects
                          if o.get("type") == "attack-pattern"
                          and not o.get("revoked") and not o.get("x_mitre_deprecated")]
        techniques = sum(1 for o in valid_patterns if not o.get("x_mitre_is_subtechnique"))
        subtechniques = len(valid_patterns) - techniques
        return {
            "version": self.manifest.get("version"),
            "bundle_file": self.manifest.get("bundle_file"),
            "bundle_sha256": self.manifest.get("bundle_sha256"),
            "bundle_bytes": self.manifest.get("bundle_bytes"),
            "bundle_modified": self.manifest.get("bundle_modified"),
            "imported_at": self.manifest.get("imported_at"),
            "attribution": self.manifest.get("attribution"),
            "object_count": len(self.objects),
            "techniques": techniques,
            "subtechniques": subtechniques,
            "tactics": sum(1 for o in self.objects if o.get("type") == "x-mitre-tactic"),
            "detection_strategies": sum(1 for o in self.objects
                                        if o.get("type") == "x-mitre-detection-strategy"),
            "analytics": sum(1 for o in self.objects if o.get("type") == "x-mitre-analytic"),
            "revoked": sum(1 for o in self.objects if o.get("revoked")),
            "deprecated": sum(1 for o in self.objects if o.get("x_mitre_deprecated")),
        }

    @staticmethod
    def check_for_updates() -> Optional[str]:
        """Operator-triggered ONLY: fetch the collection index and report
        a newer Enterprise version, or None if current/unreachable.
        Never called during event analysis."""
        try:
            req = urllib.request.Request(INDEX_URL, headers={"User-Agent": "SentientAI-mitre-check"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                index = json.load(resp)
            current = None
            try:
                current = json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("version")
            except Exception:
                pass
            versions = []
            for coll in index.get("collections", []):
                if coll.get("name") == "Enterprise ATT&CK":
                    versions.extend(v.get("version") for v in coll.get("versions", []))
            if not versions:
                return None
            newest = sorted(versions, key=lambda v: [int(p) for p in v.split(".")])[-1]
            return newest if newest != current else None
        except Exception:
            return None

    # -- validation / resolution ----------------------------------------
    def lookup(self, technique_id: str) -> Optional[dict]:
        normalized = normalize_id(technique_id)
        return self._technique_by_id.get(normalized) if normalized else None

    def validate(self, technique_id: str) -> dict:
        """Returns {valid, technique_id, reason, replacement?}.

        reason is one of: ok, malformed, not_found, revoked,
        deprecated, subtechnique_mismatch."""
        normalized = normalize_id(technique_id)
        if normalized is None:
            return {"valid": False, "technique_id": None, "reason": "malformed"}
        obj = self._technique_by_id.get(normalized)
        if obj is None:
            return {"valid": False, "technique_id": normalized, "reason": "not_found"}
        if obj.get("revoked"):
            replacement = None
            target = self._by_stix_id.get(self._revoked_by.get(obj["id"], ""), {})
            ref = _mitre_ref(target)
            if ref:
                replacement = ref["external_id"]
            return {"valid": False, "technique_id": normalized,
                    "reason": "revoked", "replacement": replacement}
        if obj.get("x_mitre_deprecated"):
            return {"valid": False, "technique_id": normalized, "reason": "deprecated"}
        wants_sub = "." in normalized
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        if wants_sub != is_sub:
            return {"valid": False, "technique_id": normalized,
                    "reason": "subtechnique_mismatch"}
        return {"valid": True, "technique_id": normalized, "reason": "ok"}

    def resolve(self, technique_id: str) -> Optional[dict]:
        """Full validated resolution, or None (see validate() for why).
        Never returns revoked/deprecated objects, never substitutes."""
        check = self.validate(technique_id)
        if not check["valid"]:
            return None
        obj = self._technique_by_id[check["technique_id"]]
        ref = _mitre_ref(obj)
        tactics = []
        for phase in obj.get("kill_chain_phases", []) or []:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = self._tactic_by_shortname.get(phase.get("phase_name"))
            if tactic:
                tref = _mitre_ref(tactic)
                tactics.append({
                    "tactic_id": tref["external_id"] if tref else None,
                    "tactic_name": tactic.get("name"),
                    "tactic_shortname": tactic.get("x_mitre_shortname"),
                })
        parent = None
        if obj.get("x_mitre_is_subtechnique"):
            parent_obj = self._by_stix_id.get(
                self._subtechnique_parent.get(obj["id"], ""))
            pref = _mitre_ref(parent_obj) if parent_obj else None
            if parent_obj and pref:
                parent = {"technique_id": pref["external_id"],
                          "technique_name": parent_obj.get("name")}
        return {
            "technique_id": check["technique_id"],
            "technique_name": obj.get("name"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": parent,
            "tactics": tactics,
            "url": ref.get("url") if ref else None,
            "detection_strategies": self.strategies_for_technique(check["technique_id"]),
        }

    def strategies_for_technique(self, technique_id: str) -> list:
        obj = self.lookup(technique_id)
        if obj is None:
            return []
        out = []
        for stix_id in self._detects.get(obj["id"], []):
            other = self._by_stix_id.get(stix_id)
            if other and other.get("type") == "x-mitre-detection-strategy":
                ref = _mitre_ref(other)
                out.append({
                    "strategy_id": ref["external_id"] if ref else None,
                    "strategy_name": other.get("name"),
                    "url": ref.get("url") if ref else None,
                })
        return out

    def analytics_for_strategy(self, strategy_id: str) -> list:
        """Analytics whose external_references URL embeds the strategy
        (.../detectionstrategies/DET####). No relationships exist for
        analytics in the v20.0 bundle, so URL matching is the link."""
        out = []
        for obj in self.objects:
            if obj.get("type") != "x-mitre-analytic":
                continue
            for ref in obj.get("external_references", []) or []:
                m = _DET_URL_RE.search(ref.get("url", ""))
                if m and m.group(1) == strategy_id:
                    out.append({
                        "analytic_id": ref.get("external_id"),
                        "analytic_name": obj.get("name"),
                        "platforms": obj.get("x_mitre_platforms", []),
                        "url": ref.get("url"),
                    })
                    break
        return out


_CACHE: Optional[MitreAttack] = None


def get_mitre() -> Optional[MitreAttack]:
    """Cached default dataset, or None when not imported (fail closed)."""
    global _CACHE
    if _CACHE is None:
        try:
            _CACHE = MitreAttack.load_default()
        except Exception:
            return None
    return _CACHE
