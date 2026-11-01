"""Attack-intelligence assembly (Stage 5).

Combines the Stage 4 deterministic rules with validated MITRE
suggestions into the structured record the mission specifies, and
applies it to incidents. This module NEVER raises: any failure inside
it degrades to an unknown-filled record, because intelligence must
never break the verdict, incident, or candidacy pipeline it annotates.

Key honesty rules:
- Intelligence is an independent signal. It never changes the fused
  verdict/score, never approves training data, never blocks anything.
- The MITRE dataset is loaded lazily and ONLY when a finding could
  actually propose a technique (auth-pattern types, web-shell
  evidence). Otherwise only the small manifest is read for the
  dataset version, so ordinary events pay no 55 MB load.
- MITRE columns hold the most specific validated ID: for a
  sub-technique, mitre_technique_id is the PARENT technique and the
  sub-technique fields carry the specific ID (so tactic/technique
  filters and sub-technique filters both work).
- review_status on an incident reflects candidacy only ("unreviewed"
  by default, "candidate" once a training candidate exists). The human
  verdict itself lives on the TrainingExample, not here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from .attack_rules import analyze_text, classify_auth_attempts, suggest_mitre
from .mitre_attack import MANIFEST_PATH

_MAX_TEXT = 8000
_MITRE_CANDIDATE_TYPES = {
    "password_guessing", "password_spraying", "credential_stuffing",
    "brute_force", "web_shell_indicator",
}
_JOB_FINDING_CAP = 6


def _manifest_version() -> Optional[str]:
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("version")
    except Exception:
        return None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_intelligence(text, metadata=None, auth_attempts=None, mitre=None,
                       joined: bool = False):
    """Assemble the intelligence record for one analyzed text.

    text: the analyzed log/request text (capped defensively).
    metadata: structured fields (route, method, status, meta keys).
    auth_attempts: optional aggregated login attempts (see
        attack_rules.classify_auth_attempts); appended as a finding
        and used as the MITRE fallback when rules propose nothing.
    mitre: a MitreAttack instance, None for lazy auto-load (only when
        a candidate finding exists), or False to skip validation.
    joined: True when text is a " | "-joined composite (the worker's
        _event_log_text output). The joiner itself would otherwise
        trip the pipe alternative of the command-injection pattern
        whenever a part starts with id/sh/nc/bash, so joined text is
        flattened to spaces first. A genuine "a | id" inside a joined
        part is then indistinguishable from the joiner and is NOT
        flagged — a deliberate false-negative preference over a
        systematic false positive. Raw text (sentinel path) is
        analyzed as-is.
    Never raises."""
    try:
        return _build(text, metadata, auth_attempts, mitre, joined)
    except Exception as exc:  # intelligence must never break the pipeline
        return {
            "attack_category": None,
            "attack_type": None,
            "attack_subtype": None,
            "classification_confidence": None,
            "classification_evidence": [],
            "attack_outcome": "unknown",
            "mitre_tactic": None,
            "mitre_technique_id": None,
            "mitre_technique_name": None,
            "mitre_subtechnique_id": None,
            "mitre_subtechnique_name": None,
            "mitre_mapping_confidence": None,
            "mitre_mapping_rationale": None,
            "mitre_dataset_version": _manifest_version(),
            "analysis_timestamp": _utcnow_iso(),
            "findings": [],
            "finding_count": 0,
            "error": str(exc),
        }


def _build(text, metadata, auth_attempts, mitre, joined=False):
    raw = text if isinstance(text, str) else ""
    if joined:
        raw = raw.replace(" | ", " ")
    findings = analyze_text(raw[:_MAX_TEXT], metadata or {})
    if auth_attempts:
        auth = classify_auth_attempts(auth_attempts)
        if auth is not None:
            findings.append(auth)
    primary = findings[0] if findings else None

    suggestion = None
    suggestion_finding = None
    if mitre is not False and any(
            f.get("attack_type") in _MITRE_CANDIDATE_TYPES for f in findings):
        if mitre is None:
            try:
                from .mitre_attack import get_mitre
                mitre = get_mitre()
            except Exception:
                mitre = None
        if mitre is not None:
            for finding in findings:
                if finding.get("attack_type") in _MITRE_CANDIDATE_TYPES:
                    suggestion = suggest_mitre(finding, mitre)
                    if suggestion is not None:
                        suggestion_finding = finding
                        break

    mitre_fields = {
        "mitre_tactic": None,
        "mitre_technique_id": None,
        "mitre_technique_name": None,
        "mitre_subtechnique_id": None,
        "mitre_subtechnique_name": None,
        "mitre_mapping_confidence": None,
        "mitre_mapping_rationale": None,
    }
    if suggestion is not None:
        tactics = suggestion.get("tactics") or []
        tactic = tactics[0] if tactics else {}
        if suggestion.get("is_subtechnique") and suggestion.get("parent"):
            mitre_fields["mitre_technique_id"] = suggestion["parent"]["technique_id"]
            mitre_fields["mitre_technique_name"] = suggestion["parent"]["technique_name"]
            mitre_fields["mitre_subtechnique_id"] = suggestion["technique_id"]
            mitre_fields["mitre_subtechnique_name"] = suggestion["technique_name"]
        else:
            mitre_fields["mitre_technique_id"] = suggestion["technique_id"]
            mitre_fields["mitre_technique_name"] = suggestion["technique_name"]
        mitre_fields["mitre_tactic"] = tactic.get("tactic_name")
        mitre_fields["mitre_mapping_confidence"] = (
            suggestion_finding or {}).get("confidence")
        mitre_fields["mitre_mapping_rationale"] = suggestion.get("rationale")

    return {
        "attack_category": primary["attack_category"] if primary else None,
        "attack_type": primary["attack_type"] if primary else None,
        "attack_subtype": primary.get("attack_subtype") if primary else None,
        "classification_confidence": primary["confidence"] if primary else None,
        "classification_evidence": primary["evidence"] if primary else [],
        "attack_outcome": primary["outcome"] if primary else "no_indicator",
        **mitre_fields,
        "mitre_dataset_version": _manifest_version(),
        "analysis_timestamp": _utcnow_iso(),
        "findings": findings,
        "finding_count": len(findings),
    }


def job_assessment_intelligence(intelligence: dict) -> dict:
    """Bounded copy for AutomationJob.assessment_json (capped at 8000
    chars total): primary fields + first findings + count. The full
    findings list lives on the incident's classification_evidence."""
    findings = intelligence.get("findings") or []
    return {
        "attack_category": intelligence.get("attack_category"),
        "attack_type": intelligence.get("attack_type"),
        "attack_subtype": intelligence.get("attack_subtype"),
        "classification_confidence": intelligence.get("classification_confidence"),
        "attack_outcome": intelligence.get("attack_outcome"),
        "mitre_technique_id": intelligence.get("mitre_subtechnique_id")
        or intelligence.get("mitre_technique_id"),
        "mitre_technique_name": intelligence.get("mitre_subtechnique_name")
        or intelligence.get("mitre_technique_name"),
        "mitre_dataset_version": intelligence.get("mitre_dataset_version"),
        "findings": findings[:_JOB_FINDING_CAP],
        "finding_count": intelligence.get("finding_count", len(findings)),
        "findings_capped": len(findings) > _JOB_FINDING_CAP,
    }


def apply_to_incident(incident, intelligence: dict, force: bool = False) -> bool:
    """Write intelligence fields onto an incident object (no commit).

    Applies when force is True or when the incident carries no
    intelligence yet (attack_category AND analysis_timestamp empty).
    Never overwrites an existing analysis. Returns True if applied.
    review_status is set to "unreviewed"; callers upgrade it to
    "candidate" after a training candidate is created."""
    if not force and not (
            getattr(incident, "attack_category", None) is None
            and getattr(incident, "analysis_timestamp", None) is None):
        return False
    incident.attack_category = intelligence.get("attack_category")
    incident.attack_type = intelligence.get("attack_type")
    incident.attack_subtype = intelligence.get("attack_subtype")
    incident.classification_confidence = intelligence.get("classification_confidence")
    incident.classification_evidence = json.dumps(
        intelligence.get("findings") or [], ensure_ascii=False)
    incident.attack_outcome = intelligence.get("attack_outcome")
    incident.mitre_tactic = intelligence.get("mitre_tactic")
    incident.mitre_technique_id = intelligence.get("mitre_technique_id")
    incident.mitre_technique_name = intelligence.get("mitre_technique_name")
    incident.mitre_subtechnique_id = intelligence.get("mitre_subtechnique_id")
    incident.mitre_subtechnique_name = intelligence.get("mitre_subtechnique_name")
    incident.mitre_mapping_confidence = intelligence.get("mitre_mapping_confidence")
    incident.mitre_mapping_rationale = intelligence.get("mitre_mapping_rationale")
    incident.mitre_dataset_version = intelligence.get("mitre_dataset_version")
    try:
        incident.analysis_timestamp = datetime.fromisoformat(
            intelligence["analysis_timestamp"])
    except Exception:
        incident.analysis_timestamp = datetime.now(timezone.utc)
    incident.review_status = "unreviewed"
    return True


def incident_intelligence_dict(incident) -> Optional[dict]:
    """Rebuild the stored intelligence record for display, or None
    when the incident was never analyzed by this layer."""
    if getattr(incident, "analysis_timestamp", None) is None:
        return None
    try:
        findings = json.loads(incident.classification_evidence or "[]")
    except Exception:
        findings = []
    return {
        "attack_category": incident.attack_category,
        "attack_type": incident.attack_type,
        "attack_subtype": incident.attack_subtype,
        "classification_confidence": incident.classification_confidence,
        "attack_outcome": incident.attack_outcome,
        "mitre_tactic": incident.mitre_tactic,
        "mitre_technique_id": incident.mitre_technique_id,
        "mitre_technique_name": incident.mitre_technique_name,
        "mitre_subtechnique_id": incident.mitre_subtechnique_id,
        "mitre_subtechnique_name": incident.mitre_subtechnique_name,
        "mitre_mapping_confidence": incident.mitre_mapping_confidence,
        "mitre_mapping_rationale": incident.mitre_mapping_rationale,
        "mitre_dataset_version": incident.mitre_dataset_version,
        "analysis_timestamp": incident.analysis_timestamp.isoformat()
        if incident.analysis_timestamp else None,
        "review_status": incident.review_status,
        "findings": findings,
    }
