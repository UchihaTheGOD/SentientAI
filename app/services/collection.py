"""Collect training candidates from human moderation decisions.

This is the *producer* end of the internal Sentinel pipeline — the one place
that turns activity on the site into a training candidate. It is deliberately
narrow, because two rules from the data policy meet here:

  1. **A candidate is only ever born from a moderator's explicit decision on
     reported content.** Never from arbitrary public posts or comments. The
     material is real and a human has already judged it, which is exactly what
     makes it worth learning from — and what keeps us clear of "auto-train on
     whatever users typed."
  2. **Producing a candidate changes nothing about what is trainable.** Every
     row is written as ``CANDIDATE`` with ``safe_to_train=False``. The only path
     to a dataset is still an admin review in ``app/services/training.py``.

The candidate captures what a reviewer needs to judge the label later: the
reported content (sanitised to plain text), the decision the moderator made,
and the category the report *claimed* — stored as ``model_prediction``, i.e. a
guess to be checked at review, never asserted as fact. Scoring (see
``app/services/scoring.py``) is advisory triage only and cannot promote a row.

Nothing here is imported by a public route handler; the only caller is the
admin-only moderation flow (``app/api/moderation.py::log_action``).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.blog_post import BlogPost
from app.models.learning import CANDIDATE
from app.models.moderation import REPORT_REASON_LABELS, Report
from app.models.social import Comment
from app.models.training_example import TrainingExample
from app.services import audit, scoring
from app.services import training as training_service
from app.services.sanitize import strip_formatting

logger = logging.getLogger("sentientai.collection")

# The two labels a moderation decision can teach.
_REMOVE = "remove"
_KEEP = "keep"

# Which moderation actions map to a clean keep/remove judgement on a single
# piece of content, and how strong a signal each is for the scorer. Actions not
# listed here (suspending an account, restoring content, resolving a report
# administratively) do not label one item, so they produce nothing.
_ACTION_DECISION = {
    "post_hidden":      (_REMOVE, scoring.SIGNAL_STRONG),
    "comment_hidden":   (_REMOVE, scoring.SIGNAL_STRONG),
    "post_removed":     (_REMOVE, scoring.SIGNAL_STRONG),
    "report_dismissed": (_KEEP,   scoring.SIGNAL_WEAK),
}

# Longest content snapshot we keep. A moderation example is about the decision,
# not the full article body, so a short excerpt is enough and keeps the row lean.
_MAX_CONTENT = 600
# Below this the snapshot cannot teach anything; skip rather than store noise.
_MIN_CONTENT_CHARS = 4


def _content_snapshot(db: Session, target_type: str, target_id: int) -> str | None:
    """Plain-text snapshot of the moderated item.

    Returns ``None`` when there is no single piece of content to learn from
    (a profile), or the content has since gone.
    """
    if target_type == "post":
        post = db.query(BlogPost).filter(BlogPost.id == target_id).first()
        if post is None:
            return None
        joined = "\n".join(p for p in (post.title or "", post.summary or "") if p)
        return strip_formatting(joined, _MAX_CONTENT)
    if target_type == "comment":
        comment = db.query(Comment).filter(Comment.id == target_id).first()
        if comment is None:
            return None
        return strip_formatting(comment.body, _MAX_CONTENT)
    return None


def _decision_text(verdict: str, target_type: str, reason: str | None,
                   predicted: str | None) -> str:
    """The 'answer' a reviewer is judging: what the moderator decided and why.

    Prefers the moderator's own reason. Falls back to a generic, honest summary
    that names the reported category rather than inventing a rationale.
    """
    reason = (reason or "").strip()
    if verdict == _REMOVE:
        if reason:
            return f"Remove this {target_type}. {reason}"
        label = REPORT_REASON_LABELS.get(predicted, "the community guidelines")
        return (
            f"Remove this {target_type}: a moderator reviewed the report "
            f"(“{label}”) and confirmed it violates the community guidelines."
        )
    if reason:
        return f"Keep this {target_type}. {reason}"
    return (
        f"Keep this {target_type}: a moderator reviewed the report and found it "
        f"does not violate the community guidelines."
    )


def collect_from_moderation(
    db: Session,
    *,
    action: str,
    target_type: str,
    target_id: int,
    moderator=None,
    reason: str | None = None,
    report_id: int | None = None,
    request=None,
) -> TrainingExample | None:
    """Turn one moderation decision into an unreviewed training candidate.

    Returns the new ``TrainingExample`` (always a ``CANDIDATE``), or ``None``
    when the action is not a content judgement, the content is gone, the
    snapshot is too small to teach anything, or anything goes wrong.

    It never raises and never leaves the caller's transaction dirty: a
    moderation action must succeed even if candidate collection does not.
    """
    decision = _ACTION_DECISION.get(action)
    if decision is None:
        return None
    verdict, signal = decision

    try:
        content = _content_snapshot(db, target_type, target_id)
        if not content or len(content.strip()) < _MIN_CONTENT_CHARS:
            return None

        # The category the *report* claimed. It is a guess to be checked during
        # review, so it lands in model_prediction — never in human_label, which
        # only a reviewer sets.
        predicted: str | None = None
        if report_id:
            report = db.query(Report).filter(Report.id == report_id).first()
            if report is not None:
                predicted = report.reason

        instruction = (
            f"Decide whether this reported {target_type} should be removed and explain why."
        )
        input_text = f"Reported {target_type}: '{content}'"
        output_text = _decision_text(verdict, target_type, reason, predicted)

        digest = training_service.dedup_hash(instruction, input_text)
        is_duplicate = training_service.find_duplicate(db, digest) is not None

        result = scoring.score_candidate(
            signal=signal,
            instruction=instruction,
            input_text=input_text,
            output_text=output_text,
            is_duplicate=is_duplicate,
        )

        # Moderation is now human-only: the obsolete Sentinel moderation
        # model was removed, and CyberLLMv1 is a security-log classifier,
        # not a content-moderation classifier — forcing it to moderate
        # blog posts/comments would be a misuse of the model. The
        # training candidate itself is born from the moderator's own
        # decision (see module docstring), so removing the model
        # annotation does not change what the candidate teaches.
        # Legacy-named sentinel_* columns are kept as storage (existing
        # DB) and record the honest removal status.
        sentinel_info = {"status": "model_removed_human_review_only", "json_valid": False, "parsed": None, "error": "legacy Sentinel moderation model removed; human review is the sole moderation authority", "raw_text": "", "text": "", "tokens": 0, "latency_ms": 0}
        # Prepare sentinel columns for storage (honest, may be not-ready/empty)
        _sent_status_val = (sentinel_info or {}).get("status")
        _sent_raw = (sentinel_info or {}).get("raw_text") or (sentinel_info or {}).get("text") or ""
        _sent_parsed = (sentinel_info or {}).get("parsed")
        import json as _json
        _sent_parsed_json = _json.dumps(_sent_parsed) if _sent_parsed else None
        _sent_label = (_sent_parsed or {}).get("label") if _sent_parsed else None
        _sent_category = (_sent_parsed or {}).get("category") if _sent_parsed else None
        _sent_conf = str((_sent_parsed or {}).get("confidence")) if _sent_parsed and (_sent_parsed or {}).get("confidence") is not None else None
        _sent_lat = (sentinel_info or {}).get("latency_ms")
        _sent_model = (sentinel_info or {}).get("model")
        example = TrainingExample(
            instruction=instruction,
            input_text=input_text,
            output_text=output_text,
            source="moderation",
            provenance="moderation_flag",
            status=CANDIDATE,
            approved=False,
            safe_to_train=False,
            model_prediction=predicted,
            quality_score=result.score,
            quality_band=result.band,
            quality_notes=result.notes_text or None,
            dedup_hash=digest,
            sentinel_status=_sent_status_val,
            sentinel_raw_text=_sent_raw[:2000] if _sent_raw else None,
            sentinel_parsed_json=_sent_parsed_json,
            sentinel_label=_sent_label,
            sentinel_category=_sent_category,
            sentinel_confidence=_sent_conf,
            sentinel_latency_ms=_sent_lat,
            sentinel_model=_sent_model,
        )
        db.add(example)
        db.commit()
        db.refresh(example)
    except Exception:
        db.rollback()
        logger.exception("Failed to collect a moderation training candidate")
        return None

    audit.record(
        db, "training.candidate_created", user=moderator,
        target_type="training_example", target_id=str(example.id),
        detail=f"band={example.quality_band}; from={action}", request=request,
    )
    return example
# ---------------------------------------------------------------------------
# Sentinel incident -> sanitized TrainingExample (bridge target)
# ---------------------------------------------------------------------------

_MAX_INCIDENT_INPUT = 1800
_MAX_INCIDENT_OUTPUT = 1200

def _redact_for_training(text: str) -> str:
    try:
        from app.services.security_events import redact
        return redact(text) or text
    except Exception:
        return text

def _incident_instruction(fused_verdict: str | None) -> str:
    return "Classify the security log: respond with likely_threat, needs_review, or likely_benign and explain why."

def _incident_output_text(incident) -> str:
    verdict = (incident.fused_verdict or "needs_review").strip()
    score = incident.fused_score
    ev = []
    try:
        import json as _js
        raw = incident.evidence
        if raw:
            parsed = _js.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, list):
                ev = [str(x)[:200] for x in parsed[:6] if x]
    except Exception:
        ev = []
    lines = [f"verdict: {verdict}"]
    if score is not None:
        lines[0] += f" (score {score})"
    if ev:
        lines.append("evidence: " + "; ".join(ev[:4]))
    lines.append("requires human review before training")
    txt = "\n".join(lines)
    return txt[:_MAX_INCIDENT_OUTPUT]

def collect_from_incident(db, incident, actor=None, request=None):
    try:
        from app.models.training_example import TrainingExample
        from app.models.learning import CANDIDATE
        if incident is None or not getattr(incident, "log_text", None):
            return None
        log_raw = (incident.log_text or "").strip()
        if len(log_raw) < 4:
            return None
        log_clean = _redact_for_training(log_raw)[:_MAX_INCIDENT_INPUT]
        try:
            from app.services.sanitize import strip_formatting
            maybe = strip_formatting(log_clean, _MAX_INCIDENT_INPUT)
            if maybe and len(maybe.strip()) >= 4:
                log_clean = maybe
        except Exception:
            pass
        instruction = _incident_instruction(getattr(incident, "fused_verdict", None))
        input_text = f"Log excerpt: {log_clean}"
        output_text = _incident_output_text(incident)
        provenance = "sentinel_incident"
        source = "sentinel"
        from app.services import training as training_service
        digest = training_service.dedup_hash(instruction, input_text)
        is_dup = training_service.find_duplicate(db, digest) is not None
        if is_dup:
            existing = training_service.find_duplicate(db, digest)
            return existing
        verdict = (incident.fused_verdict or "").lower()
        if verdict == "likely_threat":
            signal = scoring.SIGNAL_STRONG
        elif verdict == "needs_review":
            signal = scoring.SIGNAL_WEAK
        else:
            signal = scoring.SIGNAL_NONE
        result = scoring.score_candidate(signal=signal, instruction=instruction, input_text=input_text, output_text=output_text, is_duplicate=False)
        sent_raw = ((incident.model_a_text or "") + "\n" + (incident.model_b_text or "")).strip()[:2000]
        example = TrainingExample(
            instruction=instruction,
            input_text=input_text,
            output_text=output_text,
            source=source,
            provenance=provenance,
            status=CANDIDATE,
            approved=False,
            safe_to_train=False,
            model_prediction=verdict or None,
            quality_score=result.score,
            quality_band=result.band,
            quality_notes=result.notes_text or None,
            dedup_hash=digest,
            sentinel_status=incident.model_a_status or incident.model_b_status or None,
            sentinel_raw_text=sent_raw or None,
            sentinel_parsed_json=None,
            sentinel_label=verdict or None,
            sentinel_category=None,
            sentinel_confidence=str(incident.fused_score) if incident.fused_score is not None else None,
            sentinel_latency_ms=None,
            sentinel_model=None,
        )
        db.add(example)
        db.commit()
        db.refresh(example)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        import logging as _lg
        _lg.getLogger("sentientai.collection").exception("collect_from_incident failed")
        return None
    try:
        audit.record(db, "training.candidate_created", user=actor, target_type="training_example", target_id=str(example.id), detail=f"band={example.quality_band}; from=sentinel_incident:{getattr(incident, 'id', '?')}", request=request)
    except Exception:
        pass
    return example

