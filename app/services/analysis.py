"""Analysis orchestrator — ties lab execution, detection, and logging together."""
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from sqlalchemy.orm import Session

from app.models.learning import CANDIDATE, AnalysisFeedback
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services import scoring, training
from app.services.detection import detect, DetectionResult
from app.services.cyberllm_client import get_cyberllm_client


def analyze_lab_submission(
    db: Session,
    user_id: int,
    lab_id: str,
    lab_category: str,
    payload: str,
    lab_result: Dict[str, Any],
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Full analysis pipeline for a lab submission.

    1. Run detection engine on the payload.
    2. Run CyberLLM analysis (mock for now).
    3. Log SecurityEvent to DB (with session_id if provided).
    4. Generate + store TrainingExample.
    5. Return full result dict for the response page.
    """
    # 1) Detection
    detection: DetectionResult = detect(payload, lab_category)

    # Determine if the attack "succeeded" in the lab context
    attack_succeeded = lab_result.get("vulnerable", False) and detection.detected

    # 2) CyberLLM analysis
    client = get_cyberllm_client()
    event_data = {
        "detected": detection.detected,
        "attack_category": detection.attack_category,
        "severity": detection.severity,
        "explanation": detection.explanation,
        "defense_recommendation": detection.defense_recommendation,
        "sanitized_payload": payload[:500],  # truncate for safety
        "patterns_matched": detection.patterns_matched,
    }
    analysis = client.analyze_attack(event_data)

    # 3) Log SecurityEvent
    event = SecurityEvent(
        user_id=user_id,
        lab_id=lab_id,
        session_id=session_id,
        timestamp=datetime.now(timezone.utc),
        method="POST",
        endpoint=f"/testing/labs/{lab_id}/submit",
        sanitized_payload=payload[:500],
        detection_result="detected" if detection.detected else "not_detected",
        attack_category=detection.attack_category if detection.detected else "none",
        severity=detection.severity if detection.detected else "info",
        success=attack_succeeded,
        blocked=detection.should_block,
        explanation=analysis.explanation,
        defense_recommendation=analysis.defense_recommendation,
        raw_analysis_json=json.dumps({
            "confidence": analysis.confidence,
            "technique_description": analysis.technique_description,
            "patterns_matched": detection.patterns_matched,
        }),
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # 4) Generate training example.
    #    It is stored as a CANDIDATE only. Nothing here sets `approved` or
    #    `safe_to_train` — that needs an admin review (app/services/training.py),
    #    so no user input can put itself into the training set.
    training_data = client.generate_training_example(event_data)
    digest = training.dedup_hash(
        training_data["instruction"], training_data["input"]
    )

    # Score the candidate for triage. This is advisory only: it decides queue
    # order and a band label, never whether the row can train. A candidate that
    # already has a twin in the store is flagged so a reviewer sees the overlap
    # before spending time on a second copy.
    is_duplicate = training.find_duplicate(db, digest) is not None
    score = scoring.score_candidate(
        detected=detection.detected,
        attack_category=detection.attack_category,
        severity=detection.severity,
        patterns_matched=detection.patterns_matched,
        instruction=training_data["instruction"],
        input_text=training_data["input"],
        output_text=training_data["output"],
        is_duplicate=is_duplicate,
    )

    training_example = TrainingExample(
        event_id=event.id,
        instruction=training_data["instruction"],
        input_text=training_data["input"],
        output_text=training_data["output"],
        attack_type=training_data["attack_type"],
        severity=training_data["severity"],
        source=training_data["source"],
        approved=False,
        status=CANDIDATE,
        safe_to_train=False,
        # What the pipeline thought, kept separate from any human label so the
        # two can be compared later.
        model_prediction=detection.attack_category if detection.detected else "none",
        provenance="lab_submission",
        dedup_hash=digest,
        quality_score=score.score,
        quality_band=score.band,
        quality_notes=score.notes_text or None,
    )
    db.add(training_example)
    db.commit()

    # 5) Build result
    if detection.should_block:
        status_label = "BLOCKED"
    elif detection.detected and attack_succeeded:
        status_label = "SUCCESSFUL"
    elif detection.detected:
        status_label = "DETECTED"
    else:
        status_label = "NOT DETECTED"

    return {
        "event_id": event.id,
        "session_id": session_id,
        "detected": detection.detected,
        "blocked": detection.should_block,
        "attack_type": analysis.attack_type,
        "status": status_label,
        "severity": analysis.severity,
        "explanation": analysis.explanation,
        "technique_description": analysis.technique_description,
        "defense_recommendation": analysis.defense_recommendation,
        "lab_output": lab_result.get("output", ""),
        "lab_id": lab_id,
        "timestamp": event.timestamp.isoformat(),
    }


def record_analysis_feedback(
    db: Session,
    event: SecurityEvent,
    user_id: int,
    verdict: str,
    note: Optional[str] = None,
) -> AnalysisFeedback:
    """Record one user's verdict on an event's CyberLLM explanation.

    Stored once per (event, user): a repeat vote updates the existing row rather
    than inserting a second, so a single account cannot stack feedback on one
    event. The caller is responsible for validating `verdict` against
    `FEEDBACK_VERDICTS` and for scoping `event` to the requesting user.

    An "incorrect" verdict is a *hint*, not a control. If the linked candidate is
    still pending and the scorer had triaged it "useful", it is dropped to
    "review" so an admin looks manually before it could ever be approved. It
    never changes `approved` or `safe_to_train` — only a human review does that.
    """
    feedback = (
        db.query(AnalysisFeedback)
        .filter(
            AnalysisFeedback.event_id == event.id,
            AnalysisFeedback.user_id == user_id,
        )
        .first()
    )
    if feedback is None:
        feedback = AnalysisFeedback(event_id=event.id, user_id=user_id, verdict=verdict)
        db.add(feedback)
    feedback.verdict = verdict
    feedback.note = note or None

    if verdict == "incorrect":
        candidate = (
            db.query(TrainingExample)
            .filter(TrainingExample.event_id == event.id)
            .first()
        )
        if (
            candidate is not None
            and candidate.is_pending
            and candidate.quality_band == scoring.BAND_USEFUL
        ):
            candidate.quality_band = scoring.BAND_REVIEW
            marker = "User feedback flagged the analysis as incorrect."
            candidate.quality_notes = (
                f"{candidate.quality_notes}\n{marker}" if candidate.quality_notes else marker
            )

    db.commit()
    db.refresh(feedback)
    return feedback
