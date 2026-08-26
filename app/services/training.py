"""Training example management — approve, reject, export."""
import json
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.training_example import TrainingExample


def get_pending_examples(db: Session, limit: int = 50) -> List[TrainingExample]:
    return (
        db.query(TrainingExample)
        .filter(TrainingExample.approved == False)
        .order_by(TrainingExample.created_at.desc())
        .limit(limit)
        .all()
    )


def get_approved_examples(db: Session) -> List[TrainingExample]:
    return (
        db.query(TrainingExample)
        .filter(TrainingExample.approved == True)
        .order_by(TrainingExample.created_at.desc())
        .all()
    )


def approve_example(db: Session, example_id: int, reviewer_id: int) -> Optional[TrainingExample]:
    example = db.query(TrainingExample).filter(TrainingExample.id == example_id).first()
    if example:
        example.approved = True
        example.reviewed_by = reviewer_id
        db.commit()
        db.refresh(example)
    return example


def reject_example(db: Session, example_id: int) -> bool:
    example = db.query(TrainingExample).filter(TrainingExample.id == example_id).first()
    if example:
        db.delete(example)
        db.commit()
        return True
    return False


def export_approved_jsonl(db: Session) -> str:
    """Export approved training examples as JSONL string."""
    examples = get_approved_examples(db)
    lines = []
    for ex in examples:
        record = {
            "instruction": ex.instruction,
            "input": ex.input_text,
            "output": ex.output_text,
            "attack_type": ex.attack_type,
            "severity": ex.severity,
            "source": ex.source,
            "approved": True,
        }
        lines.append(json.dumps(record))
    return "\n".join(lines)
