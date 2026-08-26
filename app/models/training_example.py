"""Training example model — curated data for CyberLLM fine-tuning."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from app.database import Base


class TrainingExample(Base):
    __tablename__ = "training_examples"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True)
    instruction = Column(Text, nullable=False)
    input_text = Column(Text, nullable=False)
    output_text = Column(Text, nullable=False)
    attack_type = Column(String(50))
    severity = Column(String(20))
    source = Column(String(50), default="sentientai_lab")
    approved = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
