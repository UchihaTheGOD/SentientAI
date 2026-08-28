"""Security event model — logs every lab interaction."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    lab_id = Column(String(50), nullable=False, index=True)

    # Link back to the parent session (nullable for backwards compatibility)
    session_id = Column(String(64), ForeignKey("lab_sessions.session_id"),
                        nullable=True, index=True)

    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    method = Column(String(10), default="POST")
    endpoint = Column(String(255))
    sanitized_payload = Column(Text)
    detection_result = Column(String(20))  # detected / not_detected
    attack_category = Column(String(50))   # sqli, xss, path_traversal, etc.
    severity = Column(String(20))          # low / medium / high / critical
    success = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)
    explanation = Column(Text)
    defense_recommendation = Column(Text)
    raw_analysis_json = Column(Text)  # JSON blob from CyberLLM / detection engine

