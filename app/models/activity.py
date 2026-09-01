"""Activity model — tracks user actions across the platform."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from app.database import Base


# Extensible activity types — add new ones as needed
ACTIVITY_TYPES = [
    "account_created",
    "blog_post_created",
    "blog_post_updated",
    "blog_post_published",
    "comment_posted",
    "followed_user",
    "profile_updated",
]


class Activity(Base):
    __tablename__ = "activities"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    activity_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=False, default="")

    # Optional references — polymorphic linking to related entities
    target_type = Column(String(50), nullable=True)   # e.g. "blog_post", "comment", "user"
    target_id = Column(String(100), nullable=True)     # ID of the related entity (string for uuid compat)

    # Privacy: public activities show on public profile, private ones are user-only
    is_public = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
