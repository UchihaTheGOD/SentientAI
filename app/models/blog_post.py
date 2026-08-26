"""Blog post model — public-facing content."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base


class BlogPost(Base):
    __tablename__ = "blog_posts"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(200), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    author = Column(String(100), nullable=False, default="SentientAI Team")
    category = Column(String(50), nullable=False, index=True)
    summary = Column(Text, nullable=False, default="")
    content = Column(Text, nullable=False)
    reading_time = Column(Integer, default=5)  # minutes
    published = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))


# Valid blog categories
BLOG_CATEGORIES = [
    "Vulnerability Research",
    "Detection Engineering",
    "SOC",
    "Web Security",
    "Incident Response",
    "Security Engineering",
    "Lab Notes",
]
