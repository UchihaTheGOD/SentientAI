"""Blog post model — public-facing content."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

# Post lifecycle states (PHASE 27). Drafts and archived posts never appear in
# public feeds — see app/api/blog.py::public_posts_query().
POST_DRAFT = "draft"
POST_PUBLISHED = "published"
POST_ARCHIVED = "archived"
POST_STATES = (POST_DRAFT, POST_PUBLISHED, POST_ARCHIVED)


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
    # `published` is the legacy boolean. It is kept in sync with `status` so old
    # queries and templates keep working; `status` is authoritative.
    published = Column(Boolean, default=False, index=True)
    status = Column(String(20), default="draft", nullable=False, index=True)
    published_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    # User authorship (nullable — legacy seeded posts have author string but no user_id)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    views = Column(Integer, default=0, nullable=False)
    excerpt = Column(Text, nullable=True)  # Short excerpt, auto-generated from content if not set

    # Moderation (set by admins only — see app/api/moderation.py)
    is_hidden = Column(Boolean, default=False, nullable=False, index=True)
    hidden_reason = Column(String(255), nullable=True)

    # Relationships
    tags = relationship("Tag", secondary="post_tags", backref="posts", lazy="selectin")

    # -- state helpers -----------------------------------------------------
    @property
    def state(self) -> str:
        """Normalised lifecycle state, tolerant of legacy rows."""
        if self.status in POST_STATES:
            return self.status
        return POST_PUBLISHED if self.published else POST_DRAFT

    @property
    def is_public(self) -> bool:
        """True only when a normal visitor may see this post."""
        return self.state == POST_PUBLISHED and not self.is_hidden

    @property
    def state_label(self) -> str:
        return {
            POST_DRAFT: "Draft",
            POST_PUBLISHED: "Published",
            POST_ARCHIVED: "Archived",
        }.get(self.state, "Draft")

    def apply_state(self, new_state: str) -> None:
        """Move the post between draft / published / archived consistently."""
        if new_state not in POST_STATES:
            raise ValueError(f"Unknown post state: {new_state}")
        self.status = new_state
        self.published = new_state == POST_PUBLISHED
        if new_state == POST_PUBLISHED and self.published_at is None:
            self.published_at = datetime.now(timezone.utc)

    @property
    def display_excerpt(self) -> str:
        """Return excerpt, or a trimmed plain-text lead from the content."""
        from app.services.sanitize import strip_formatting

        if self.excerpt:
            return self.excerpt
        if self.summary:
            return self.summary
        return strip_formatting(self.content, 200)


# Valid content categories — general community platform
BLOG_CATEGORIES = [
    "Technology",
    "Programming",
    "Design",
    "Productivity",
    "Career",
    "Science",
    "Personal",
    "Projects",
    "Learning",
    "Tools",
    "Opinion",
    "Community",
]

# Keep a secondary set for tester/research content — used in /testing write flow
RESEARCH_CATEGORIES = [
    "Vulnerability Research",
    "Detection Engineering",
    "SOC",
    "Web Security",
    "Incident Response",
    "Security Engineering",
    "Lab Notes",
]

ALL_CATEGORIES = BLOG_CATEGORIES + RESEARCH_CATEGORIES

