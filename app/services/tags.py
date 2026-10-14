"""Tag parsing and lookup.

Tags come from a free-text field, so they are untrusted: normalised to a short
slug-safe form, length-capped, de-duplicated and count-capped before they ever
reach the database or a template.
"""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from app.models.tag import Tag

MAX_TAGS_PER_POST = 5
MAX_TAG_LENGTH = 30

_SPLIT_RE = re.compile(r"[,\n;]+")
_CLEAN_RE = re.compile(r"[^a-z0-9 +#.-]")
_SPACE_RE = re.compile(r"\s+")


def normalise_tag(raw: str) -> str:
    """'  Web  Security!! ' → 'web security'. Returns '' when nothing usable."""
    text = (raw or "").replace("\x00", "").strip().lower().lstrip("#")
    text = _CLEAN_RE.sub("", text)
    text = _SPACE_RE.sub(" ", text).strip(" -.")
    return text[:MAX_TAG_LENGTH]


def slugify_tag(name: str) -> str:
    slug = _SPACE_RE.sub("-", name.strip())
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug[:60]


def parse_tags(raw: str | None) -> list[str]:
    """Parse a comma/newline separated field into clean, unique tag names."""
    if not raw:
        return []
    seen: list[str] = []
    for chunk in _SPLIT_RE.split(raw):
        name = normalise_tag(chunk)
        if not name or len(name) < 2:
            continue
        if name not in seen:
            seen.append(name)
        if len(seen) >= MAX_TAGS_PER_POST:
            break
    return seen


def get_or_create_tags(db: Session, names: list[str]) -> list[Tag]:
    """Resolve tag names to rows, creating any that don't exist yet."""
    resolved: list[Tag] = []
    for name in names:
        slug = slugify_tag(name)
        if not slug:
            continue
        tag = db.query(Tag).filter(Tag.slug == slug).first()
        if tag is None:
            tag = Tag(name=name, slug=slug)
            db.add(tag)
            db.flush()
        resolved.append(tag)
    return resolved


def tags_to_field(tags) -> str:
    """Render a post's tags back into the comma-separated edit field."""
    return ", ".join(t.name for t in (tags or []))
