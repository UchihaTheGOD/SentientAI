"""Pagination helper shared by every list view.

Returns a small object the templates can render directly, so the pager markup
lives in one partial (`app/templates/partials/pagination.html`) instead of being
re-invented per page.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
from typing import Any, Sequence

DEFAULT_PER_PAGE = 12
MAX_PER_PAGE = 50


@dataclass
class Page:
    items: list[Any] = field(default_factory=list)
    page: int = 1
    per_page: int = DEFAULT_PER_PAGE
    total: int = 0

    @property
    def pages(self) -> int:
        return max(1, ceil(self.total / self.per_page)) if self.per_page else 1

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def prev_page(self) -> int:
        return max(1, self.page - 1)

    @property
    def next_page(self) -> int:
        return min(self.pages, self.page + 1)

    @property
    def start_index(self) -> int:
        return 0 if not self.total else (self.page - 1) * self.per_page + 1

    @property
    def end_index(self) -> int:
        return min(self.total, self.page * self.per_page)

    @property
    def window(self) -> list[int | None]:
        """Page numbers to render, with `None` marking an elision gap."""
        total = self.pages
        if total <= 7:
            return list(range(1, total + 1))
        current = self.page
        keep = {1, total, current}
        for offset in (1, 2):
            keep.add(max(1, current - offset))
            keep.add(min(total, current + offset))
        ordered = sorted(keep)
        out: list[int | None] = []
        previous = 0
        for number in ordered:
            if previous and number - previous > 1:
                out.append(None)
            out.append(number)
            previous = number
        return out

    @property
    def is_empty(self) -> bool:
        return not self.items


def clamp_page(page: int | None) -> int:
    try:
        value = int(page or 1)
    except (TypeError, ValueError):
        return 1
    return max(1, min(value, 10_000))


def clamp_per_page(per_page: int | None, default: int = DEFAULT_PER_PAGE) -> int:
    try:
        value = int(per_page or default)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, MAX_PER_PAGE))


def paginate(query, page: int | None = 1, per_page: int = DEFAULT_PER_PAGE) -> Page:
    """Paginate a SQLAlchemy query with a single COUNT plus one windowed SELECT."""
    page_number = clamp_page(page)
    size = clamp_per_page(per_page, per_page)
    total = query.order_by(None).count()
    pages = max(1, ceil(total / size)) if total else 1
    if page_number > pages:
        page_number = pages
    items = query.limit(size).offset((page_number - 1) * size).all()
    return Page(items=list(items), page=page_number, per_page=size, total=total)


def paginate_list(rows: Sequence[Any], page: int | None = 1,
                  per_page: int = DEFAULT_PER_PAGE) -> Page:
    """Paginate an already-materialised sequence (used where SQL can't sort)."""
    page_number = clamp_page(page)
    size = clamp_per_page(per_page, per_page)
    total = len(rows)
    pages = max(1, ceil(total / size)) if total else 1
    if page_number > pages:
        page_number = pages
    start = (page_number - 1) * size
    return Page(items=list(rows[start:start + size]), page=page_number,
                per_page=size, total=total)
