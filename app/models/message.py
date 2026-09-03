"""Direct messages between two users.

A message is plain text (never rendered as HTML) that one signed-in account
sends to another. `pair_key` is a stable, order-independent key for the two
participants (``"lowId:highId"``) so a conversation can be indexed and grouped
without caring who sent which message.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.database import Base


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        # The two hot queries: one conversation in order, and "my unread".
        Index("ix_messages_pair_created", "pair_key", "created_at"),
        Index("ix_messages_recipient_unread", "recipient_id", "is_read"),
    )

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    # "min(id):max(id)" — identifies the conversation regardless of direction.
    pair_key = Column(String(40), nullable=False, index=True)
    body = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
