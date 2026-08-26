"""User model."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False, index=True)  # user | tester | admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_tester(self) -> bool:
        return self.role in ("tester", "admin")
