"""
User model for authentication system.

Responsibilities:
- Store account credentials (bcrypt hashed)
- Enforce unique email constraint
- Provide timestamp tracking
- Define relationship to VaultEntry
"""

from datetime import datetime
from typing import List

from sqlalchemy import String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

#from backend.models.vault_entry import VaultEntry
from backend.app.database import Base

from typing import List, TYPE_CHECKING
if TYPE_CHECKING:
    from .vault_entry import VaultEntry # This prevents the crash
    
    
class User(Base):
    __tablename__ = "users"

    # Primary Key
    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True
    )

    # Email (login identifier)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )

    username: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )

    # Bcrypt hash of account password
    password: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    # Cryptographically random 16-byte salt (stored as hex: 32 chars)
    # Used for PBKDF2 key derivation on the frontend
    # Generated during registration, retrieved during login
    salt: Mapped[str] = mapped_column(
        String(32),  # 16 bytes = 32 hex characters
        nullable=True  # Allow NULL temporarily for backfill during migration
    )

    # Timestamp fields
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # Relationship to vault entries
    vault_entries: Mapped[List["VaultEntry"]] = relationship(
        "VaultEntry",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
    
    