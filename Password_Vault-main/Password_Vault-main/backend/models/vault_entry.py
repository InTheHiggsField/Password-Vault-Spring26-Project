from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, Integer, DateTime, ForeignKey, LargeBinary, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base

if TYPE_CHECKING:
    from .user import User


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    # Foreign key to users.id — cascade delete so entries are cleaned up with the user
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Plaintext account label (e.g. "Netflix", "Gmail") — displayable without decryption
    account: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # AES-GCM ciphertext (encrypted password + GCM auth tag)
    password: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    # AES-GCM nonce — must be 12 bytes, unique per encryption
    iv: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    # PBKDF2 salt — must be 16 bytes minimum
    salt: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationship back to User
    user: Mapped["User"] = relationship(back_populates="vault_entries")