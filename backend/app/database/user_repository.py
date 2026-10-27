"""
User repository – CRUD operations for the users table.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.user_model import User
from app.auth.security import hash_password, verify_password

logger = logging.getLogger(__name__)


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Return a user by case-insensitive email, or None."""
    return db.execute(
        select(User).where(User.email == email.lower().strip())
    ).scalar_one_or_none()


def get_user_by_id(db: Session, user_id: str) -> Optional[dict]:
    """Return a minimal user dict (no password) by ID, or None."""
    user = db.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()
    if not user:
        return None
    return {"id": user.id, "email": user.email, "full_name": user.full_name}


def create_user(db: Session, email: str, full_name: str, plain_password: str) -> User:
    """Create and persist a new user. Raises ValueError on duplicate email."""
    norm_email = email.lower().strip()
    existing = get_user_by_email(db, norm_email)
    if existing:
        raise ValueError("An account with this email address already exists.")

    user = User(
        email=norm_email,
        full_name=full_name.strip(),
        hashed_password=hash_password(plain_password),
    )
    db.add(user)
    db.flush()
    logger.info(f"Created user {user.id} ({norm_email})")
    return user


def authenticate_user(db: Session, email: str, plain_password: str) -> Optional[User]:
    """Return the User if credentials are valid, else None."""
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(plain_password, user.hashed_password):
        return None
    return user
