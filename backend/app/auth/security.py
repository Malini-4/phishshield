"""
Authentication utilities: password hashing and JWT token management.
Uses bcrypt for password hashing (via passlib) and HS256 JWT tokens.
"""
from __future__ import annotations

import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Password hashing ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    import bcrypt
    pwd_bytes = plain.encode('utf-8')[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    import bcrypt
    try:
        pwd_bytes = plain.encode('utf-8')[:72]
        hashed_bytes = hashed.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False


# ── JWT tokens ───────────────────────────────────────────────────────────────

def _get_secret_key() -> str:
    """Read the JWT secret from the environment; generate a warning if missing."""
    key = ""
    try:
        from app.config import get_settings
        key = get_settings().JWT_SECRET_KEY or ""
    except Exception:
        pass
    if not key:
        key = os.environ.get("JWT_SECRET_KEY", "")
    if not key:
        # In development, accept a hardcoded-looking but actually random default.
        # The default will change every restart – users will be logged out.
        logger.warning(
            "JWT_SECRET_KEY is not set. Using an ephemeral key. "
            "Set JWT_SECRET_KEY in .env for persistent sessions."
        )
        # Use a stable fallback that survives the process lifetime
        if not hasattr(_get_secret_key, "_fallback"):
            _get_secret_key._fallback = secrets.token_hex(32)  # type: ignore[attr-defined]
        return _get_secret_key._fallback  # type: ignore[attr-defined]
    return key


ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours


def create_access_token(user_id: str, email: str) -> str:
    """Create a signed JWT access token."""
    try:
        from jose import jwt
    except ImportError:
        raise RuntimeError(
            "python-jose[cryptography] is required. "
            "Install it: pip install 'python-jose[cryptography]'"
        )

    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, _get_secret_key(), algorithm="HS256")


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT access token. Returns payload dict or None."""
    try:
        from jose import jwt, JWTError
        payload = jwt.decode(token, _get_secret_key(), algorithms=["HS256"])
        return payload
    except Exception:
        return None
