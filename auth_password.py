"""Password verification for optional Streamlit auth (Argon2/bcrypt preferred, legacy SHA-256 hex)."""

from __future__ import annotations

import hashlib
import re
import secrets

from passlib.hash import argon2, bcrypt

_LEGACY_SHA256_HEX = re.compile(r'^[0-9a-fA-F]{64}$')


def verify_stored_password_hash(plain: str, stored: str) -> bool:
    """
    Verify plain password against AUTH_PASSWORD_HASH.
    Supported formats:
    - Argon2 (passlib string starting with $argon2)
    - bcrypt ($2a$, $2b$, $2y$)
    - Legacy: 64-char hex SHA-256 of UTF-8 password (timing-safe compare)
    """
    if not stored or plain is None:
        return False
    stored = stored.strip()
    if stored.startswith('$argon2'):
        try:
            return argon2.verify(plain, stored)
        except (ValueError, TypeError):
            return False
    if stored.startswith('$2a$') or stored.startswith('$2b$') or stored.startswith('$2y$'):
        try:
            return bcrypt.verify(plain, stored)
        except ValueError:
            return False
    if _LEGACY_SHA256_HEX.match(stored):
        digest = hashlib.sha256(plain.encode('utf-8')).hexdigest()
        return secrets.compare_digest(digest.lower(), stored.lower())
    return False


def verify_plain_env_password(plain: str, env_plain: str) -> bool:
    """
    Backward-compatible check for AUTH_PASSWORD in .env (plaintext).
    Compares SHA-256 hex digests with timing-safe equality.
    Prefer AUTH_PASSWORD_HASH with Argon2 instead of plaintext env.
    """
    if not env_plain:
        return False
    d_plain = hashlib.sha256(plain.encode('utf-8')).hexdigest()
    d_env = hashlib.sha256(env_plain.encode('utf-8')).hexdigest()
    return secrets.compare_digest(d_plain, d_env)
