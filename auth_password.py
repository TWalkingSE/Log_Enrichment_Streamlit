"""Password verification for optional Streamlit auth (Argon2 preferred, bcrypt accepted).

Usa `argon2-cffi` e `bcrypt` diretamente: o `passlib`, usado antes, não é mais
mantido. Os hashes que ele gerava (`$argon2id$...`, `$2b$...`) são o formato
padrão e continuam sendo aceitos sem regerar nada.

O formato legado — SHA-256 hex sem salt — **não é mais aceito**: é rápido de
atacar por força bruta e igual para senhas iguais. `is_legacy_sha256_hash`
existe para a tela de login dizer isso explicitamente, em vez de um "senha
incorreta" que ninguém saberia explicar.
"""

from __future__ import annotations

import hashlib
import re
import secrets

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_LEGACY_SHA256_HEX = re.compile(r'^[0-9a-fA-F]{64}$')
_BCRYPT_PREFIXES = ('$2a$', '$2b$', '$2y$')

_hasher = PasswordHasher()


def is_legacy_sha256_hash(stored: str) -> bool:
    """True para o formato antigo (SHA-256 hex sem salt), que foi descontinuado."""
    return bool(stored) and bool(_LEGACY_SHA256_HEX.match(stored.strip()))


def hash_password(plain: str) -> str:
    """Hash Argon2id para AUTH_PASSWORD_HASH."""
    return _hasher.hash(plain)


def verify_stored_password_hash(plain: str, stored: str) -> bool:
    """
    Verify plain password against AUTH_PASSWORD_HASH.
    Supported formats:
    - Argon2 (`$argon2id$`, `$argon2i$`, `$argon2d$`)
    - bcrypt (`$2a$`, `$2b$`, `$2y$`)
    O SHA-256 hex legado devolve False (ver `is_legacy_sha256_hash`).
    """
    if not stored or plain is None:
        return False
    stored = stored.strip()
    if stored.startswith('$argon2'):
        try:
            return _hasher.verify(stored, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    if stored.startswith(_BCRYPT_PREFIXES):
        # A biblioteca `bcrypt` não conhece o prefixo `$2y$` (PHP); o algoritmo
        # é o mesmo do `$2b$`.
        normalizado = '$2b$' + stored[4:] if stored.startswith('$2y$') else stored
        try:
            return bcrypt.checkpw(plain.encode('utf-8'), normalizado.encode('utf-8'))
        except ValueError:
            return False
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
