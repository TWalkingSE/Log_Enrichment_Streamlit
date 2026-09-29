"""
HMAC-signed IP cache packages for air-gapped / offline transfer.

Envelope format (JSON):
{
  "version": 1,
  "created_at": "...",
  "entry_count": N,
  "payload": { "<ip>": {...}, ... },
  "signature": "<hex hmac-sha256 of canonical payload>"
}

Secret: CACHE_HMAC_SECRET env (or AUDIT_HMAC_SECRET fallback).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional, Tuple


def get_cache_hmac_secret() -> Optional[str]:
    secret = os.getenv("CACHE_HMAC_SECRET") or os.getenv("AUDIT_HMAC_SECRET")
    if secret and secret.strip():
        return secret.strip()
    return None


def _canonical_payload(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_payload(payload: Dict[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), _canonical_payload(payload), hashlib.sha256).hexdigest()


def build_signed_package(cache: Dict[str, Any], secret: Optional[str] = None) -> Dict[str, Any]:
    secret = secret or get_cache_hmac_secret()
    if not secret:
        raise ValueError("CACHE_HMAC_SECRET (or AUDIT_HMAC_SECRET) required to sign cache")
    payload = dict(cache)
    return {
        "version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "entry_count": len(payload),
        "payload": payload,
        "signature": sign_payload(payload, secret),
    }


def verify_signed_package(
    package: Dict[str, Any],
    secret: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Returns (ok, message, payload_dict).
    """
    secret = secret or get_cache_hmac_secret()
    if not secret:
        return False, "no_secret", {}
    if not isinstance(package, dict):
        return False, "invalid_package", {}
    payload = package.get("payload")
    sig = package.get("signature")
    if not isinstance(payload, dict) or not isinstance(sig, str):
        return False, "missing_fields", {}
    expected = sign_payload(payload, secret)
    if not hmac.compare_digest(expected, sig):
        return False, "bad_signature", {}
    return True, "ok", payload


def is_signed_envelope(data: Any) -> bool:
    return isinstance(data, dict) and "payload" in data and "signature" in data
