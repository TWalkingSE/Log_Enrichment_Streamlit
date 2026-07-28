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
from pathlib import Path
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


def save_signed_cache(cache: Dict[str, Any], path: str | Path, secret: Optional[str] = None) -> Path:
    path = Path(path)
    package = build_signed_package(cache, secret=secret)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(package, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_signed_cache(path: str | Path, secret: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return False, "not_found", {}
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        return False, f"read_error:{e}", {}
    # Plain cache (unsigned) — accept only if no secret configured
    if isinstance(package, dict) and "payload" not in package and "signature" not in package:
        if secret or get_cache_hmac_secret():
            return False, "unsigned_rejected", {}
        return True, "unsigned_ok", package
    return verify_signed_package(package, secret=secret)


def is_signed_envelope(data: Any) -> bool:
    return isinstance(data, dict) and "payload" in data and "signature" in data
