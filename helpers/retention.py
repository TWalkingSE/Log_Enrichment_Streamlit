"""
Retention policies for audit trail, session data, logs and IP cache.
Safe to run at startup or via scripts/retention_cleanup.py.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def prune_jsonl_by_age_and_lines(
    path: Path,
    *,
    max_age_days: int,
    max_lines: int,
    timestamp_key: str = "timestamp",
) -> Dict[str, int]:
    """Keep last max_lines and drop events older than max_age_days (if timestamp parseable)."""
    if not path.exists() or max_lines <= 0:
        return {"kept": 0, "removed": 0}

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning("retention: cannot read %s: %s", path, e)
        return {"kept": 0, "removed": 0}

    cutoff = time.time() - max_age_days * 86400 if max_age_days > 0 else None
    kept = []
    removed = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        drop = False
        if cutoff is not None:
            try:
                obj = json.loads(line)
                ts = obj.get(timestamp_key)
                if isinstance(ts, str):
                    # ISO timestamp
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if dt.timestamp() < cutoff:
                        drop = True
            except Exception:
                pass
        if drop:
            removed += 1
        else:
            kept.append(line)

    if max_lines and len(kept) > max_lines:
        removed += len(kept) - max_lines
        kept = kept[-max_lines:]

    if removed:
        try:
            path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        except OSError as e:
            logger.error("retention: cannot write %s: %s", path, e)
            return {"kept": len(kept), "removed": 0}

    return {"kept": len(kept), "removed": removed}


def prune_directory_by_mtime(directory: Path, max_age_days: int, patterns=("*",)) -> Dict[str, int]:
    if not directory.exists() or max_age_days <= 0:
        return {"removed": 0, "kept": 0}
    cutoff = time.time() - max_age_days * 86400
    removed = 0
    kept = 0
    for pattern in patterns:
        for p in directory.glob(pattern):
            if not p.is_file():
                continue
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    removed += 1
                else:
                    kept += 1
            except OSError as e:
                logger.warning("retention: skip %s: %s", p, e)
    return {"removed": removed, "kept": kept}


def prune_ip_cache(cache_path: Path, max_age_days: int) -> Dict[str, int]:
    """Drop cache entries older than max_age_days based on _cached_at."""
    if not cache_path.exists() or max_age_days <= 0:
        return {"kept": 0, "removed": 0}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("retention: bad cache %s: %s", cache_path, e)
        return {"kept": 0, "removed": 0}
    if not isinstance(raw, dict):
        return {"kept": 0, "removed": 0}

    cutoff = time.time() - max_age_days * 86400
    kept = {}
    removed = 0
    for ip, entry in raw.items():
        if not isinstance(entry, dict):
            removed += 1
            continue
        ts = entry.get("_cached_at", 0) or 0
        if ts and ts < cutoff:
            removed += 1
        else:
            kept[ip] = entry
    if removed:
        try:
            cache_path.write_text(json.dumps(kept), encoding="utf-8")
        except OSError as e:
            logger.error("retention: cannot rewrite cache: %s", e)
            return {"kept": len(raw), "removed": 0}
    return {"kept": len(kept), "removed": removed}


def run_retention(
    *,
    audit_max_age_days: Optional[int] = None,
    audit_max_lines: Optional[int] = None,
    sessions_max_age_days: Optional[int] = None,
    cache_max_age_days: Optional[int] = None,
    dry_run: bool = False,
) -> Dict[str, dict]:
    """Apply configured retention policies. Returns summary."""
    audit_max_age_days = (
        audit_max_age_days
        if audit_max_age_days is not None
        else _int_env("RETENTION_AUDIT_DAYS", 90)
    )
    audit_max_lines = (
        audit_max_lines
        if audit_max_lines is not None
        else _int_env("RETENTION_AUDIT_MAX_LINES", 50000)
    )
    sessions_max_age_days = (
        sessions_max_age_days
        if sessions_max_age_days is not None
        else _int_env("RETENTION_SESSIONS_DAYS", 30)
    )
    cache_max_age_days = (
        cache_max_age_days
        if cache_max_age_days is not None
        else _int_env("RETENTION_CACHE_DAYS", 30)
    )

    summary: Dict[str, dict] = {}
    if dry_run:
        summary["dry_run"] = True
        return summary

    audit_path = ROOT / "logs" / "audit_trail.jsonl"
    summary["audit"] = prune_jsonl_by_age_and_lines(
        audit_path,
        max_age_days=audit_max_age_days,
        max_lines=audit_max_lines,
    )

    sessions_dir = ROOT / "data" / "sessions"
    summary["sessions"] = prune_directory_by_mtime(
        sessions_dir,
        sessions_max_age_days,
        patterns=("*.parquet", "*.pkl", "*.meta.json"),
    )

    cache_path = ROOT / "ip_cache.json"
    summary["ip_cache"] = prune_ip_cache(cache_path, cache_max_age_days)

    logger.info("retention summary: %s", summary)
    return summary
