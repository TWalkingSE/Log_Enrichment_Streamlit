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
from typing import Any, Dict, Optional

from helpers.atomic_io import atomic_write_json, atomic_write_text

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _archive_path(path: Path) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.stem}.{stamp}{path.suffix}")
    n = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}.{stamp}-{n}{path.suffix}")
        n += 1
    return candidate


def prune_jsonl_by_age_and_lines(
    path: Path,
    *,
    max_age_days: int,
    max_lines: int,
    timestamp_key: str = "timestamp",
) -> Dict[str, Any]:
    """Keep last max_lines and drop events older than max_age_days (if timestamp parseable).

    Nada é apagado: as linhas removidas vão, inalteradas, para
    `<nome>.<AAAAMMDD-HHMMSS>.jsonl` ao lado do arquivo (retorno `archive`),
    e as mantidas permanecem byte a byte. `anchor_hash` é o `event_hash` da
    última linha arquivada. Ambas as escritas são atômicas.

    Timestamp ilegível mantém a linha: sem idade conhecida, não há base para
    descartá-la.
    """
    if not path.exists() or max_lines <= 0:
        return {"kept": 0, "removed": 0}

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        logger.warning("retention: cannot read %s: %s", path, e)
        return {"kept": 0, "removed": 0}

    from datetime import datetime

    cutoff = time.time() - max_age_days * 86400 if max_age_days > 0 else None
    kept: list[str] = []
    dropped: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        drop = False
        if cutoff is not None:
            try:
                ts = json.loads(line).get(timestamp_key)
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    drop = dt.timestamp() < cutoff
            except (ValueError, TypeError, AttributeError):
                logger.warning("retention: timestamp ilegível em %s; linha mantida", path)
        (dropped if drop else kept).append(line)

    if max_lines and len(kept) > max_lines:
        dropped.extend(kept[:-max_lines])
        kept = kept[-max_lines:]

    if not dropped:
        return {"kept": len(kept), "removed": 0}

    anchor_hash = None
    try:
        anchor_hash = json.loads(dropped[-1]).get("event_hash")
    except (ValueError, AttributeError):
        logger.warning("retention: última linha arquivada de %s não é JSON válido", path)

    archive = _archive_path(path)
    try:
        # Arquivamento primeiro: se a segunda escrita falhar, nada se perdeu.
        atomic_write_text(archive, "\n".join(dropped) + "\n")
        atomic_write_text(path, "\n".join(kept) + ("\n" if kept else ""))
    except OSError:
        logger.exception("retention: falha ao arquivar/regravar %s", path)
        return {"kept": len(kept) + len(dropped), "removed": 0}

    return {"kept": len(kept), "removed": len(dropped),
            "archive": str(archive), "anchor_hash": anchor_hash}


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


def prune_ip_cache(cache_path: Path, max_age_days: int) -> Dict[str, Any]:
    """Drop cache entries older than max_age_days based on _cached_at.

    Cache assinado (envelope HMAC) não é podado: remover entradas invalidaria
    a assinatura. Antes as chaves do envelope eram tratadas como IPs e o
    arquivo era regravado como `{"payload": ...}` — assinatura e cache
    destruídos.
    """
    if not cache_path.exists() or max_age_days <= 0:
        return {"kept": 0, "removed": 0}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("retention: cache ilegível %s", cache_path)
        return {"kept": 0, "removed": 0}
    if not isinstance(raw, dict):
        return {"kept": 0, "removed": 0}
    from helpers.signed_cache import is_signed_envelope
    if is_signed_envelope(raw):
        logger.info("retention: cache assinado não é podado (%s)", cache_path)
        return {"kept": len(raw.get("payload") or {}), "removed": 0, "skipped": "signed"}

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
            atomic_write_json(cache_path, kept)
        except OSError:
            logger.exception("retention: não foi possível regravar o cache")
            return {"kept": len(raw), "removed": 0}
    return {"kept": len(kept), "removed": removed}


def run_retention(
    *,
    audit_max_age_days: Optional[int] = None,
    audit_max_lines: Optional[int] = None,
    sessions_max_age_days: Optional[int] = None,
    cache_max_age_days: Optional[int] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
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

    summary: Dict[str, Any] = {}
    if dry_run:
        summary["dry_run"] = True
        return summary

    import audit_logger
    summary["audit"] = audit_logger.archive_old_events(audit_max_age_days, audit_max_lines)

    sessions_dir = ROOT / "data" / "sessions"
    summary["sessions"] = prune_directory_by_mtime(
        sessions_dir,
        sessions_max_age_days,
        patterns=("*.parquet", "*.pkl", "*.meta.json"),
    )

    from api_client import IP_CACHE_PATH
    summary["ip_cache"] = prune_ip_cache(Path(IP_CACHE_PATH), cache_max_age_days)

    logger.info("retention summary: %s", summary)
    return summary
