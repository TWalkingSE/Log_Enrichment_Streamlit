"""
Optional disk persistence for enriched DataFrames outside Streamlit session_state.
Prefers parquet (pyarrow/fastparquet); falls back to pickle.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "data" / "sessions"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name(name: str) -> str:
    cleaned = _SAFE_NAME.sub("_", (name or "current").strip())[:80]
    return cleaned or "current"


def session_paths(name: str = "current") -> dict:
    base = DATA_DIR / _safe_name(name)
    return {
        "parquet": base.with_suffix(".parquet"),
        "pickle": base.with_suffix(".pkl"),
        "meta": base.with_suffix(".meta.json"),
    }


def save_dataframe(df: Optional[pd.DataFrame], name: str = "current") -> Optional[str]:
    """Persist DataFrame; returns path written or None."""
    if df is None or getattr(df, "empty", True):
        return None
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    paths = session_paths(name)
    try:
        df.to_parquet(paths["parquet"], index=False)
        logger.info("DataFrame salvo em %s (%s linhas)", paths["parquet"], len(df))
        return str(paths["parquet"])
    except Exception as e:
        logger.debug("Parquet indisponível (%s); usando pickle", e)
        try:
            df.to_pickle(paths["pickle"])
            logger.info("DataFrame salvo em %s (%s linhas)", paths["pickle"], len(df))
            return str(paths["pickle"])
        except Exception as e2:
            logger.error("Falha ao persistir DataFrame: %s", e2)
            return None


def load_dataframe(name: str = "current") -> Optional[pd.DataFrame]:
    """Load last persisted DataFrame if present."""
    paths = session_paths(name)
    if paths["parquet"].exists():
        try:
            return pd.read_parquet(paths["parquet"])
        except Exception as e:
            logger.warning("Falha ao ler parquet %s: %s", paths["parquet"], e)
    if paths["pickle"].exists():
        try:
            return pd.read_pickle(paths["pickle"])
        except Exception as e:
            logger.warning("Falha ao ler pickle %s: %s", paths["pickle"], e)
    return None


def clear_dataframe(name: str = "current") -> None:
    paths = session_paths(name)
    for p in paths.values():
        try:
            if p.exists():
                p.unlink()
        except OSError as e:
            logger.warning("Não foi possível remover %s: %s", p, e)
