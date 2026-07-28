"""Runtime feature flags from environment / Streamlit session."""

from __future__ import annotations

import os


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def is_air_gapped() -> bool:
    """
    When True, enrichment must not call external HTTP APIs.
    Only local cache / offline data is used.
    """
    try:
        import streamlit as st
        if st.session_state.get("air_gapped") is not None:
            return bool(st.session_state.get("air_gapped"))
    except Exception:
        pass
    return _env_truthy("AIR_GAPPED", False)


def retention_enabled() -> bool:
    return _env_truthy("RETENTION_ON_STARTUP", True)
