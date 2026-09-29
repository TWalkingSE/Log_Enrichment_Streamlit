"""Runtime feature flags from environment / Streamlit session."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


class AirGappedError(RuntimeError):
    """Chamada de rede externa bloqueada pelo modo air-gapped."""


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _session_air_gapped():
    """Valor do toggle de sessão, ou None fora de um script Streamlit.

    Só ImportError e a ausência de contexto de execução são esperados aqui.
    O `except Exception: pass` anterior engolia qualquer erro — e um erro
    engolido aqui DESLIGAVA o modo air-gapped em silêncio.
    """
    try:
        import streamlit as st
    except ImportError:
        return None
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
    except ImportError:
        get_script_run_ctx = None
    if get_script_run_ctx is not None and get_script_run_ctx(suppress_warning=True) is None:
        return None
    value = st.session_state.get("air_gapped")
    return None if value is None else bool(value)


def is_air_gapped() -> bool:
    """
    When True, enrichment must not call external HTTP APIs.
    Only local cache / offline data is used.
    """
    session_value = _session_air_gapped()
    if session_value is not None:
        return session_value
    return _env_truthy("AIR_GAPPED", False)


def ensure_network_allowed(service: str) -> None:
    """Levanta `AirGappedError` se o modo air-gapped estiver ativo.

    Antes só o IP-API respeitava o modo: VirusTotal, AbuseIPDB, Shodan e a
    atualização da lista Tor saíam para a rede mesmo com ele ligado.
    """
    if is_air_gapped():
        logger.warning("Air-gapped: chamada externa bloqueada (%s)", service)
        raise AirGappedError(
            f"Modo air-gapped ativo: consulta a {service} bloqueada. "
            "Desative o modo em Configurações para usar serviços externos.")


def retention_enabled() -> bool:
    return _env_truthy("RETENTION_ON_STARTUP", True)
