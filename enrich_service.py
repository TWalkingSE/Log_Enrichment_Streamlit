"""
Shared IP enrichment service.
Unifies batch lookup + cache for access logs and interception pipelines.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import aiohttp
import pandas as pd

from api_client import IPAPIClient, is_valid_ip

logger = logging.getLogger(__name__)

ProgressCb = Optional[Callable[[int, int], None]]
UpdateCb = Optional[Callable[[str], None]]


def collect_unique_ips(df: pd.DataFrame, ip_col: str) -> List[str]:
    """Extract unique valid IPs from a DataFrame column."""
    if df is None or df.empty or ip_col not in df.columns:
        return []
    ips = df[ip_col].dropna().astype(str).unique().tolist()
    return [ip for ip in ips if is_valid_ip(ip)]


async def enrich_ips(
    ips: Iterable[str],
    *,
    cache_file: Optional[str] = 'ip_cache.json',
    api_key: Optional[str] = None,
    batch_size: int = 500,
    period: int = 0,
    update_callback: UpdateCb = None,
    progress_callback: ProgressCb = None,
    save_cache: bool = True,
) -> Tuple[Dict[str, dict], IPAPIClient]:
    """
    Enrich a list of IPs via IPAPIClient batch endpoint (cache-aware).

    Returns:
        (results_by_ip, client)
    """
    unique = [ip for ip in dict.fromkeys(ips) if is_valid_ip(ip)]
    client = IPAPIClient(
        batch_size=batch_size,
        period=period,
        cache_file=cache_file,
        api_key=api_key,
    )

    if not unique:
        if update_callback:
            update_callback("Nenhum IP válido para enriquecer")
        return {}, client

    if update_callback:
        update_callback(f"Enriquecendo {len(unique)} IPs únicos...")

    async with aiohttp.ClientSession() as session:
        results = await client.consultar_batch(
            session,
            unique,
            callback=update_callback,
            progress_callback=progress_callback,
        )

    if save_cache and cache_file:
        client.salvar_cache()
        if update_callback:
            update_callback(
                f"Cache: {client.cache_hits} hits, {client.cache_misses} misses"
            )

    return results, client


async def enrich_dataframe(
    df: pd.DataFrame,
    ip_col: str,
    *,
    cache_file: Optional[str] = 'ip_cache.json',
    api_key: Optional[str] = None,
    batch_size: int = 500,
    period: int = 0,
    update_callback: UpdateCb = None,
    progress_callback: ProgressCb = None,
    apply_results: Optional[Callable[[pd.DataFrame, Dict[str, dict]], pd.DataFrame]] = None,
    save_cache: bool = True,
) -> Tuple[pd.DataFrame, Dict[str, dict]]:
    """
    Enrich DataFrame IPs and optionally merge results via apply_results(df, results).
    """
    ips = collect_unique_ips(df, ip_col)
    results, _client = await enrich_ips(
        ips,
        cache_file=cache_file,
        api_key=api_key,
        batch_size=batch_size,
        period=period,
        update_callback=update_callback,
        progress_callback=progress_callback,
        save_cache=save_cache,
    )
    if apply_results is not None and results:
        df = apply_results(df, results)
    return df, results
