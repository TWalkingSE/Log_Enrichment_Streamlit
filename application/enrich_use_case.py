"""
Enrichment use-case facade.
UI / workers call this instead of reaching into api_client directly.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from enrich_service import collect_unique_ips, enrich_dataframe, enrich_ips


async def enrich_ip_list(
    ips: Iterable[str],
    *,
    cache_file: Optional[str] = "ip_cache.json",
    api_key: Optional[str] = None,
    batch_size: int = 500,
    period: int = 0,
    update_callback: Optional[Callable[[str], None]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    save_cache: bool = True,
) -> Tuple[Dict[str, dict], object]:
    return await enrich_ips(
        ips,
        cache_file=cache_file,
        api_key=api_key,
        batch_size=batch_size,
        period=period,
        update_callback=update_callback,
        progress_callback=progress_callback,
        save_cache=save_cache,
    )


async def enrich_df(
    df: pd.DataFrame,
    ip_col: str,
    **kwargs,
) -> Tuple[pd.DataFrame, Dict[str, dict]]:
    return await enrich_dataframe(df, ip_col, **kwargs)


def unique_ips(df: pd.DataFrame, ip_col: str) -> List[str]:
    return collect_unique_ips(df, ip_col)
