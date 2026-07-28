"""Adapter wrapping IPAPIClient for application layer."""

from __future__ import annotations

from typing import Optional

from api_client import IPAPIClient


def build_ip_client(
    *,
    cache_file: Optional[str] = "ip_cache.json",
    api_key: Optional[str] = None,
    batch_size: int = 500,
    period: int = 0,
    air_gapped: Optional[bool] = None,
) -> IPAPIClient:
    return IPAPIClient(
        batch_size=batch_size,
        period=period,
        cache_file=cache_file,
        api_key=api_key,
        air_gapped=air_gapped,
    )
