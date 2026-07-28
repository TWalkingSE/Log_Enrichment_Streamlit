"""
A/B period comparison for enriched log DataFrames.
Splits by date range and compares volume / infra / geo KPIs.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, Optional, Tuple

import pandas as pd


def _parse_dates(df: pd.DataFrame, date_col: str = "Data") -> pd.DataFrame:
    out = df.copy()
    out["_dt"] = pd.to_datetime(out[date_col], format="mixed", errors="coerce")
    return out.dropna(subset=["_dt"])


def slice_period(
    df: pd.DataFrame,
    start: date | datetime,
    end: date | datetime,
    *,
    date_col: str = "Data",
) -> pd.DataFrame:
    if df is None or df.empty or date_col not in df.columns:
        return pd.DataFrame()
    work = _parse_dates(df, date_col)
    start_ts = pd.Timestamp(start)
    end_ts = pd.Timestamp(end) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
    return work[(work["_dt"] >= start_ts) & (work["_dt"] <= end_ts)].drop(columns=["_dt"], errors="ignore")


def period_kpis(df: pd.DataFrame, *, ip_col: Optional[str] = None) -> Dict[str, Any]:
    if df is None or df.empty:
        return {
            "records": 0,
            "unique_ips": 0,
            "providers": 0,
            "countries": 0,
            "cities": 0,
            "proxy_pct": 0.0,
            "hosting_pct": 0.0,
            "mobile_pct": 0.0,
            "top_providers": {},
            "top_countries": {},
        }
    col = ip_col or ("Sender IP" if "Sender IP" in df.columns else "Ip")
    n = len(df)
    proxy_pct = float(df["Ip_Proxy"].astype(bool).sum() / n * 100) if "Ip_Proxy" in df.columns else 0.0
    host_pct = float(df["Ip_Hospedagem"].astype(bool).sum() / n * 100) if "Ip_Hospedagem" in df.columns else 0.0
    mobile_pct = float(df["Ip_Movel"].astype(bool).sum() / n * 100) if "Ip_Movel" in df.columns else 0.0
    top_prov = df["Ip_Dono"].value_counts().head(5).to_dict() if "Ip_Dono" in df.columns else {}
    top_ctry = df["Ip_Pais"].value_counts().head(5).to_dict() if "Ip_Pais" in df.columns else {}
    return {
        "records": n,
        "unique_ips": int(df[col].nunique()) if col in df.columns else 0,
        "providers": int(df["Ip_Dono"].dropna().nunique()) if "Ip_Dono" in df.columns else 0,
        "countries": int(df["Ip_Pais"].dropna().nunique()) if "Ip_Pais" in df.columns else 0,
        "cities": int(df["Ip_Cidade"].dropna().nunique()) if "Ip_Cidade" in df.columns else 0,
        "proxy_pct": round(proxy_pct, 1),
        "hosting_pct": round(host_pct, 1),
        "mobile_pct": round(mobile_pct, 1),
        "top_providers": {str(k): int(v) for k, v in top_prov.items()},
        "top_countries": {str(k): int(v) for k, v in top_ctry.items()},
    }


def _delta(a: float, b: float) -> float:
    return round(b - a, 1)


def compare_periods(
    df: pd.DataFrame,
    period_a: Tuple[date, date],
    period_b: Tuple[date, date],
    *,
    date_col: str = "Data",
    ip_col: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compare KPIs between period A and period B.
    Returns dict with kpis_a, kpis_b, deltas, and sliced frames sizes.
    """
    df_a = slice_period(df, period_a[0], period_a[1], date_col=date_col)
    df_b = slice_period(df, period_b[0], period_b[1], date_col=date_col)
    ka = period_kpis(df_a, ip_col=ip_col)
    kb = period_kpis(df_b, ip_col=ip_col)

    metric_keys = [
        "records", "unique_ips", "providers", "countries", "cities",
        "proxy_pct", "hosting_pct", "mobile_pct",
    ]
    deltas = {k: _delta(float(ka[k]), float(kb[k])) for k in metric_keys}

    # IPs only in A / only in B
    col = ip_col or ("Sender IP" if "Sender IP" in df.columns else "Ip")
    set_a = set(df_a[col].astype(str)) if col in df_a.columns and not df_a.empty else set()
    set_b = set(df_b[col].astype(str)) if col in df_b.columns and not df_b.empty else set()

    return {
        "kpis_a": ka,
        "kpis_b": kb,
        "deltas": deltas,
        "ips_only_a": sorted(set_a - set_b)[:50],
        "ips_only_b": sorted(set_b - set_a)[:50],
        "ips_shared": len(set_a & set_b),
        "count_a": len(df_a),
        "count_b": len(df_b),
    }


def date_bounds(df: pd.DataFrame, date_col: str = "Data") -> Optional[Tuple[date, date]]:
    if df is None or df.empty or date_col not in df.columns:
        return None
    work = _parse_dates(df, date_col)
    if work.empty:
        return None
    return work["_dt"].min().date(), work["_dt"].max().date()
