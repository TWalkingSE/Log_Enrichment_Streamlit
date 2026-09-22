"""
IOC / STIX 2.1 export helpers for SIEM and threat-intel tooling.
No external STIX library required — emits valid-enough STIX 2.1 JSON bundles.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import pandas as pd

from validators import as_bool, bool_series


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _stix_id(type_name: str) -> str:
    return f"{type_name}--{uuid.uuid4()}"


def _ip_column(df: pd.DataFrame) -> str:
    if "Ip" in df.columns:
        return "Ip"
    if "Sender IP" in df.columns:
        return "Sender IP"
    return "Ip"


def collect_ioc_candidates(df: pd.DataFrame, ip_col: Optional[str] = None) -> List[str]:
    """Indicadores distintos presentes no dado, SEM validar formato de IP.

    Difere de `enrich_service.collect_unique_ips`, que filtra por
    `is_valid_ip` porque só faz sentido consultar a API com IPs válidos.
    Aqui um valor malformado ainda é um indicador que o analista pode querer
    levar ao SIEM, então nada é descartado silenciosamente.
    """
    if df is None or getattr(df, "empty", True):
        return []
    col = ip_col or _ip_column(df)
    if col not in df.columns:
        return []
    ips = df[col].dropna().astype(str).str.strip().unique().tolist()
    return [ip for ip in ips if ip and ip.lower() not in {"nan", "none"}]


def export_ioc_list(
    df: pd.DataFrame,
    *,
    ip_col: Optional[str] = None,
    only_suspicious: bool = False,
) -> str:
    """Plain-text IOC list (one IP per line)."""
    col = ip_col or _ip_column(df)
    work = df
    if only_suspicious and work is not None and not work.empty:
        mask = bool_series(work, "Ip_Proxy") | bool_series(work, "Ip_Hospedagem")
        work = work[mask]
    ips = collect_ioc_candidates(work, col)
    return "\n".join(ips) + ("\n" if ips else "")


def export_ioc_csv(df: pd.DataFrame, *, ip_col: Optional[str] = None) -> str:
    """CSV with IP + enrichment context for SIEM ingestion."""
    col = ip_col or _ip_column(df)
    if df is None or df.empty or col not in df.columns:
        return "ip,org,asn,city,country,proxy,hosting,mobile\n"
    rows = []
    seen: Set[str] = set()
    for _, row in df.iterrows():
        ip = str(row.get(col, "")).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        rows.append({
            "ip": ip,
            "org": row.get("Ip_Dono", ""),
            "asn": row.get("Ip_AS", ""),
            "city": row.get("Ip_Cidade", ""),
            "country": row.get("Ip_Pais", ""),
            "proxy": as_bool(row.get("Ip_Proxy"), field="Ip_Proxy"),
            "hosting": as_bool(row.get("Ip_Hospedagem"), field="Ip_Hospedagem"),
            "mobile": as_bool(row.get("Ip_Movel"), field="Ip_Movel"),
        })
    out = pd.DataFrame(rows)
    return out.to_csv(index=False)


def build_stix_bundle(
    df: pd.DataFrame,
    *,
    ip_col: Optional[str] = None,
    name: str = "Log Enrichment IOCs",
    only_suspicious: bool = False,
    max_indicators: int = 5000,
) -> Dict[str, Any]:
    """
    Build a STIX 2.1 Bundle with ipv4/ipv6-addr SCOs and indicator SDOs.
    """
    col = ip_col or _ip_column(df)
    work = df if df is not None else pd.DataFrame()
    if only_suspicious and not work.empty:
        mask = bool_series(work, "Ip_Proxy") | bool_series(work, "Ip_Hospedagem")
        work = work[mask]

    now = _utcnow()
    identity_id = _stix_id("identity")
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": name,
            "identity_class": "organization",
        }
    ]

    seen: Set[str] = set()
    count = 0
    if not work.empty and col in work.columns:
        for _, row in work.iterrows():
            ip = str(row.get(col, "")).strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            if count >= max_indicators:
                break
            count += 1

            is_v6 = ":" in ip
            sco_type = "ipv6-addr" if is_v6 else "ipv4-addr"
            sco_id = _stix_id(sco_type)
            objects.append({
                "type": sco_type,
                "spec_version": "2.1",
                "id": sco_id,
                "value": ip,
            })

            labels = []
            if as_bool(row.get("Ip_Proxy"), field="Ip_Proxy"):
                labels.append("proxy")
            if as_bool(row.get("Ip_Hospedagem"), field="Ip_Hospedagem"):
                labels.append("hosting")
            if as_bool(row.get("Ip_Movel"), field="Ip_Movel"):
                labels.append("mobile")
            if not labels:
                labels.append("observed")

            # O indicador pode conter caracteres que quebram o literal do
            # pattern STIX (IOCs malformados são preservados de propósito).
            ip_pattern = ip.replace("\\", "\\\\").replace("'", "\\'")
            pattern = f"[ipv6-addr:value = '{ip_pattern}']" if is_v6 else f"[ipv4-addr:value = '{ip_pattern}']"
            desc_parts = [
                f"org={row.get('Ip_Dono', '')}",
                f"asn={row.get('Ip_AS', '')}",
                f"city={row.get('Ip_Cidade', '')}",
                f"country={row.get('Ip_Pais', '')}",
            ]
            indicator_id = _stix_id("indicator")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"IP {ip}",
                "description": "; ".join(str(p) for p in desc_parts),
                "indicator_types": ["anomalous-activity"] if ("proxy" in labels or "hosting" in labels) else ["unknown"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": labels,
                "created_by_ref": identity_id,
            })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "based-on",
                "source_ref": indicator_id,
                "target_ref": sco_id,
            })

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }


def export_stix_json(
    df: pd.DataFrame,
    *,
    ip_col: Optional[str] = None,
    name: str = "Log Enrichment IOCs",
    only_suspicious: bool = False,
    max_indicators: int = 5000,
) -> str:
    bundle = build_stix_bundle(
        df,
        ip_col=ip_col,
        name=name,
        only_suspicious=only_suspicious,
        max_indicators=max_indicators,
    )
    return json.dumps(bundle, ensure_ascii=False, indent=2)
