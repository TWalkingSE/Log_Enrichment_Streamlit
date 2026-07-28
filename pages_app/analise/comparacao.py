"""
Análise Avançada - Comparação A/B de períodos
"""

from __future__ import annotations

from datetime import timedelta

import pandas as pd
import streamlit as st

from helpers.period_compare import compare_periods, date_bounds
from i18n import t


def page_comparacao():
    from styles.components import section_header, empty_state

    section_header(t("comparacao.title"), t("comparacao.subtitle"), divider="orange")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t("comparacao.no_data"), "⚖️", t("common.process_data_first"))
        return

    if "Data" not in df.columns:
        st.warning(t("comparacao.no_date_col"))
        return

    bounds = date_bounds(df)
    if not bounds:
        st.warning(t("comparacao.no_valid_dates"))
        return

    min_d, max_d = bounds
    span = max((max_d - min_d).days, 1)
    mid = min_d + timedelta(days=span // 2)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**{t('comparacao.period_a')}**")
        a_start = st.date_input(t("comparacao.start"), value=min_d, min_value=min_d, max_value=max_d, key="ab_a_start")
        a_end = st.date_input(t("comparacao.end"), value=mid, min_value=min_d, max_value=max_d, key="ab_a_end")
    with c2:
        st.markdown(f"**{t('comparacao.period_b')}**")
        b_start = st.date_input(t("comparacao.start"), value=mid + timedelta(days=1) if mid < max_d else mid, min_value=min_d, max_value=max_d, key="ab_b_start")
        b_end = st.date_input(t("comparacao.end"), value=max_d, min_value=min_d, max_value=max_d, key="ab_b_end")

    if a_start > a_end or b_start > b_end:
        st.error(t("comparacao.invalid_range"))
        return

    result = compare_periods(df, (a_start, a_end), (b_start, b_end))
    ka, kb, deltas = result["kpis_a"], result["kpis_b"], result["deltas"]

    st.caption(
        t(
            "comparacao.summary",
            a=result["count_a"],
            b=result["count_b"],
            shared=result["ips_shared"],
        )
    )

    metrics = [
        ("records", t("comparacao.records")),
        ("unique_ips", t("comparacao.unique_ips")),
        ("providers", t("comparacao.providers")),
        ("countries", t("comparacao.countries")),
        ("cities", t("comparacao.cities")),
        ("proxy_pct", t("comparacao.proxy_pct")),
        ("hosting_pct", t("comparacao.hosting_pct")),
        ("mobile_pct", t("comparacao.mobile_pct")),
    ]

    rows = []
    for key, label in metrics:
        va, vb = ka[key], kb[key]
        d = deltas[key]
        suffix = "%" if key.endswith("_pct") else ""
        rows.append({
            t("comparacao.metric"): label,
            "A": f"{va}{suffix}",
            "B": f"{vb}{suffix}",
            "Δ (B−A)": f"{d:+}{suffix}",
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader(t("comparacao.top_providers_a"))
        if ka["top_providers"]:
            st.dataframe(
                pd.DataFrame(list(ka["top_providers"].items()), columns=[t("comparacao.provider"), t("comparacao.count")]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("—")
        st.subheader(t("comparacao.ips_only_a"))
        st.code("\n".join(result["ips_only_a"]) or "—")
    with col_b:
        st.subheader(t("comparacao.top_providers_b"))
        if kb["top_providers"]:
            st.dataframe(
                pd.DataFrame(list(kb["top_providers"].items()), columns=[t("comparacao.provider"), t("comparacao.count")]),
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("—")
        st.subheader(t("comparacao.ips_only_b"))
        st.code("\n".join(result["ips_only_b"]) or "—")
