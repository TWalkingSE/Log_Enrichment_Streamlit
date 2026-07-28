"""
Análise Avançada - Geolocalização
Geo History, Sub-redes, Padrões de Vida.
"""

import streamlit as st
import pandas as pd
import os
import json

from analysis import (
    detect_life_patterns,
    detect_geo_changes,
    analyze_subnet_patterns, correlate_subnets_cross_target, compute_subnet_consistency,
)
from i18n import t


@st.cache_data(show_spinner=False)
def _cached_subnet_patterns(df, ipv4_mask, ipv6_mask):
    return analyze_subnet_patterns(df, ipv4_mask=ipv4_mask, ipv6_mask=ipv6_mask)


@st.cache_data(show_spinner=False)
def _cached_subnet_consistency(df, ipv4_mask, ipv6_mask):
    return compute_subnet_consistency(df, ipv4_mask=ipv4_mask, ipv6_mask=ipv6_mask)


@st.cache_data(show_spinner=False)
def _cached_life_patterns(df):
    return detect_life_patterns(df)


def page_geo():
    from styles.components import section_header, empty_state
    section_header(t('geo.title'), divider="green")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('geo.no_data'), "🌐", t('common.process_data_first'))
        return

    # ── Geo History ──
    with st.container(border=True):
        st.subheader(t('geo.history_title'))
        st.caption(t('geo.history_subtitle'))
        cache_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'ip_cache.json')
        cache = {}
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    cache = json.load(f)
            except Exception:
                pass
        if cache:
            result = detect_geo_changes(df, cache)
            changes = result.get('changed_ips', [])
            if changes:
                st.warning(t('geo.geo_changes_found', count=result['total_changes']))
                for ch in changes:
                    sev_icon = {'Crítico': '🔴', 'Alto': '🟠', 'Médio': '🟡'}.get(ch.get('severity', ''), '⚪')
                    with st.expander(f"{sev_icon} {ch['ip']} — {ch.get('severity', '')}"):
                        st.markdown(f"**{t('geo.current')}:** {ch.get('new_city', '')} / {ch.get('new_isp', '')}")
                        st.markdown(f"**{t('geo.previous')}:** {ch.get('old_city', '')} / {ch.get('old_isp', '')}")
                        st.markdown(f"**{t('geo.change_date')}:** {ch.get('change_date', 'N/A')}")
                        if ch.get('distance_km'):
                            st.markdown(f"**{t('geo.distance')}:** {ch['distance_km']} km")
            else:
                st.success(t('geo.no_geo_changes'))
        else:
            st.info(t('geo.empty_cache'))

    # ── Sub-redes ──
    with st.container(border=True):
        st.subheader(t('geo.subnets_title'))
        with st.popover("⚙️"):
            ipv4_mask = st.slider("IPv4", 16, 32, 24, key="subnet_v4")
            ipv6_mask = st.slider("IPv6", 32, 64, 48, key="subnet_v6")

        result = _cached_subnet_patterns(df, ipv4_mask, ipv6_mask)
        c1, c2 = st.columns(2)
        c1.metric("Subnets", result['total_subnets'])
        consistency = _cached_subnet_consistency(df, ipv4_mask, ipv6_mask)
        c2.metric("Consistency", f"{consistency['consistency_score']}%")

        if result['dominant_subnets']:
            st.markdown("**Top Sub-redes:**")
            dom_df = pd.DataFrame(result['dominant_subnets'])
            display_cols = [c for c in ['subnet', 'ip_count', 'record_count', 'providers', 'cities'] if c in dom_df.columns]
            st.dataframe(dom_df[display_cols], use_container_width=True, hide_index=True)

        if consistency.get('top_subnets'):
            st.markdown(f"**Sub-rede primária:** `{consistency['primary_subnet']}` ({consistency.get('primary_pct', 0)}%)")
            st.markdown(f"**Trocas de sub-rede:** {consistency['subnet_changes']}")

        # Cross-target subnet correlation
        stored = st.session_state.stored_targets
        if len(stored) >= 2:
            st.divider()
            if st.button("🔗 Correlação de Sub-redes entre Alvos", key="subnet_cross"):
                shared = correlate_subnets_cross_target(stored, ipv4_mask=ipv4_mask, ipv6_mask=ipv6_mask)
                if shared:
                    st.warning(f"⚠️ **{len(shared)}** sub-rede(s) compartilhada(s)!")
                    st.dataframe(pd.DataFrame([{
                        'Sub-rede': s['subnet'],
                        'Alvos': ', '.join(s['targets']),
                        'Total IPs': s['total_ips']
                    } for s in shared]), use_container_width=True, hide_index=True)
                else:
                    st.success("✅ Nenhuma sub-rede compartilhada.")

    # ── Padrões de Vida ──
    with st.container(border=True):
        st.subheader(t('geo.life_patterns_title'))
        life = _cached_life_patterns(df)
        if life.get('has_data'):
            for c in life.get('clusters', []):
                icon = {'home': '🏠', 'work': '🏢', 'other': '📍'}.get(c.get('type', ''), '📍')
                st.markdown(f"**{icon} {c.get('label', '')}** — {c.get('city', '')} ({c.get('count', 0)} acessos)")
        else:
            st.info(t('geo.life_patterns_subtitle'))
