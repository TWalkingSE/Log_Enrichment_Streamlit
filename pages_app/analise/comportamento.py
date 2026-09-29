"""
Análise Avançada - Comportamento
VPN/Proxy, Confiança IP, Números Descartáveis.
"""

import pandas as pd
import streamlit as st

from analysis import (
    detect_vpn_heuristics, compute_ip_confidence,
    detect_disposable_numbers,
)
from helpers.large_data import cache_key, gate
from i18n import t


@st.cache_data(show_spinner=False)
def _cached_vpn(_df, key):
    return detect_vpn_heuristics(_df)


@st.cache_data(show_spinner=False)
def _cached_confidence(_df, key):
    return compute_ip_confidence(_df)


def page_comportamento():
    from styles.components import section_header, empty_state
    section_header(t('comportamento.title'), divider="violet")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('comportamento.no_data'), "🕵️", t('common.process_data_first'))
        return

    # ── VPN/Proxy ──
    with st.container(border=True):
        st.subheader(t('comportamento.vpn_title'))
        vpn_result = (_cached_vpn(df, cache_key('vpn', len(df)))
                      if gate(t('comportamento.gate_vpn'), df, 'comp_vpn')
                      else {})
        score = vpn_result.get('score', 0)
        c1, c2 = st.columns([1, 2])
        with c1:
            delta = (t('common.high') if score >= 50 else t('common.medium') if score >= 20
                     else t('common.low'))
            st.metric(t('comportamento.vpn_score'), f"{score}/100", delta=delta,
                      delta_color="inverse" if score >= 50 else "off" if score >= 20 else "normal")
        with c2:
            for k, v in vpn_result.get('indicators', {}).items():
                st.markdown(f"**{k}**: {v}")
            if not vpn_result.get('indicators') and vpn_result:
                st.success(t('comportamento.no_vpn_indicators'))
        suspicious = vpn_result.get('suspicious_ips', [])
        if suspicious:
            st.warning(t('comportamento.suspicious_ips', count=len(suspicious)))
            for ip in suspicious:
                st.code(ip, language=None)

    # ── Confiança IP ──
    with st.container(border=True):
        st.subheader(t('comportamento.confidence_title'))
        ip_conf = (_cached_confidence(df, cache_key('conf', len(df)))
                   if gate(t('comportamento.gate_confidence'), df, 'comp_conf')
                   else pd.DataFrame())
        if not ip_conf.empty:
            c1, c2, c3 = st.columns(3)
            c1.metric(t('comportamento.ip_real'), len(ip_conf[ip_conf['Classification'] == 'IP Real']))
            c2.metric(t('comportamento.uncertain'), len(ip_conf[ip_conf['Classification'] == 'Incerto']))
            c3.metric(t('comportamento.masked'), len(ip_conf[ip_conf['Classification'] == 'IP Mascarado']))
            st.dataframe(ip_conf, use_container_width=True, height=400, hide_index=True)

    # ── Números Descartáveis ──
    with st.container(border=True):
        st.subheader(t('comportamento.disposable_title'))
        df_i = st.session_state.get('df_interceptacao')
        if df_i is not None and not df_i.empty:
            with st.popover(t('comportamento.configure')):
                max_app = st.slider(t('comportamento.max_appearances'), 1, 10, 3, key="disp_max")
            if gate(t('comportamento.gate_disposable'), df_i, 'comp_disp'):
                disposable = detect_disposable_numbers(df_i, max_appearances=max_app)
                if not disposable.empty:
                    st.warning(t('comportamento.disposable_found', count=len(disposable)))
                    st.dataframe(disposable, use_container_width=True, hide_index=True)
                else:
                    st.success(t('comportamento.no_disposable'))
        else:
            st.info(t('comportamento.no_interception_data'))
