"""
Análise Avançada - Comportamento
VPN/Proxy, Confiança IP, Números Descartáveis.
"""

import streamlit as st
import pandas as pd

from analysis import (
    detect_vpn_heuristics, compute_ip_confidence,
    detect_disposable_numbers,
)
from i18n import t


def page_comportamento():
    from styles.components import section_header, empty_state
    section_header(t('comportamento.title'), divider="violet")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('comportamento.no_data'), "🕵️", t('common.process_data_first'))
        return

    # ── VPN/Proxy ──
    with st.container(border=True):
        st.subheader("🕵️ Detecção Heurística de VPN/Proxy")
        vpn_result = detect_vpn_heuristics(df)
        score = vpn_result.get('score', 0)
        c1, c2 = st.columns([1, 2])
        with c1:
            delta = "Alto" if score >= 50 else "Médio" if score >= 20 else "Baixo"
            st.metric("Score VPN", f"{score}/100", delta=delta,
                      delta_color="inverse" if score >= 50 else "off" if score >= 20 else "normal")
        with c2:
            for k, v in vpn_result.get('indicators', {}).items():
                st.markdown(f"**{k}**: {v}")
            if not vpn_result.get('indicators'):
                st.success("Nenhum indicador de VPN comportamental.")
        suspicious = vpn_result.get('suspicious_ips', [])
        if suspicious:
            st.warning(f"**{len(suspicious)} IPs suspeitos:**")
            for ip in suspicious:
                st.code(ip, language=None)

    # ── Confiança IP ──
    with st.container(border=True):
        st.subheader("🎯 Confiança de IPs")
        ip_conf = compute_ip_confidence(df)
        if not ip_conf.empty:
            c1, c2, c3 = st.columns(3)
            c1.metric("IP Real", len(ip_conf[ip_conf['Classification'] == 'IP Real']))
            c2.metric("Incerto", len(ip_conf[ip_conf['Classification'] == 'Incerto']))
            c3.metric("Mascarado", len(ip_conf[ip_conf['Classification'] == 'IP Mascarado']))
            st.dataframe(ip_conf, width='stretch', height=400, hide_index=True)

    # ── Números Descartáveis ──
    with st.container(border=True):
        st.subheader("📱 Detecção de Números Descartáveis")
        df_i = st.session_state.get('df_interceptacao')
        if df_i is not None and not df_i.empty:
            with st.popover("⚙️ Configurar"):
                max_app = st.slider("Máximo de aparições", 1, 10, 3, key="disp_max")
            disposable = detect_disposable_numbers(df_i, max_appearances=max_app)
            if not disposable.empty:
                st.warning(f"**{len(disposable)}** números descartáveis")
                st.dataframe(disposable, width='stretch', hide_index=True)
            else:
                st.success("✅ Nenhum número descartável detectado.")
        else:
            st.info("Processe dados de **Interceptação** primeiro.")
