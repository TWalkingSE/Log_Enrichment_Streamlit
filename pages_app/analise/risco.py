"""
Análise Avançada - Risco & Ameaças
Risk Score, VirusTotal, Shodan, Tor Exit Nodes.
"""

import streamlit as st
import pandas as pd
import os
import asyncio
import logging
import plotly.express as px

from analysis import (
    calculate_risk_scores,
    batch_check_virustotal, batch_check_abuseipdb,
    compute_multi_source_threat_score,
    batch_check_shodan, compute_shodan_risk_indicators,
    get_tor_exit_nodes, check_tor_exit_nodes,
)

from i18n import t

logger = logging.getLogger(__name__)


def page_risco():
    from styles.components import section_header, empty_state
    section_header(t('risco.title'), divider="red")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('risco.no_data'), "🛡️", t('common.process_data_first'))
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    unique_ips = df[ip_col].dropna().unique().tolist()[:50]

    # ── Risk Score ──
    with st.container(border=True):
        st.subheader("🛡️ Score de Risco por IP")
        scores = calculate_risk_scores(df, ip_col=ip_col)
        if not scores.empty:
            c1, c2, c3 = st.columns(3)
            c1.metric("Alto Risco (≥50)", len(scores[scores['Score'] >= 50]))
            c2.metric("Médio Risco", len(scores[(scores['Score'] >= 20) & (scores['Score'] < 50)]))
            c3.metric("Baixo Risco", len(scores[scores['Score'] < 20]))
            fig = px.bar(scores.head(20), x='Score', y='IP', orientation='h',
                         color='Score', color_continuous_scale='RdYlGn_r',
                         hover_data=['Provedor', 'Cidade', 'Fatores'])
            fig.update_layout(height=500, yaxis={'categoryorder': 'total ascending'},
                              showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='risk_chart')
            st.dataframe(scores, width='stretch', height=400, hide_index=True)

    # ── VirusTotal + AbuseIPDB ──
    with st.container(border=True):
        st.subheader("🦠 VirusTotal / AbuseIPDB — Análise Multi-Fonte")
        c1, c2 = st.columns(2)
        with c1:
            vt_key = st.text_input("VirusTotal API Key", type="password", key="vt_api_key",
                                   value=os.getenv('VIRUSTOTAL_API_KEY', ''))
        with c2:
            abuse_key = st.text_input("AbuseIPDB API Key", type="password", key="abuse_key_vt",
                                      value=os.getenv('ABUSEIPDB_API_KEY', ''))
        st.caption(f"{len(unique_ips)} IPs únicos (máx 50)")
        if st.button("🔍 Analisar IPs", key="vt_analyze", type="primary"):
            if not vt_key and not abuse_key:
                st.error("Forneça ao menos uma API Key.")
            else:
                with st.status("Consultando APIs externas...") as status:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        vt_results = loop.run_until_complete(batch_check_virustotal(unique_ips, vt_key)) if vt_key else []
                        abuse_results = loop.run_until_complete(batch_check_abuseipdb(unique_ips, abuse_key)) if abuse_key else []
                        vt_scores = compute_multi_source_threat_score(abuse_results, vt_results)
                        if vt_scores:
                            st.session_state['vt_scores'] = pd.DataFrame(vt_scores)
                            status.update(label=f"✅ {len(vt_scores)} IPs!", state="complete")
                    finally:
                        loop.close()
        if 'vt_scores' in st.session_state:
            st.dataframe(st.session_state['vt_scores'], width='stretch', height=400, hide_index=True)

    # ── Shodan ──
    with st.container(border=True):
        st.subheader("🔎 Shodan — Serviços & Portas Expostas")
        shodan_key = os.getenv('SHODAN_API_KEY', '')
        if shodan_key:
            st.success("🔑 Shodan API Key configurada via `.env`.")
        else:
            st.info("Configure `SHODAN_API_KEY` no arquivo `.env`.")
        st.caption(f"{len(unique_ips)} IPs únicos (máx 50)")
        if st.button("🔎 Consultar Shodan", key="shodan_btn", type="primary"):
            if not shodan_key:
                st.error("Informe a API Key do Shodan.")
            else:
                with st.status("Consultando Shodan...") as status:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        results = loop.run_until_complete(batch_check_shodan(unique_ips, shodan_key))
                        risk = compute_shodan_risk_indicators(results, df)
                        st.session_state['shodan_results'] = results
                        st.session_state['shodan_risk'] = risk
                        status.update(label=f"✅ {len(results)} IPs consultados!", state="complete")
                    except Exception as e:
                        st.error(f"Erro: {e}")
                    finally:
                        loop.close()
        if 'shodan_risk' in st.session_state:
            risk = st.session_state['shodan_risk']
            dangerous = [r for r in risk if r.get('dangerous_ports')]
            unexpected = [r for r in risk if r.get('unexpected_services')]
            total_vulns = sum(r.get('vulns_count', 0) for r in risk)
            c1, c2, c3 = st.columns(3)
            c1.metric("IPs com Portas Perigosas", len(dangerous))
            c2.metric("Serviços Inesperados", len(unexpected))
            c3.metric("Vulnerabilidades", total_vulns)
            flagged = [r for r in risk if r.get('risk_level') in ('Alto', 'Crítico')]
            if flagged:
                st.warning(f"⚠️ **{len(flagged)}** IPs com indicadores de risco:")
                st.dataframe(pd.DataFrame(flagged), width='stretch', hide_index=True)
        if 'shodan_results' in st.session_state:
            with st.expander("📋 Dados brutos do Shodan"):
                for r in st.session_state['shodan_results']:
                    if r.get('ports'):
                        st.markdown(f"**{r['ip']}** — Portas: {', '.join(map(str, r['ports']))}")

    # ── Tor Exit Nodes ──
    with st.container(border=True):
        st.subheader("🧅 Verificação Tor Exit Nodes")
        tor_enabled = st.toggle("Habilitar verificação Tor", value=True, key="tor_enabled")
        if tor_enabled:
            if st.button("🧅 Verificar IPs contra Tor", key="tor_check_btn", type="primary"):
                with st.status("Carregando lista de Tor exit nodes...") as status:
                    try:
                        tor_nodes = get_tor_exit_nodes()
                        st.caption(f"Lista Tor: {len(tor_nodes)} nós carregados")
                        result = check_tor_exit_nodes(df, tor_nodes, ip_col=ip_col)
                        st.session_state['tor_result'] = result
                        status.update(label=f"✅ Verificado! {result['total_tor']} IP(s) Tor.", state="complete")
                    except Exception as e:
                        st.error(f"Erro: {e}")
            if 'tor_result' in st.session_state:
                result = st.session_state['tor_result']
                tor_ips = result.get('tor_ips', [])
                c1, c2 = st.columns(2)
                c1.metric("IPs Tor", result['total_tor'])
                c2.metric("Percentual Tor", f"{result['pct_tor']}%")
                if tor_ips:
                    st.error(f"🧅 **{len(tor_ips)}** IP(s) identificado(s) como Tor Exit Node!")
                    timeline = result.get('tor_timeline', [])
                    if timeline:
                        st.dataframe(pd.DataFrame(timeline), width='stretch', hide_index=True)
                    else:
                        for ip in tor_ips:
                            st.code(ip, language=None)
                else:
                    st.success("✅ Nenhum IP corresponde a Tor exit node.")
