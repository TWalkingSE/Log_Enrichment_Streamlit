"""
Análise Avançada - Risco & Ameaças
Risk Score, VirusTotal, Shodan, Tor Exit Nodes.
"""

import streamlit as st
import pandas as pd
import os
import logging
import plotly.express as px

from analysis import (
    calculate_risk_scores,
    batch_check_virustotal, batch_check_abuseipdb,
    compute_multi_source_threat_score,
    batch_check_shodan, compute_shodan_risk_indicators,
    get_tor_exit_nodes, check_tor_exit_nodes,
)
from advanced_analysis import get_tor_exit_cache_status
from analysis.risk import RISK_HIGH, RISK_MEDIUM, risk_level_counts
from helpers.runtime_flags import AirGappedError
from helpers.shared import run_async
from helpers.large_data import cache_key, gate, show_truncation

# Consultas externas por IP (VirusTotal, AbuseIPDB, Shodan) são limitadas pela
# cota gratuita desses serviços.
MAX_EXTERNAL_IPS = 50

from i18n import t

logger = logging.getLogger(__name__)


# `_df` não é hasheado (prefixo `_`); a identidade do cache vem de `key`,
# derivado da versão do dataset. Hashear o frame a cada rerun era o custo.
@st.cache_data(show_spinner=False)
def _cached_risk_scores(_df, ip_col, key):
    return calculate_risk_scores(_df, ip_col=ip_col)


def page_risco():
    from styles.components import section_header, empty_state
    section_header(t('risco.title'), divider="red")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('risco.no_data'), "🛡️", t('common.process_data_first'))
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    all_unique_ips = df[ip_col].dropna().unique().tolist()
    unique_ips = all_unique_ips[:MAX_EXTERNAL_IPS]

    # ── Risk Score ──
    with st.container(border=True):
        st.subheader(t('risco.risk_score_title'))
        scores = (_cached_risk_scores(df, ip_col, cache_key('risk', len(df), ip_col))
                  if gate(t('risco.gate_scores'), df, 'risk_scores')
                  else pd.DataFrame())
        if not scores.empty:
            alto, medio, baixo = risk_level_counts(scores)
            c1, c2, c3 = st.columns(3)
            c1.metric(t('risco.high_risk', threshold=RISK_HIGH), alto, help=f"Score ≥ {RISK_HIGH}")
            c2.metric(t('risco.medium_risk'), medio, help=f"{RISK_MEDIUM} ≤ Score < {RISK_HIGH}")
            c3.metric(t('risco.low_risk'), baixo, help=f"Score < {RISK_MEDIUM}")
            top = scores.head(20)
            fig = px.bar(top, x='Score', y='IP', orientation='h',
                         color='Score', color_continuous_scale='RdYlGn_r',
                         hover_data=['Provedor', 'Cidade', 'Fatores'])
            fig.update_layout(height=500, yaxis={'categoryorder': 'total ascending'},
                              showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='risk_chart')
            show_truncation(len(top), len(scores), t('risco.unit_chart_ips'))
            st.dataframe(scores, use_container_width=True, height=400, hide_index=True)

    # ── VirusTotal + AbuseIPDB ──
    with st.container(border=True):
        st.subheader(t('risco.vt_abuseipdb_title'))
        c1, c2 = st.columns(2)
        # As chaves do .env NÃO pré-preenchem os campos: o valor de um
        # text_input vai para o navegador, mesmo com type="password".
        env_vt = os.getenv('VIRUSTOTAL_API_KEY', '')
        env_abuse = os.getenv('ABUSEIPDB_API_KEY', '')
        with c1:
            vt_key = st.text_input(t('risco.vt_key_label'), type="password", key="vt_api_key",
                                   placeholder=t('risco.using_env_key') if env_vt else "") or env_vt
        with c2:
            abuse_key = st.text_input(t('risco.abuseipdb_key_label'), type="password", key="abuse_key_vt",
                                      placeholder=t('risco.using_env_key') if env_abuse else "") or env_abuse
        show_truncation(len(unique_ips), len(all_unique_ips), t('risco.unit_queried_ips'))
        if st.button(t('risco.run_analysis', count=len(unique_ips)), key="vt_analyze", type="primary"):
            if not vt_key and not abuse_key:
                st.error(t('risco.need_key'))
            else:
                with st.status(t('risco.analyzing')) as status:
                    try:
                        vt_results = run_async(batch_check_virustotal(unique_ips, vt_key)) if vt_key else []
                        abuse_results = run_async(batch_check_abuseipdb(unique_ips, abuse_key)) if abuse_key else []
                    except AirGappedError as e:
                        st.error(str(e))
                        status.update(label=t('risco.blocked_airgap'), state="error")
                    else:
                        vt_scores = compute_multi_source_threat_score(abuse_results, vt_results)
                        if vt_scores:
                            st.session_state['vt_scores'] = pd.DataFrame(vt_scores)
                            status.update(label=t('risco.ips_done', count=len(vt_scores)), state="complete")
        if 'vt_scores' in st.session_state:
            st.dataframe(st.session_state['vt_scores'], use_container_width=True, height=400, hide_index=True)

    # ── Shodan ──
    with st.container(border=True):
        st.subheader(t('risco.shodan_title'))
        shodan_key = os.getenv('SHODAN_API_KEY', '')
        if shodan_key:
            st.success(t('risco.shodan_key_env'))
        else:
            st.info(t('risco.shodan_configure'))
        show_truncation(len(unique_ips), len(all_unique_ips), t('risco.unit_queried_ips'))
        if st.button(t('risco.run_shodan', count=len(unique_ips)), key="shodan_btn", type="primary"):
            if not shodan_key:
                st.error(t('risco.shodan_need_key'))
            else:
                with st.status(t('risco.querying_shodan')) as status:
                    try:
                        results = run_async(batch_check_shodan(unique_ips, shodan_key))
                        risk = compute_shodan_risk_indicators(results, df)
                        st.session_state['shodan_results'] = results
                        st.session_state['shodan_risk'] = risk
                        status.update(label=t('risco.shodan_done', count=len(results)), state="complete")
                    except AirGappedError as e:
                        st.error(str(e))
                        status.update(label=t('risco.blocked_airgap'), state="error")
                    except Exception as e:
                        logger.exception("Consulta ao Shodan falhou")
                        st.error(t('risco.error', error=e))
        if 'shodan_risk' in st.session_state:
            risk = st.session_state['shodan_risk']
            dangerous = [r for r in risk if r.get('dangerous_ports')]
            unexpected = [r for r in risk if r.get('unexpected_services')]
            total_vulns = sum(r.get('vulns_count', 0) for r in risk)
            c1, c2, c3 = st.columns(3)
            c1.metric(t('risco.dangerous_ports'), len(dangerous))
            c2.metric(t('risco.unexpected_services'), len(unexpected))
            c3.metric(t('risco.vulnerabilities'), total_vulns)
            flagged = [r for r in risk if r.get('risk_level') in ('Alto', 'Crítico')]
            if flagged:
                st.warning(t('risco.shodan_risk_found', count=len(flagged)))
                st.dataframe(pd.DataFrame(flagged), use_container_width=True, hide_index=True)
            else:
                st.success(t('risco.no_shodan_risk'))
        if 'shodan_results' in st.session_state:
            with st.expander(t('risco.shodan_raw')):
                for r in st.session_state['shodan_results']:
                    if r.get('ports'):
                        st.markdown(t('risco.shodan_ports', ip=r['ip'], ports=', '.join(map(str, r['ports']))))

    # ── Tor Exit Nodes ──
    with st.container(border=True):
        st.subheader(t('risco.tor_check_title'))
        tor_enabled = st.toggle(t('risco.tor_enable'), value=True, key="tor_enabled")
        if tor_enabled:
            if st.button(t('risco.tor_check_btn'), key="tor_check_btn", type="primary"):
                with st.status(t('risco.tor_loading')) as status:
                    try:
                        tor_nodes = get_tor_exit_nodes()
                        tor_meta = get_tor_exit_cache_status()
                        if not tor_nodes:
                            # Lista vazia NÃO é "nenhum IP Tor": é verificação
                            # impossível. Antes a página dizia "✅ Nenhum IP
                            # corresponde a Tor exit node".
                            st.session_state.pop('tor_result', None)
                            st.error(t('risco.tor_list_unavailable'))
                            status.update(label=t('risco.tor_list_unavailable_label'), state="error")
                        else:
                            result = check_tor_exit_nodes(df, tor_nodes, ip_col=ip_col)
                            result['lista_idade_h'] = tor_meta.get('age_hours')
                            result['lista_obsoleta'] = tor_meta.get('is_stale', True)
                            result['lista_nos'] = len(tor_nodes)
                            st.session_state['tor_result'] = result
                            status.update(label=t('risco.tor_checked', count=result['total_tor']),
                                          state="complete")
                    except Exception as e:
                        logger.exception("Verificação Tor falhou")
                        st.error(t('risco.error', error=e))
            if 'tor_result' in st.session_state:
                result = st.session_state['tor_result']
                tor_ips = result.get('tor_ips', [])
                idade = result.get('lista_idade_h')
                idade_txt = (f"{idade:.1f} h" if isinstance(idade, (int, float))
                             else t('risco.age_unknown'))
                if result.get('lista_obsoleta'):
                    # A lista muda a cada hora; servida velha, um nó que saiu
                    # da rede Tor ainda conta e um novo não aparece.
                    st.warning(t('risco.tor_list_stale', nodes=result.get('lista_nos', 0), age=idade_txt))
                else:
                    st.caption(t('risco.tor_list_info', nodes=result.get('lista_nos', 0), age=idade_txt))
                c1, c2 = st.columns(2)
                c1.metric(t('risco.tor_ips'), result['total_tor'])
                c2.metric(t('risco.tor_pct'), f"{result['pct_tor']}%")
                if tor_ips:
                    st.error(t('risco.tor_found', count=len(tor_ips)))
                    timeline = result.get('tor_timeline', [])
                    if timeline:
                        st.dataframe(pd.DataFrame(timeline), use_container_width=True, hide_index=True)
                    else:
                        for ip in tor_ips:
                            st.code(ip, language=None)
                else:
                    st.success(t('risco.no_tor_match'))
