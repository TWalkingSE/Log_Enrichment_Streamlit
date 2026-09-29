"""
Análise Avançada - Visão Geral
Dashboard de KPIs e status rápido de todas as análises.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

from analysis import (
    calculate_risk_scores, compute_data_health,
    detect_vpn_heuristics, compute_ip_confidence,
)
from analysis.risk import RISK_HIGH, risk_level_counts
from helpers.large_data import cache_key, gate
from validators import bool_series
from i18n import t


# `_df` não é hasheado (prefixo `_`); a identidade do cache vem de `key`,
# derivado da versão do dataset — hashear o frame a cada rerun era o custo.
@st.cache_data(show_spinner=False)
def _cached_overview_kpis(_df, ip_col, key):
    df = _df
    unique_ips = df[ip_col].nunique()
    n_providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0
    proxy_pct = (bool_series(df, 'Ip_Proxy').sum() / len(df) * 100) if 'Ip_Proxy' in df.columns and len(df) > 0 else 0
    health = compute_data_health(df)
    health_score = health.get('overall_score', 0)
    scores = calculate_risk_scores(df, ip_col=ip_col)
    avg_risk = float(scores['Score'].mean()) if not scores.empty else 0.0
    # Mesmo limiar da página de Risco e do relatório (antes: 50 aqui).
    high_risk = risk_level_counts(scores)[0]
    vpn = detect_vpn_heuristics(df)
    ip_conf = compute_ip_confidence(df)
    masked = int(len(ip_conf[ip_conf['Classification'] == 'IP Mascarado'])) if not ip_conf.empty else 0
    return {
        'unique_ips': unique_ips,
        'n_providers': n_providers,
        'proxy_pct': proxy_pct,
        'health_score': health_score,
        'scores': scores,
        'avg_risk': avg_risk,
        'high_risk': high_risk,
        'vpn_score': vpn.get('score', 0),
        'masked': masked,
    }


def page_overview():
    from styles.components import section_header, empty_state
    section_header(t('overview.title'), divider="violet")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('overview.no_data'), "📊", t('common.process_data_first'))
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    # Toda a página é derivada de varreduras completas do frame — um clique
    # libera tudo de uma vez em datasets grandes.
    if not gate(t('overview.calculate'), df, 'overview_kpis'):
        return

    # ── Row 1: KPIs (cached) ──
    kpis = _cached_overview_kpis(df, ip_col, cache_key('ovk', len(df), ip_col))
    unique_ips = kpis['unique_ips']
    n_providers = kpis['n_providers']
    proxy_pct = kpis['proxy_pct']
    health_score = kpis['health_score']
    scores = kpis['scores']
    avg_risk = kpis['avg_risk']
    high_risk = kpis['high_risk']

    with st.container(border=True):
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric(t('common.unique_ips'), unique_ips)
        c2.metric(t('overview.avg_risk_score'), f"{avg_risk:.0f}",
                  delta=t('overview.high_risk', count=high_risk),
                  delta_color="inverse" if high_risk > 0 else "off")
        c3.metric(t('overview.vpn_proxy_pct'), f"{proxy_pct:.1f}%",
                  delta=t('common.high') if proxy_pct > 20 else t('common.normal'),
                  delta_color="inverse" if proxy_pct > 20 else "off")
        c4.metric(t('common.providers'), n_providers)
        c5.metric(t('overview.vpn_score'), f"{kpis['vpn_score']}/100",
                  delta_color="inverse" if kpis['vpn_score'] >= 50 else "off")
        c6.metric(t('overview.data_health'), f"{health_score}%",
                  delta=t('common.good') if health_score >= 80 else t('common.attention'),
                  delta_color="normal" if health_score >= 80 else "inverse")

    # ── Row 2: Quick Status ──
    with st.container(border=True):
        s1, s2, s3, s4 = st.columns(4)
        tor_result = st.session_state.get('tor_result')
        with s1:
            if tor_result:
                st.metric(t('overview.tor_nodes'), tor_result['total_tor'],
                          delta=t('common.detected') if tor_result['total_tor'] > 0 else t('common.clean'),
                          delta_color="inverse" if tor_result['total_tor'] > 0 else "normal")
            else:
                st.metric(t('overview.tor_nodes'), "—", delta=t('common.not_verified'), delta_color="off")
        with s2:
            shodan_risk = st.session_state.get('shodan_risk')
            if shodan_risk:
                flagged = len([r for r in shodan_risk if r.get('risk_level') in ('Alto', 'Crítico')])
                st.metric(t('overview.shodan_alerts'), flagged,
                          delta=t('common.attention') if flagged > 0 else t('common.clean'),
                          delta_color="inverse" if flagged > 0 else "normal")
            else:
                st.metric(t('overview.shodan_alerts'), "—", delta=t('common.not_queried'), delta_color="off")
        with s3:
            masked = kpis['masked']
            st.metric(t('overview.masked_ips'), masked,
                      delta=t('common.suspect') if masked > 0 else t('common.ok'),
                      delta_color="inverse" if masked > 0 else "normal")
        with s4:
            st.metric(t('overview.stored_targets'), len(st.session_state.get('stored_targets', {})))

    # ── Row 3: Top Risk IPs ──
    if not scores.empty:
        with st.container(border=True):
            st.subheader(t('overview.top_risk_ips'))
            fig = px.bar(scores.head(10), x='Score', y='IP', orientation='h',
                         color='Score', color_continuous_scale='RdYlGn_r',
                         hover_data=['Provedor', 'Cidade', 'Fatores'])
            fig.update_layout(height=350, yaxis={'categoryorder': 'total ascending'},
                              showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='overview_risk')

    # ── Row 4: Resumo Executivo ──
    with st.container(border=True):
        st.subheader(t('overview.exec_summary'))
        st.caption(t('overview.exec_subtitle'))

        alvo = st.session_state.get('alvo') or t('common.not_informed')
        dt_fato = st.session_state.get('dt_fato', None)
        dt_fato_str = dt_fato.strftime('%d/%m/%Y') if hasattr(dt_fato, 'strftime') else str(dt_fato or '—')

        # Calcular métricas adicionais
        ipv6_count = df[df.get('Tipo_IP', pd.Series(dtype=str)).eq('IPv6')].shape[0] if 'Tipo_IP' in df.columns else 0
        ipv4_count = len(df) - ipv6_count if 'Tipo_IP' in df.columns else len(df)
        total_regs = len(df)
        paises = df['Ip_Pais'].dropna().nunique() if 'Ip_Pais' in df.columns else 0
        cidades = df['Ip_Cidade'].dropna().nunique() if 'Ip_Cidade' in df.columns else 0
        top_prov = df['Ip_Dono'].value_counts().head(3).to_dict() if 'Ip_Dono' in df.columns else {}

        # Determinar classificação de risco geral
        if avg_risk >= 60:
            risco_geral = t('overview.risk_high')
            risco_desc = t('overview.risk_high_desc')
        elif avg_risk >= 35:
            risco_geral = t('overview.risk_medium')
            risco_desc = t('overview.risk_medium_desc')
        else:
            risco_geral = t('overview.risk_low')
            risco_desc = t('overview.risk_low_desc')

        # Briefing formatado
        linhas_tabela = [
            (t('overview.total_records'), f"{total_regs:,}"),
            (t('overview.unique_ips'), f"{unique_ips:,}"),
            (t('overview.ipv6_ipv4'), f"{ipv6_count:,} / {ipv4_count:,}"),
            (t('overview.identified_providers'), n_providers),
            (t('common.countries'), paises),
            (t('common.cities'), cidades),
            (t('overview.avg_risk'), f"{avg_risk:.0f}/100"),
            (t('overview.high_risk_ips', threshold=RISK_HIGH), high_risk),
            (t('overview.vpn_proxy_usage'), f"{proxy_pct:.1f}%"),
            (t('overview.masked_ips_label'), masked),
            (t('overview.data_health_label'), f"{health_score}%"),
        ]
        briefing = (
            f"\n**{t('overview.investigation')}:** {alvo}\n"
            f"**{t('overview.fact_date')}:** {dt_fato_str}\n"
            f"**{t('overview.risk_classification')}:** {risco_geral}\n\n---\n\n"
            f"| {t('overview.indicator')} | {t('overview.value')} |\n|---|---|\n"
            + "".join(f"| {rotulo} | {valor} |\n" for rotulo, valor in linhas_tabela)
        )

        if top_prov:
            briefing += f"\n**{t('overview.main_providers')}**\n"
            for p, c in top_prov.items():
                briefing += f"- {p}: {c:,} {t('overview.records_suffix')}\n"

        briefing += f"\n**{t('overview.assessment')}:** {risco_desc}\n"

        # Achados relevantes
        findings = []
        if proxy_pct > 20:
            findings.append(t('overview.high_vpn_rate', pct=f"{proxy_pct:.1f}"))
        if masked > 0:
            findings.append(t('overview.masked_classified', count=masked))
        tor_result_exec = st.session_state.get('tor_result')
        if tor_result_exec and tor_result_exec.get('total_tor', 0) > 0:
            findings.append(t('overview.tor_detected', count=tor_result_exec['total_tor']))
        if high_risk > 5:
            findings.append(t('overview.many_high_risk', count=high_risk, threshold=RISK_HIGH))
        if ipv6_count > ipv4_count:
            findings.append(t('overview.ipv6_predominance', ipv6=ipv6_count, total=total_regs))
        if health_score < 70:
            findings.append(t('overview.low_data_quality', score=health_score))

        if findings:
            briefing += f"\n**{t('overview.relevant_findings')}**\n"
            for f in findings:
                briefing += f"- {f}\n"

        st.markdown(briefing)

        # Botão para copiar
        st.download_button(
            t('overview.download_summary'),
            data=briefing.replace('**', '').replace('|', ' '),
            file_name=f"resumo_executivo_{alvo.replace(' ', '_')}.txt",
            mime="text/plain",
            key="download_exec_summary",
        )
