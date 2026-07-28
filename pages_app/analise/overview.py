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
from i18n import t


@st.cache_data(show_spinner=False)
def _cached_overview_kpis(df, ip_col):
    unique_ips = df[ip_col].nunique()
    n_providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0
    proxy_pct = (df['Ip_Proxy'].sum() / len(df) * 100) if 'Ip_Proxy' in df.columns and len(df) > 0 else 0
    health = compute_data_health(df)
    health_score = health.get('overall_score', 0)
    scores = calculate_risk_scores(df, ip_col=ip_col)
    avg_risk = float(scores['Score'].mean()) if not scores.empty else 0.0
    high_risk = int(len(scores[scores['Score'] >= 50])) if not scores.empty else 0
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

    # ── Row 1: KPIs (cached) ──
    kpis = _cached_overview_kpis(df, ip_col)
    unique_ips = kpis['unique_ips']
    n_providers = kpis['n_providers']
    proxy_pct = kpis['proxy_pct']
    health_score = kpis['health_score']
    scores = kpis['scores']
    avg_risk = kpis['avg_risk']
    high_risk = kpis['high_risk']

    with st.container(border=True):
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("IPs Únicos", unique_ips)
        c2.metric("Score Médio Risco", f"{avg_risk:.0f}", delta=f"{high_risk} alto risco",
                  delta_color="inverse" if high_risk > 0 else "off")
        c3.metric("% VPN/Proxy", f"{proxy_pct:.1f}%",
                  delta="Alto" if proxy_pct > 20 else "Normal",
                  delta_color="inverse" if proxy_pct > 20 else "off")
        c4.metric("Provedores", n_providers)
        c5.metric("Score VPN", f"{kpis['vpn_score']}/100",
                  delta_color="inverse" if kpis['vpn_score'] >= 50 else "off")
        c6.metric("Saúde Dados", f"{health_score}%",
                  delta="Boa" if health_score >= 80 else "Atenção",
                  delta_color="normal" if health_score >= 80 else "inverse")

    # ── Row 2: Quick Status ──
    with st.container(border=True):
        s1, s2, s3, s4 = st.columns(4)
        tor_result = st.session_state.get('tor_result')
        with s1:
            if tor_result:
                st.metric("🧅 Tor Nodes", tor_result['total_tor'],
                          delta="Detectado!" if tor_result['total_tor'] > 0 else "Limpo",
                          delta_color="inverse" if tor_result['total_tor'] > 0 else "normal")
            else:
                st.metric("🧅 Tor Nodes", "—", delta="Não verificado", delta_color="off")
        with s2:
            shodan_risk = st.session_state.get('shodan_risk')
            if shodan_risk:
                flagged = len([r for r in shodan_risk if r.get('risk_level') in ('Alto', 'Crítico')])
                st.metric("🔎 Shodan Alerts", flagged,
                          delta="Atenção" if flagged > 0 else "Limpo",
                          delta_color="inverse" if flagged > 0 else "normal")
            else:
                st.metric("🔎 Shodan Alerts", "—", delta="Não consultado", delta_color="off")
        with s3:
            masked = kpis['masked']
            st.metric("🎯 IPs Mascarados", masked,
                      delta="Suspeito" if masked > 0 else "OK",
                      delta_color="inverse" if masked > 0 else "normal")
        with s4:
            st.metric("📦 Alvos Armazenados", len(st.session_state.get('stored_targets', {})))

    # ── Row 3: Top Risk IPs ──
    if not scores.empty:
        with st.container(border=True):
            st.subheader("🛡️ Top 10 IPs por Risco")
            fig = px.bar(scores.head(10), x='Score', y='IP', orientation='h',
                         color='Score', color_continuous_scale='RdYlGn_r',
                         hover_data=['Provedor', 'Cidade', 'Fatores'])
            fig.update_layout(height=350, yaxis={'categoryorder': 'total ascending'},
                              showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='overview_risk')

    # ── Row 4: Resumo Executivo ──
    with st.container(border=True):
        st.subheader("📋 Resumo Executivo")
        st.caption("Briefing de uma página para despacho rápido")

        alvo = st.session_state.get('alvo', 'Não informado')
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
            risco_geral = "🔴 ALTO"
            risco_desc = "Múltiplos indicadores de risco elevado detectados."
        elif avg_risk >= 35:
            risco_geral = "🟡 MÉDIO"
            risco_desc = "Indicadores moderados — requer atenção."
        else:
            risco_geral = "🟢 BAIXO"
            risco_desc = "Sem indicadores significativos de risco."

        # Briefing formatado
        briefing = f"""
**INVESTIGAÇÃO:** {alvo}
**DATA DO FATO:** {dt_fato_str}
**CLASSIFICAÇÃO GERAL DE RISCO:** {risco_geral}

---

| Indicador | Valor |
|---|---|
| Total de registros | {total_regs:,} |
| IPs únicos | {unique_ips:,} |
| IPv6 / IPv4 | {ipv6_count:,} / {ipv4_count:,} |
| Provedores identificados | {n_providers} |
| Países | {paises} |
| Cidades | {cidades} |
| Score médio de risco | {avg_risk:.0f}/100 |
| IPs de alto risco (≥50) | {high_risk} |
| Uso de VPN/Proxy | {proxy_pct:.1f}% |
| IPs mascarados | {masked} |
| Saúde dos dados | {health_score}% |
"""

        if top_prov:
            briefing += "\n**Principais provedores:**\n"
            for p, c in top_prov.items():
                briefing += f"- {p}: {c:,} registros\n"

        briefing += f"\n**Avaliação:** {risco_desc}\n"

        # Achados relevantes
        findings = []
        if proxy_pct > 20:
            findings.append(f"⚠️ Alta taxa de VPN/Proxy ({proxy_pct:.1f}%) — possível ocultação de IP real.")
        if masked > 0:
            findings.append(f"⚠️ {masked} IP(s) classificado(s) como mascarado(s).")
        tor_result_exec = st.session_state.get('tor_result')
        if tor_result_exec and tor_result_exec.get('total_tor', 0) > 0:
            findings.append(f"⚠️ {tor_result_exec['total_tor']} conexão(ões) via rede Tor detectada(s).")
        if high_risk > 5:
            findings.append(f"⚠️ {high_risk} IPs com score de risco elevado (≥50).")
        if ipv6_count > ipv4_count:
            findings.append(f"📊 Predominância IPv6 ({ipv6_count}/{total_regs}) — boa rastreabilidade.")
        if health_score < 70:
            findings.append(f"⚠️ Qualidade dos dados abaixo do ideal ({health_score}%).")

        if findings:
            briefing += "\n**Achados relevantes:**\n"
            for f in findings:
                briefing += f"- {f}\n"

        st.markdown(briefing)

        # Botão para copiar
        st.download_button(
            "📥 Baixar Resumo Executivo (.txt)",
            data=briefing.replace('**', '').replace('|', ' '),
            file_name=f"resumo_executivo_{alvo.replace(' ', '_')}.txt",
            mime="text/plain",
            key="download_exec_summary",
        )
