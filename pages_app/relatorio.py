"""
Log Enrichment - Página de Relatório PDF
Geração de relatórios básicos e profissionais com análises avançadas.
"""

import streamlit as st
import logging
from datetime import datetime

from analysis import (
    calculate_risk_scores, detect_impossible_jumps, detect_base_locations,
    generate_behavioral_profile, detect_vpn_heuristics, compute_ip_confidence,
    detect_life_patterns
)
from audit_logger import log_audit_event, generate_integrity_receipt
from report_generator import generate_professional_report
from helpers.pdf_report import generate_pdf_report

from i18n import t

logger = logging.getLogger(__name__)


def page_relatorio():
    from styles.components import section_header, empty_state
    section_header(t('relatorio.title'), t('relatorio.subtitle'), divider="orange")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('relatorio.no_data'), "📄", t('common.process_data_first'))
        return

    alvo = st.session_state.alvo or 'desconhecido'

    st.subheader("📋 Conteúdo do Relatório")
    total = len(df)
    unique = df['Ip'].nunique() if 'Ip' in df.columns else 0
    providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Registros", total)
    with c2:
        st.metric("IPs Únicos", unique)
    with c3:
        st.metric("Provedores", providers)

    tab_basic, tab_pro = st.tabs(["📄 Relatório Básico", "📊 Relatório Profissional"])

    with tab_basic:
        st.markdown("""O relatório PDF incluirá:
        - Resumo geral (alvo, total IPs, data)
        - Top 10 provedores
        - Distribuição por região e período
        - Tipo de conexão
        - Anomalias detectadas
        - Top 10 IPs recorrentes
        """)

        if st.button("📄 Gerar Relatório Básico", type="primary", key="btn_basic_pdf"):
            with st.spinner("Gerando PDF..."):
                try:
                    pdf_bytes = generate_pdf_report(df, alvo)
                    filename = f"relatorio_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    st.download_button("📥 Baixar PDF", data=pdf_bytes,
                        file_name=filename, mime="application/pdf", key="dl_basic_pdf")
                    st.success("✅ Relatório gerado!")
                except Exception as e:
                    st.error(f"Erro ao gerar PDF: {e}")

    with tab_pro:
        st.markdown("Relatório profissional com análises avançadas, cadeia de custódia e hash de integridade.")

        with st.expander("⚙️ Configuração do Relatório", expanded=True):
            rc1, rc2 = st.columns(2)
            with rc1:
                org = st.text_input("Organização", placeholder="Ex: Polícia Civil de MG", key="rpt_org")
                case_num = st.text_input("Número do Caso", placeholder="Ex: IPL 001/2025", key="rpt_case")
                analyst_name = st.text_input("Analista", placeholder="Seu nome", key="rpt_analyst")
            with rc2:
                classification = st.selectbox("Classificação",
                    ["", "CONFIDENCIAL", "RESTRITO", "SIGILOSO", "USO INTERNO"], key="rpt_class")
                include_raw = st.checkbox("Incluir tabela de dados brutos", key="rpt_raw")
                include_charts = st.checkbox("Incluir gráficos", value=True, key="rpt_charts")

        if st.button("📊 Gerar Relatório Profissional", type="primary", key="btn_pro_pdf"):
            with st.spinner("Gerando relatório profissional com análises..."):
                try:
                    analyses = {}
                    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
                    analyses['risk_scores'] = calculate_risk_scores(df, ip_col=ip_col)
                    analyses['impossible_jumps'] = detect_impossible_jumps(df)
                    analyses['base_locations'] = detect_base_locations(df)
                    analyses['behavioral_profile'] = generate_behavioral_profile(df)
                    analyses['vpn_heuristics'] = detect_vpn_heuristics(df)
                    analyses['ip_confidence'] = compute_ip_confidence(df)
                    analyses['life_patterns'] = detect_life_patterns(df)

                    receipt = generate_integrity_receipt(
                        input_file=None, output_file=None,
                        alvo=alvo, record_count=len(df))
                    config = {
                        'title': 'Relatorio de Analise de IPs',
                        'organization': org,
                        'case_number': case_num,
                        'analyst': analyst_name,
                        'classification': classification,
                        'include_raw_data': include_raw,
                        'include_charts': include_charts,
                    }

                    pdf_bytes = generate_professional_report(
                        df, alvo, config=config, analyses=analyses,
                        audit_hash=receipt.get('sha256', ''))

                    log_audit_event('report_generated', {
                        'alvo': alvo, 'type': 'professional',
                        'records': len(df), 'sha256': receipt.get('sha256', ''),
                    })

                    filename = f"relatorio_pro_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                    st.download_button("📥 Baixar Relatório Profissional", data=pdf_bytes,
                        file_name=filename, mime="application/pdf", key="dl_pro_pdf")
                    st.success("✅ Relatório profissional gerado!")

                    with st.expander("🔒 Recibo de Integridade"):
                        st.json(receipt)
                except Exception as e:
                    logger.error(f"Erro ao gerar relatório profissional: {e}")
                    st.error(f"Erro ao gerar PDF: {e}")
