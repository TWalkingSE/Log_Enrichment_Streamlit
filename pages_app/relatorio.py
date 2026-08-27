"""
Log Enrichment - Página de Relatório HTML Interativo
Geração de relatório HTML standalone com análises avançadas.
"""

import streamlit as st
import logging
import time
from datetime import datetime

from analysis import (
    calculate_risk_scores, detect_impossible_jumps, detect_base_locations,
    generate_behavioral_profile, detect_vpn_heuristics, compute_ip_confidence,
    detect_life_patterns,
    analyze_subnet_patterns, analyze_provider_timing,
    detect_digital_silence, validate_timezone_consistency,
    detect_shared_wifi, detect_geo_changes,
    cross_target_correlation,
)
import json
import os
from audit_logger import log_audit_event, generate_integrity_receipt
from html_report_generator import generate_html_report

from i18n import t

logger = logging.getLogger(__name__)


def _try(fn, *args, **kwargs):
    """Executa uma análise tolerando falhas; retorna None em caso de erro."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        logger.warning(f"Análise {getattr(fn, '__name__', fn)} falhou: {exc}")
        return None


def _stage(name, rows, fn, *args, **kwargs):
    """Executa uma etapa do relatório registrando início, fim e duração.

    A ordem destes registros no log é o que permite localizar em qual análise
    uma falha ou travamento ocorreu — sem eles, um MemoryError vindo de uma
    extensão C/C++ não deixa rastro utilizável.
    """
    logger.info("relatorio.stage.start %s rows=%d", name, rows)
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    logger.info("relatorio.stage.done %s %.1fs", name, time.perf_counter() - t0)
    return result


def page_relatorio():
    from styles.components import section_header, empty_state
    section_header(t('relatorio.title'), t('relatorio.subtitle'), divider="orange")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('relatorio.no_data'), "📄", t('common.process_data_first'))
        return

    alvo = st.session_state.alvo or 'desconhecido'

    st.subheader("📋 Pré-visualização do Relatório")
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

    with st.expander("⚙️ Configuração do Relatório", expanded=True):
        rc1, rc2 = st.columns(2)
        with rc1:
            org = st.text_input("Organização", placeholder="Ex: Polícia Civil de MG", key="rpt_org")
            case_num = st.text_input("Número do Caso", placeholder="Ex: IPL 001/2025", key="rpt_case")
            analyst_name = st.text_input("Analista", placeholder="Seu nome", key="rpt_analyst")
        with rc2:
            classification = st.selectbox("Classificação",
                ["", "CONFIDENCIAL", "RESTRITO", "SIGILOSO", "USO INTERNO"], key="rpt_class")
            include_raw = st.checkbox("Incluir amostra de dados brutos", key="rpt_raw")

    st.markdown("""
    O relatório HTML interativo incluirá automaticamente apenas as seções relevantes:
    - **Sumário Executivo** com métricas e achados
    - **Perfil Comportamental** (quando houver dados temporais)
    - **Mapa Geográfico Interativo** com clusterização
    - **Distribuição de Provedores** com gráficos Plotly
    - **Tipos de Conexão** (residencial, móvel, proxy/VPN, hosting)
    - **Análise de Risco** com scoring por IP
    - **Saltos Impossíveis** (quando detectados)
    - **Heurísticas de VPN** (quando detectadas)
    - **Confiança de IPs** (real vs mascarado)
    - **Locais Base** (casa/trabalho estimados)
    - **Padrões de Vida** (clustering geoespacial)
    - **Silêncio Digital** (gaps > 24h, viagens, troca de chip)
    - **Consistência de Subnets** (/24 IPv4 e /48 IPv6)
    - **Validação de Fuso Horário** (atividade em horário de sono no fuso do IP)
    - **Padrão Temporal por Provedor** (always-on, agendado, esporádico, VPN programada)
    - **Mudanças Geográficas Históricas** (a partir do cache de enriquecimento)
    - **WiFi Compartilhado** e **Correlação entre Alvos** (quando houver múltiplos alvos)
    - **IPs Mais Recorrentes**
    - **Hash SHA-256** para cadeia de custódia
    """)

    if st.button("🌐 Gerar Relatório HTML Profissional", type="primary", key="btn_pro_html"):
        with st.spinner("Gerando relatório HTML interativo com análises..."):
            try:
                analyses = {}
                n_rows = len(df)
                ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
                analyses['risk_scores'] = _stage('risk_scores', n_rows, calculate_risk_scores, df, ip_col=ip_col)
                analyses['impossible_jumps'] = _stage('impossible_jumps', n_rows, detect_impossible_jumps, df)
                analyses['base_locations'] = _stage('base_locations', n_rows, detect_base_locations, df)
                analyses['behavioral_profile'] = _stage('behavioral_profile', n_rows, generate_behavioral_profile, df, alvo=alvo)
                analyses['vpn_heuristics'] = _stage('vpn_heuristics', n_rows, detect_vpn_heuristics, df)
                analyses['ip_confidence'] = _stage('ip_confidence', n_rows, compute_ip_confidence, df)
                analyses['life_patterns'] = _stage('life_patterns', n_rows, detect_life_patterns, df)

                # ── Análises adicionais (Fase 1) ──
                analyses['digital_silence'] = _try(detect_digital_silence, df)
                analyses['subnet_patterns'] = _try(analyze_subnet_patterns, df)
                analyses['timezone_consistency'] = _try(validate_timezone_consistency, df)
                analyses['provider_timing'] = _try(analyze_provider_timing, df)

                # Carrega cache para detectar mudanças geográficas históricas
                cache_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'ip_cache.json')
                cache_data = {}
                if os.path.exists(cache_path):
                    try:
                        with open(cache_path, 'r', encoding='utf-8') as cf:
                            cache_data = json.load(cf)
                    except Exception as ce:
                        logger.warning(f'Falha ao ler ip_cache.json: {ce}')
                if cache_data:
                    analyses['geo_changes'] = _try(detect_geo_changes, df, cache_data)

                # Análises cross-target (somente se houver múltiplos alvos armazenados)
                stored = st.session_state.get('stored_targets', {}) or {}
                # garante que o alvo atual também participa
                multi_targets = dict(stored)
                if alvo and alvo not in multi_targets:
                    multi_targets[alvo] = df
                if len(multi_targets) >= 2:
                    analyses['shared_wifi'] = _try(detect_shared_wifi, multi_targets)
                    analyses['cross_correlation'] = _try(cross_target_correlation, multi_targets)

                receipt = generate_integrity_receipt(
                    input_file=None, output_file=None,
                    alvo=alvo, record_count=len(df))

                # Branding & assinaturas (configuradas em Configurações > Branding)
                branding = {
                    'logo_b64': st.session_state.get('rpt_logo_b64', ''),
                    'primary_color': st.session_state.get('rpt_brand_primary', ''),
                    'accent_color': st.session_state.get('rpt_brand_accent', ''),
                    'watermark': st.session_state.get('rpt_brand_watermark', ''),
                }
                signatures = [s for s in st.session_state.get('rpt_signatures', [])
                              if (s.get('name') or s.get('role'))]

                # Cadeia de custódia
                coc = {
                    'input_file': st.session_state.get('uploaded_filename', ''),
                    'input_hash': st.session_state.get('uploaded_file_hash', ''),
                    'operator': receipt.get('operator', ''),
                    'hostname': receipt.get('hostname', ''),
                    'receipt_hash': receipt.get('receipt_hash', ''),
                    'generated_at_iso': receipt.get('generated_at', ''),
                }

                config = {
                    'title': 'Relatorio de Analise de IPs',
                    'organization': org,
                    'case_number': case_num,
                    'analyst': analyst_name,
                    'classification': classification,
                    'include_raw_data': include_raw,
                    'branding': branding,
                    'signatures': signatures,
                    'coc': coc,
                }

                html_bytes = generate_html_report(
                    df, alvo, config=config, analyses=analyses,
                    audit_hash=receipt.get('receipt_hash', ''))

                log_audit_event('report_generated', {
                    'alvo': alvo, 'type': 'html_professional',
                    'records': len(df), 'sha256': receipt.get('receipt_hash', ''),
                })

                filename = f"relatorio_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                st.download_button(
                    "📥 Baixar Relatório HTML",
                    data=html_bytes,
                    file_name=filename,
                    mime="text/html",
                    key="dl_pro_html",
                )
                st.success("✅ Relatório HTML profissional gerado! Abra o arquivo em qualquer navegador.")

                with st.expander("🔒 Recibo de Integridade"):
                    st.json(receipt)
            except MemoryError:
                logger.exception("Falha de memória ao gerar relatório HTML (%d registros)", len(df))
                st.error(
                    f"Memória insuficiente para gerar o relatório com {len(df):,} registros. "
                    .replace(',', '.') +
                    "Filtre o período ou o provedor na página de Resultados e tente novamente.")
            except Exception as e:
                logger.exception("Erro ao gerar relatório HTML")
                st.error(f"Erro ao gerar relatório HTML: {e}")
