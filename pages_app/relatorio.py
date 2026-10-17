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
from audit_logger import log_audit_event, generate_integrity_receipt
from html_report_generator import (ANALISES_NAO_APLICAVEIS_AGREGADO, formato_agregado,
                                   generate_html_report)

from i18n import t

logger = logging.getLogger(__name__)


def _try(falhas, rotulo, fn, *args, **kwargs):
    """Executa uma análise opcional tolerando falhas; retorna None em caso de erro.

    A falha não some: vai para o log com traceback e para `falhas`, que a
    página exibe e o relatório declara como seção omitida. Antes a seção
    simplesmente não aparecia — ausência de achado e falha de análise ficavam
    indistinguíveis no laudo. MemoryError sobe (é tratado no nível da página).
    """
    try:
        return fn(*args, **kwargs)
    except MemoryError:
        raise
    except Exception as exc:
        logger.exception("Análise %s falhou", getattr(fn, '__name__', fn))
        falhas.append(f"{rotulo} (erro: {exc})")
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

    st.subheader(t('relatorio.preview_title'))
    total = len(df)
    unique = df['Ip'].nunique() if 'Ip' in df.columns else 0
    providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric(t('relatorio.records'), total)
    with c2:
        st.metric(t('relatorio.unique_ips'), unique)
    with c3:
        st.metric(t('relatorio.providers'), providers)

    # Linha de formato agregado não é acesso — o laudo declara isso e omite as
    # análises que supõem uma linha por acesso; o analista vê antes de gerar.
    agregado = formato_agregado(df)
    if agregado == 'google_atividades':
        st.info(t('resultados.google_agg_note_activities'))
    elif agregado == 'google_conexoes':
        st.info(t('resultados.google_agg_note_connections'))

    with st.expander(t('relatorio.config_title'), expanded=True):
        rc1, rc2 = st.columns(2)
        with rc1:
            org = st.text_input(t('relatorio.organization'), placeholder=t('relatorio.org_placeholder'), key="rpt_org")
            case_num = st.text_input(t('relatorio.case_number'), placeholder=t('relatorio.case_placeholder'),
                                     key="rpt_case")
            analyst_name = st.text_input(t('relatorio.analyst'), placeholder=t('relatorio.analyst_placeholder'),
                                         key="rpt_analyst")
        with rc2:
            # Os valores vão para o laudo, que é redigido em português.
            classification = st.selectbox(t('relatorio.classification'),
                ["", "CONFIDENCIAL", "RESTRITO", "SIGILOSO", "USO INTERNO"],
                format_func=lambda v: v or t('relatorio.classification_none'), key="rpt_class")
            include_raw = st.checkbox(t('relatorio.include_raw'), key="rpt_raw")

    st.markdown(t('relatorio.sections_intro'))

    if st.button(t('relatorio.generate_html'), type="primary", key="btn_pro_html"):
        with st.spinner(t('relatorio.generating_html')):
            try:
                analyses = {}
                n_rows = len(df)
                ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
                # Google Aggregated Activities: as análises que supõem uma linha
                # por acesso não rodam (o laudo lista quais e por quê), e o risco
                # não conta "baixa frequência" — linha de IP não é acesso.
                pular = ANALISES_NAO_APLICAVEIS_AGREGADO if agregado else {}
                secoes_falhas = []

                def _etapa(nome, fn, *args, **kwargs):
                    if nome not in pular:
                        analyses[nome] = _stage(nome, n_rows, fn, *args, **kwargs)

                def _opcional(nome, rotulo, fn, *args):
                    if nome not in pular:
                        analyses[nome] = _try(secoes_falhas, rotulo, fn, *args)

                _etapa('risk_scores', calculate_risk_scores, df, ip_col=ip_col,
                       fator_frequencia=not agregado)
                _etapa('impossible_jumps', detect_impossible_jumps, df)
                _etapa('base_locations', detect_base_locations, df)
                _etapa('behavioral_profile', generate_behavioral_profile, df, alvo=alvo)
                _etapa('vpn_heuristics', detect_vpn_heuristics, df)
                _etapa('ip_confidence', compute_ip_confidence, df)
                _etapa('life_patterns', detect_life_patterns, df)

                # ── Análises adicionais (Fase 1) ──
                _opcional('digital_silence', "Silêncio digital", detect_digital_silence, df)
                _opcional('subnet_patterns', "Consistência de subnets", analyze_subnet_patterns, df)
                _opcional('timezone_consistency', "Validação de fuso horário",
                          validate_timezone_consistency, df)
                _opcional('provider_timing', "Padrão temporal por provedor",
                          analyze_provider_timing, df)

                # Mudanças geográficas históricas, pelo leitor único do cache
                # (desembrulha envelope assinado; histórico não filtra TTL).
                from api_client import read_ip_cache
                cache_data = {}
                try:
                    cache_data = read_ip_cache()
                except MemoryError:
                    raise
                except Exception as ce:
                    logger.exception('Falha ao ler o cache de IPs')
                    secoes_falhas.append(f"Mudanças geográficas históricas (cache ilegível: {ce})")
                if cache_data:
                    analyses['geo_changes'] = _try(secoes_falhas, "Mudanças geográficas históricas",
                                                   detect_geo_changes, df, cache_data)

                # Análises cross-target (somente se houver múltiplos alvos armazenados)
                stored = st.session_state.get('stored_targets', {}) or {}
                # garante que o alvo atual também participa
                multi_targets = dict(stored)
                if alvo and alvo not in multi_targets:
                    multi_targets[alvo] = df
                if len(multi_targets) >= 2:
                    analyses['shared_wifi'] = _try(secoes_falhas, "WiFi compartilhado",
                                                   detect_shared_wifi, multi_targets)
                    analyses['cross_correlation'] = _try(secoes_falhas, "Correlação entre alvos",
                                                         cross_target_correlation, multi_targets)

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
                    'secoes_omitidas': secoes_falhas,
                }

                html_bytes = generate_html_report(
                    df, alvo, config=config, analyses=analyses,
                    audit_hash=receipt.get('receipt_hash', ''))

                evento_relatorio = log_audit_event('report_generated', {
                    'alvo': alvo, 'type': 'html_professional',
                    'records': len(df), 'sha256': receipt.get('receipt_hash', ''),
                })

                filename = f"relatorio_{alvo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                st.download_button(
                    t('relatorio.download_html'),
                    data=html_bytes,
                    file_name=filename,
                    mime="text/html",
                    key="dl_pro_html",
                )
                st.success(t('relatorio.html_generated'))
                if secoes_falhas:
                    st.warning(t('relatorio.sections_omitted') + "\n\n"
                               + "\n".join(f"- {s}" for s in secoes_falhas))
                for evento in (receipt.get('_audit_event'), evento_relatorio):
                    if evento is not None and not evento.get('_persisted', True):
                        st.error(t('relatorio.audit_not_saved'))
                        break

                with st.expander(t('relatorio.integrity_receipt')):
                    st.json({k: v for k, v in receipt.items() if not k.startswith('_')})
            except MemoryError:
                logger.exception("Falha de memória ao gerar relatório HTML (%d registros)", len(df))
                st.error(t('relatorio.memory_error', rows=f"{len(df):,}".replace(',', '.')))
            except Exception as e:
                logger.exception("Erro ao gerar relatório HTML")
                st.error(t('relatorio.html_error', error=e))
