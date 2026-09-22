"""
Log Enrichment - Página de Entrada de Dados
Upload de arquivos, colagem de texto, modo offline, processamento.
"""

import streamlit as st
import pandas as pd
import os
import io
import re
import tempfile
import logging

from data_processor import (
    extrair_ips_de_texto, detectar_formato_log,
    FORMATO_1, FORMATO_2, FORMATO_3, FORMATO_4, FORMATO_PRESERVATION_GOOGLE,
    FORMATO_DISCORD, FORMATO_TIKTOK
)
from audit_logger import log_audit_event
from validators import validate_dataframe, safe_output_path
from helpers.shared import add_log, run_processing, save_history, extract_alvo_from_filename
from i18n import t
from helpers.large_data import bump_data_version, show_truncation

logger = logging.getLogger(__name__)


def _sanitize_alvo(alvo):
    """Sanitiza o campo alvo removendo caracteres inseguros para nomes de arquivo."""
    if not alvo:
        return alvo
    # Permitir apenas alfanuméricos, espaços, hifens, underscores e pontos
    return re.sub(r'[^\w\s.\-]', '', alvo).strip()


def page_entrada():
    from styles.components import section_header
    section_header(t('entrada.title'), t('entrada.subtitle'), divider="green")

    # Falha ao restaurar a sessão anterior (app.py) precisa ser visível: sem
    # isso o analista veria "sem dados" sem saber que houve erro.
    restore_error = st.session_state.pop('_restore_error', None)
    if restore_error:
        st.warning(f"⚠️ {restore_error}")

    # Alvo + Output
    col_alvo, col_output = st.columns(2)
    with col_alvo:
        alvo = st.text_input(t('entrada.target'), value=st.session_state.alvo,
                              placeholder=t('entrada.target_placeholder'), key="alvo_input")
        st.session_state.alvo = alvo
    with col_output:
        output_file = st.text_input(t('entrada.output_file'),
                                     value=st.session_state.output_file, key="output_input")
        if not output_file.lower().endswith('.csv'):
            output_file = os.path.splitext(output_file)[0] + '.csv'
        output_file = safe_output_path(output_file, default_name='resultado_logs.csv')
        st.session_state.output_file = output_file

    # Input tabs
    tab_file, tab_text, tab_offline = st.tabs([
        t('entrada.tab_file'), t('entrada.tab_text'), t('entrada.tab_offline')
    ])

    input_data = None
    is_file_input = True
    detected_format = None

    with tab_offline:
        st.markdown(t('entrada.offline_desc'))
        offline_file = st.file_uploader(t('entrada.offline_upload_label'), type=['csv', 'xlsx', 'xls'],
                                         key="offline_upload")
        if offline_file is not None:
            try:
                if offline_file.name.endswith(('.xlsx', '.xls')):
                    df_off = pd.read_excel(io.BytesIO(offline_file.getvalue()))
                else:
                    df_off = pd.read_csv(io.BytesIO(offline_file.getvalue()), sep=';', encoding='utf-8-sig')
                st.success(t('entrada.offline_success', filename=offline_file.name, count=len(df_off), columns=str(df_off.columns.tolist()[:8])))
                if st.button(t('entrada.offline_load'), key="offline_load"):
                    st.session_state.df_resultado = df_off
                    bump_data_version()
                    if 'Alvo' in df_off.columns and not df_off['Alvo'].dropna().empty:
                        st.session_state.alvo = str(df_off['Alvo'].dropna().iloc[0])
                    st.rerun()
            except Exception as e:
                st.error(t('entrada.offline_error', error=e))

    with tab_file:
        uploaded_file = st.file_uploader(
            t('entrada.file_upload_label'), type=['txt', 'csv', 'xlsx', 'xls', 'pdf', 'html', 'htm'],
            help=t('entrada.file_upload_help')
        )
        if uploaded_file is not None:
            if not st.session_state.alvo:
                extracted = extract_alvo_from_filename(uploaded_file.name)
                if extracted:
                    st.session_state.alvo = extracted
                    st.session_state['alvo_input'] = extracted
                    st.rerun()

            suffix = os.path.splitext(uploaded_file.name)[1]
            tmp_fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix='log_enrich_')
            try:
                with os.fdopen(tmp_fd, 'wb') as f:
                    f.write(uploaded_file.getbuffer())
            except Exception:
                os.close(tmp_fd)
                raise
            input_data = temp_path
            is_file_input = True

            try:
                # Para HTMLs (WhatsApp/Meta/Google records.html)
                if uploaded_file.name.lower().endswith(('.html', '.htm')):
                    from html_parser import parse_html_file, detect_html_platform
                    html_content = uploaded_file.getvalue().decode('utf-8', errors='replace')
                    platform = detect_html_platform(html_content)
                    platform_names = {'whatsapp': 'WhatsApp', 'meta': 'Meta Platforms (Facebook/Instagram)',
                                      'google': 'Google', 'unknown': t('entrada.html_platform_unknown')}
                    st.info(f"📄 **{uploaded_file.name}** — HTML: **{platform_names.get(platform, platform)}**")

                    if platform != 'unknown':
                        preview_df, _ = parse_html_file(html_content, alvo=st.session_state.alvo or 'preview')
                        with st.expander(t('entrada.preview_title'), expanded=False):
                            if preview_df is not None and not preview_df.empty:
                                st.write(t('entrada.ips_found', count=len(preview_df)))
                                cols_preview = ['Ip', 'Data', 'Periodo']
                                if 'Porta' in preview_df.columns:
                                    cols_preview.insert(1, 'Porta')
                                available = [c for c in cols_preview if c in preview_df.columns]
                                st.dataframe(preview_df[available].head(20), use_container_width=True, hide_index=True)
                                show_truncation(min(20, len(preview_df)), len(preview_df))
                            else:
                                st.warning(t('entrada.no_ip_html'))
                        # Store HTML content + platform for processing
                        content = html_content
                        detected_format = f'html_{platform}'
                    else:
                        st.error(t('entrada.html_unknown'))
                        content = ''
                        detected_format = 'unknown'

                # Para PDFs (Discord, etc) — extrair texto com pdfplumber
                elif uploaded_file.name.lower().endswith('.pdf'):
                    content = ''
                    try:
                        import pdfplumber
                        text_parts = []
                        with pdfplumber.open(io.BytesIO(uploaded_file.getvalue())) as pdf:
                            for page_num, page in enumerate(pdf.pages, 1):
                                try:
                                    page_text = page.extract_text()
                                    if page_text:
                                        text_parts.append(page_text)
                                except Exception as e:
                                    logger.warning("Página %d do PDF não extraída: %s", page_num, e)
                        content = '\n'.join(text_parts)
                        if not content.strip():
                            with pdfplumber.open(temp_path) as pdf_file:
                                text_parts = []
                                for page_num, page in enumerate(pdf_file.pages, 1):
                                    try:
                                        page_text = page.extract_text()
                                        if page_text:
                                            text_parts.append(page_text)
                                    except Exception as e:
                                        logger.warning("Página %d do PDF não extraída: %s", page_num, e)
                                content = '\n'.join(text_parts)
                    except ImportError:
                        st.warning("Instale 'pdfplumber' para processar PDFs: pip install pdfplumber")
                    except Exception as e:
                        logger.warning(f"Erro ao extrair texto do PDF: {e}")

                    # Detectar formato e exibir mensagem imediatamente (como HTML faz)
                    detected_format = detectar_formato_log(content) if content.strip() else 'generico'
                    format_names = {
                        'discord': 'Discord', 'meta': 'Meta Platforms',
                        'whatsapp': 'WhatsApp', 'google': 'Google',
                        'preservation_google': 'Preservation Google',
                        'tiktok': 'TikTok',
                        'generico': t('entrada.format_generic')
                    }
                    st.info(f"📄 **{uploaded_file.name}** — PDF: **{format_names.get(detected_format, detected_format.upper())}**")

                    # Pré-visualização dos IPs
                    if content.strip():
                        try:
                            with st.expander(t('entrada.preview_title'), expanded=False):
                                preview_df = extrair_ips_de_texto(content, False, alvo=st.session_state.alvo or 'preview')
                                if preview_df is not None and not preview_df.empty:
                                    st.write(t('entrada.ips_found', count=len(preview_df)))
                                    cols_preview = ['Ip', 'Data', 'Periodo']
                                    if 'Porta' in preview_df.columns:
                                        cols_preview.insert(1, 'Porta')
                                    if 'Evento' in preview_df.columns:
                                        cols_preview.insert(1, 'Evento')
                                    if 'User_Agent' in preview_df.columns:
                                        cols_preview.insert(1, 'User_Agent')
                                    if 'User_ID' in preview_df.columns:
                                        cols_preview.insert(1, 'User_ID')
                                    available = [c for c in cols_preview if c in preview_df.columns]
                                    st.dataframe(preview_df[available].head(20), use_container_width=True, hide_index=True)
                                    show_truncation(min(20, len(preview_df)), len(preview_df))
                                else:
                                    st.warning(t('entrada.no_ip_pdf'))
                        except Exception as e:
                            logger.warning(f"Erro na pré-visualização do PDF: {e}")

                else:
                    content = uploaded_file.getvalue().decode('utf-8', errors='replace')
                    detected_format = detectar_formato_log(content)
                    st.info(f"📄 **{uploaded_file.name}** — Formato: **{detected_format.upper()}**")

                    with st.expander(t('entrada.preview_title'), expanded=False):
                        preview_df = extrair_ips_de_texto(content, False, alvo=st.session_state.alvo or 'preview')
                        if preview_df is not None and not preview_df.empty:
                            st.write(t('entrada.ips_found', count=len(preview_df)))
                            cols_preview = ['Ip', 'Data', 'Periodo']
                            if 'Porta' in preview_df.columns:
                                cols_preview.insert(1, 'Porta')
                            if 'Evento' in preview_df.columns:
                                cols_preview.insert(1, 'Evento')
                            if 'User_Agent' in preview_df.columns:
                                cols_preview.insert(1, 'User_Agent')
                            if 'User_ID' in preview_df.columns:
                                cols_preview.insert(1, 'User_ID')
                            available = [c for c in cols_preview if c in preview_df.columns]
                            st.dataframe(preview_df[available].head(20), use_container_width=True, hide_index=True)
                            show_truncation(min(20, len(preview_df)), len(preview_df))
                        else:
                            st.warning(t('entrada.no_ip_file'))
            except Exception as e:
                logger.warning(f"Erro na pré-visualização: {e}")
                st.info(f"📄 **{uploaded_file.name}** carregado")

    with tab_text:
        example_map = {
            "Genérico (Lista de IPs)": FORMATO_1,
            "Meta Platforms (Instagram/Facebook)": FORMATO_2,
            "WhatsApp": FORMATO_3,
            "Google": FORMATO_4,
            "Preservation Google": FORMATO_PRESERVATION_GOOGLE,
            "Discord": FORMATO_DISCORD,
            "TikTok": FORMATO_TIKTOK
        }

        def _on_example_change():
            sel = st.session_state.example_select
            st.session_state.pasted_text = example_map.get(sel, "")

        example = st.selectbox(
            t('entrada.load_example'),
            [t('entrada.select_placeholder'), "Genérico (Lista de IPs)",
             "Meta Platforms (Instagram/Facebook)", "WhatsApp", "Google",
             "Preservation Google", "Discord", "TikTok"],
            key="example_select",
            on_change=_on_example_change
        )

        pasted_text = st.text_area(t('entrada.paste_text'),
                                    height=250, placeholder=t('entrada.paste_placeholder'), key="pasted_text")
        if pasted_text.strip():
            try:
                detected_format = detectar_formato_log(pasted_text)
                st.info(t('entrada.format_detected', format=detected_format.upper()))
            except Exception as e:
                logger.warning(f"Erro ao detectar formato: {e}")
            input_data = pasted_text
            is_file_input = False

            with st.expander(t('entrada.preview_title'), expanded=False):
                preview_df = extrair_ips_de_texto(pasted_text, False, alvo=st.session_state.alvo or 'preview')
                if preview_df is not None and not preview_df.empty:
                    st.write(t('entrada.ips_found', count=len(preview_df)))
                    cols_preview = ['Ip', 'Data', 'Periodo']
                    if 'Porta' in preview_df.columns:
                        cols_preview.insert(1, 'Porta')
                    if 'Evento' in preview_df.columns:
                        cols_preview.insert(1, 'Evento')
                    if 'User_Agent' in preview_df.columns:
                        cols_preview.insert(1, 'User_Agent')
                    if 'User_ID' in preview_df.columns:
                        cols_preview.insert(1, 'User_ID')
                    available = [c for c in cols_preview if c in preview_df.columns]
                    st.dataframe(preview_df[available].head(20), use_container_width=True, hide_index=True)
                    show_truncation(min(20, len(preview_df)), len(preview_df))
                else:
                    st.warning(t('entrada.no_ip_detected'))

    # Options
    st.divider()
    with st.expander(t('entrada.processing_options'), expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.session_state.incremental = st.checkbox(t('entrada.incremental'), value=st.session_state.incremental)
        with c2:
            st.session_state.use_cache = st.checkbox(t('entrada.cache'), value=st.session_state.use_cache)
        with c3:
            st.session_state.batch_size = st.number_input(t('entrada.batch'), 1, 10000, value=st.session_state.batch_size)
        with c4:
            st.session_state.period = st.number_input(t('entrada.period_seconds'), 0, 300, value=st.session_state.period)

    # Process
    st.divider()
    col_btn1, col_btn2, col_btn3 = st.columns([2, 1, 1])

    with col_btn1:
        if st.button(t('entrada.start_processing'), type="primary",
                      disabled=st.session_state.processing):
            if input_data is None:
                st.error(t('entrada.no_input'))
            else:
                from helpers.job_control import JobCancelled, clear_cancel, request_cancel
                clear_cancel()
                alvo_val = _sanitize_alvo(st.session_state.alvo.strip()) or t('common.unknown')
                if alvo_val == t('common.unknown'):
                    st.warning(t('entrada.no_target_warning'))
                output = st.session_state.output_file
                cache_file = 'ip_cache.json' if st.session_state.use_cache else None

                st.session_state.processing = True
                st.session_state.log_messages = []
                add_log(t('entrada.starting'))

                with st.status(t('entrada.processing_ips'), expanded=True) as status:
                    try:
                        st.write(t('entrada.extracting_ips'))
                        st.caption(t('entrada.cancel_hint'))
                        progress_bar = st.progress(0, text=t('entrada.starting_label'))

                        def update_progress(current, total, total_records=0):
                            if total > 0:
                                pct = min(current / total, 1.0)
                                rec_info = t('entrada.of_records', total=f'{total_records:,}') if total_records else ""
                                progress_bar.progress(pct, text=t('entrada.querying_ips', current=f'{current:,}', total=f'{total:,}', rec_info=rec_info, pct=f'{pct*100:.0f}'))

                        api_key = st.session_state.api_key or None
                        result = run_processing(
                            input_data, output, is_file_input,
                            st.session_state.batch_size, st.session_state.period,
                            cache_file, st.session_state.incremental, alvo_val,
                            api_key=api_key,
                            progress_callback=update_progress
                        )

                        if result is not None and not result.empty:
                            st.session_state.df_resultado = result
                            bump_data_version()
                            try:
                                from helpers.persistence import save_dataframe
                                save_dataframe(result, name='current')
                                if alvo_val:
                                    save_dataframe(result, name=alvo_val)
                            except Exception as persist_err:
                                logger.debug(f"Persistência opcional ignorada: {persist_err}")
                            add_log(t('entrada.completed', count=len(result)))
                            save_history(alvo_val, len(result), output, detected_format or t('common.unknown'))
                            status.update(label=t('entrada.records_processed', count=len(result)), state="complete")

                            log_audit_event('processing_complete', {
                                'alvo': alvo_val, 'records': len(result),
                                'format': detected_format or t('common.unknown'),
                            })

                            try:
                                validation = validate_dataframe(result)
                                if not validation.get('is_valid', True):
                                    all_errs = []
                                    for layer in ['schema', 'domain', 'integrity']:
                                        vr = validation.get(layer)
                                        if vr and hasattr(vr, 'errors'):
                                            all_errs.extend(vr.errors)
                                    for err in all_errs[:5]:
                                        msg = err.get('message', str(err)) if isinstance(err, dict) else str(err)
                                        st.warning(t('entrada.validation_warning', msg=msg))
                                n_warn = validation.get('total_warnings', 0)
                                if n_warn > 0:
                                    st.caption(t('entrada.validation_notices', count=n_warn))
                            except Exception as val_err:
                                logger.debug(f"Validação ignorada: {val_err}")

                            st.warning(t('entrada.api_precision_warning'))

                        else:
                            st.warning(t('entrada.no_valid_ip'))
                            status.update(label=t('entrada.no_ip_found'), state="error")
                    except JobCancelled as e:
                        st.warning(str(e))
                        add_log(str(e))
                        status.update(label="Cancelado", state="error")
                        log_audit_event('processing_cancelled', {'alvo': alvo_val})
                    except Exception as e:
                        st.error(t('entrada.error_label', error=str(e)))
                        add_log(f"Erro: {str(e)}")
                        status.update(label=t('entrada.error_processing'), state="error")
                    finally:
                        st.session_state.processing = False
                        clear_cancel()
                        if is_file_input and input_data and os.path.exists(str(input_data)):
                            try:
                                os.remove(input_data)
                            except Exception as e:
                                logger.warning(f"Erro ao remover arquivo temporário: {e}")

    with col_btn2:
        if st.button(t('entrada.request_cancel'), key="btn_request_cancel"):
            from helpers.job_control import request_cancel
            request_cancel()
            st.toast(t('entrada.cancel_requested'))
        if st.session_state.df_resultado is not None and os.path.exists(st.session_state.output_file):
            with open(st.session_state.output_file, 'rb') as f:
                st.download_button(t('entrada.download_csv'), data=f,
                    file_name=os.path.basename(st.session_state.output_file),
                    mime="text/csv")

    with col_btn3:
        if st.button(t('entrada.clear_btn')):
            st.session_state.df_resultado = None
            bump_data_version()
            st.session_state.log_messages = []
            try:
                from helpers.persistence import clear_dataframe
                clear_dataframe('current')
            except Exception as e:
                logger.warning("Falha ao limpar persistência: %s", e)
            st.rerun()

    # Log
    if st.session_state.log_messages:
        with st.expander(t('entrada.log_title'), expanded=False):
            st.code("\n".join(st.session_state.log_messages[-30:]), language=None)

    # History
    if st.session_state.history:
        with st.expander(t('entrada.history_title'), expanded=False):
            hist_df = pd.DataFrame(st.session_state.history)
            st.dataframe(hist_df, use_container_width=True, hide_index=True)

    # Load existing result
    output_file = st.session_state.output_file
    if st.session_state.df_resultado is None and output_file:
        if output_file and os.path.exists(output_file):
            if st.button(t('entrada.load_file', filename=os.path.basename(output_file))):
                try:
                    if output_file.lower().endswith(('.xlsx', '.xls')):
                        df = pd.read_excel(output_file)
                    else:
                        df = pd.read_csv(output_file, sep=';', encoding='utf-8-sig')
                    st.session_state.df_resultado = df
                    bump_data_version()
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro: {e}")
