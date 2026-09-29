"""
Log Enrichment - Página de Configurações
API, cache, histórico, audit trail.
"""

import streamlit as st
import pandas as pd
import os
import json
import logging
from datetime import datetime

from audit_logger import count_audit_events, get_audit_trail, verify_audit_integrity

from helpers.large_data import show_truncation
from i18n import t

logger = logging.getLogger(__name__)


@st.cache_data(ttl=300, max_entries=2, show_spinner=False)
def _cache_info(cache_path, mtime):
    """(entradas, assinado). `mtime` na chave: relê só quando o arquivo muda.

    Antes o JSON inteiro (MBs) era carregado a cada rerun, porque o corpo de
    toda aba de `st.tabs` executa mesmo fechado.
    """
    from helpers.signed_cache import is_signed_envelope
    with open(cache_path, 'r', encoding='utf-8') as f:
        cache_data = json.load(f)
    signed = is_signed_envelope(cache_data)
    n_entries = len(cache_data.get('payload', {})) if signed else len(cache_data)
    return n_entries, signed


def page_configuracoes():
    from styles.components import section_header
    from advanced_analysis import (
        TOR_CACHE_TTL_HOURS,
        get_tor_exit_cache_status,
        update_tor_exit_nodes_cache,
    )

    section_header(t('configuracoes.title'), t('configuracoes.subtitle'), divider="gray")

    tab_api, tab_ai, tab_brand, tab_audit = st.tabs([
        t('configuracoes.tab_api'), t('configuracoes.tab_ai'),
        t('configuracoes.tab_brand'),
        t('configuracoes.tab_audit')
    ])

    with tab_api:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader(t('configuracoes.api_title'))
            air_gapped = st.toggle(
                t('configuracoes.air_gapped'),
                value=bool(st.session_state.get('air_gapped', False)),
                key="cfg_air_gapped",
                help=t('configuracoes.air_gapped_help'),
            )
            st.session_state.air_gapped = air_gapped
            if air_gapped:
                st.warning(t('configuracoes.air_gapped_active'))
            api_key = st.text_input(
                t('configuracoes.api_key_label'),
                value=st.session_state.api_key, type="password",
                placeholder=t('configuracoes.api_key_placeholder'),
                disabled=air_gapped)
            st.session_state.api_key = api_key
            if air_gapped:
                st.info(t('configuracoes.api_key_ignored'))
            elif api_key:
                st.success(t('configuracoes.api_key_configured'))
            else:
                st.info(t('configuracoes.api_free_info'))

            st.subheader(t('configuracoes.cache_title'))
            st.session_state.use_cache = st.toggle(
                t('configuracoes.use_cache'), value=st.session_state.use_cache)
            from api_client import IP_CACHE_PATH
            if os.path.exists(IP_CACHE_PATH):
                try:
                    n_entries, signed = _cache_info(IP_CACHE_PATH, os.path.getmtime(IP_CACHE_PATH))
                    signed_note = " (HMAC)" if signed else ""
                    st.caption(t('configuracoes.cache_count', count=n_entries) + signed_note)
                    c_exp, c_clr = st.columns(2)
                    with c_exp:
                        if st.button(t('configuracoes.export_signed_cache'), key='btn_export_signed_cache'):
                            try:
                                from helpers.signed_cache import build_signed_package, get_cache_hmac_secret
                                if not get_cache_hmac_secret():
                                    st.error(t('configuracoes.signed_cache_no_secret'))
                                else:
                                    # Leitor único: verifica a assinatura de um
                                    # cache já assinado antes de reassiná-lo.
                                    from api_client import read_ip_cache
                                    pkg = build_signed_package(read_ip_cache(IP_CACHE_PATH))
                                    st.download_button(
                                        t('configuracoes.download_signed_cache'),
                                        json.dumps(pkg, ensure_ascii=False, indent=2),
                                        'ip_cache.signed.json',
                                        'application/json',
                                        key='dl_signed_cache',
                                    )
                            except Exception as e:
                                logger.exception("Falha ao exportar cache assinado")
                                st.error(str(e))
                    with c_clr:
                        if st.button(t('configuracoes.clear_cache')):
                            os.remove(IP_CACHE_PATH)
                            st.success(t('configuracoes.cache_cleared'))
                            st.rerun()
                except (OSError, ValueError) as e:
                    logger.exception("Erro ao ler cache")
                    st.warning(t('configuracoes.cache_unreadable', error=e))

            signed_up = st.file_uploader(
                t('configuracoes.import_signed_cache'),
                type=['json'],
                key='signed_cache_upload',
            )
            if signed_up is not None and st.button(t('configuracoes.apply_signed_cache'), key='btn_apply_signed'):
                try:
                    from helpers.signed_cache import is_signed_envelope, verify_signed_package
                    pkg = json.loads(signed_up.getvalue().decode('utf-8'))
                    if is_signed_envelope(pkg):
                        ok, msg, payload = verify_signed_package(pkg)
                        if not ok:
                            st.error(t('configuracoes.signed_cache_bad', msg=msg))
                        else:
                            # Atômico: uma falha no meio não destrói o cache atual.
                            from api_client import IP_CACHE_PATH
                            from helpers.atomic_io import atomic_write_json
                            atomic_write_json(IP_CACHE_PATH, pkg, ensure_ascii=False)
                            st.success(t('configuracoes.signed_cache_imported', count=len(payload)))
                            st.rerun()
                    else:
                        st.error(t('configuracoes.signed_cache_not_envelope'))
                except Exception as e:
                    st.error(str(e))

            st.subheader(t('configuracoes.history_title'))
            if st.session_state.history:
                st.caption(t('configuracoes.history_count', count=len(st.session_state.history)))
                if st.button(t('configuracoes.clear_history')):
                    st.session_state.history = []
                    from helpers.shared import HISTORY_FILE
                    if os.path.exists(HISTORY_FILE):
                        os.remove(HISTORY_FILE)
                    st.success(t('configuracoes.history_cleared'))
                    st.rerun()

            st.subheader(t('configuracoes.shodan_title'))
            if os.getenv('SHODAN_API_KEY', ''):
                st.success(t('configuracoes.shodan_configured'))
            else:
                st.info(t('configuracoes.shodan_info'))

            st.subheader(t('configuracoes.tor_title'))
            tor_auto_check = st.toggle(
                t('configuracoes.tor_auto_check'),
                value=st.session_state.get('tor_auto_check', False),
                key="cfg_tor_toggle")
            st.session_state['tor_auto_check'] = tor_auto_check
            if tor_auto_check:
                st.caption(t('configuracoes.tor_auto_caption'))

            tor_cache_status = get_tor_exit_cache_status(ttl_hours=TOR_CACHE_TTL_HOURS)
            if tor_cache_status.get('available'):
                cached_at = tor_cache_status.get('cached_at')
                cached_label = (
                    datetime.fromtimestamp(cached_at).strftime('%d/%m/%Y %H:%M:%S')
                    if cached_at else t('configuracoes.tor_cache_unknown')
                )
                freshness = (
                    t('configuracoes.tor_cache_fresh')
                    if not tor_cache_status.get('is_stale')
                    else t('configuracoes.tor_cache_stale')
                )
                st.caption(t(
                    'configuracoes.tor_cache_info',
                    count=tor_cache_status.get('node_count', 0),
                    date=cached_label,
                    age=f"{tor_cache_status.get('age_hours', 0):.1f}",
                    freshness=freshness,
                ))
            else:
                st.caption(t('configuracoes.tor_no_cache'))

            if st.button(t('configuracoes.tor_refresh'), key="cfg_tor_refresh"):
                with st.status(t('configuracoes.tor_refreshing')) as status:
                    result = update_tor_exit_nodes_cache()
                    st.session_state['cfg_tor_refresh_result'] = result
                    if result['success']:
                        total = result['node_count']
                        label = t('configuracoes.tor_updated', count=total)
                        if result.get('source_errors'):
                            label += t('configuracoes.tor_partial')
                        status.update(label=label, state="complete")
                    else:
                        status.update(label=t('configuracoes.tor_failed'), state="error")

            refresh_result = st.session_state.get('cfg_tor_refresh_result')
            if refresh_result:
                if refresh_result.get('success'):
                    st.success(t(
                        'configuracoes.tor_success_detail',
                        count=refresh_result['node_count'],
                        bulk=refresh_result['source_counts'].get('torbulkexitlist', 0),
                        onionoo=refresh_result['source_counts'].get('onionoo', 0),
                    ))
                    if refresh_result.get('source_errors'):
                        warning_details = '; '.join(
                            f"{source}: {error}"
                            for source, error in refresh_result['source_errors'].items()
                        )
                        st.warning(t('configuracoes.tor_partial_warning', details=warning_details))
                else:
                    st.error(refresh_result.get('error', t('configuracoes.tor_failed')))

            st.caption(t('configuracoes.tor_automation'))

        with c2:
            st.subheader(t('configuracoes.formats_title'))
            # Os mesmos exemplos de "Carregar exemplo" na Entrada — antes esta
            # lista era uma cópia à parte e não tinha Discord nem Preservation.
            from data_processor import (
                FORMATO_1, FORMATO_2, FORMATO_3, FORMATO_4, FORMATO_DISCORD,
                FORMATO_PRESERVATION_GOOGLE, FORMATO_TIKTOK,
            )
            exemplos = [
                (t('configuracoes.format_generic'), FORMATO_1),
                ("Meta Platforms (Instagram/Facebook)", FORMATO_2),
                ("WhatsApp", FORMATO_3),
                ("Google", FORMATO_4),
                ("Preservation Google", FORMATO_PRESERVATION_GOOGLE),
                ("Discord", FORMATO_DISCORD),
                ("TikTok (Events IP Data)", FORMATO_TIKTOK),
            ]
            for n, (nome, exemplo) in enumerate(exemplos, start=1):
                with st.expander(t('configuracoes.format_n', n=n, name=nome)):
                    st.code(exemplo.strip(), language=None)
            st.subheader(t('configuracoes.output_formats_title'))
            st.markdown(t('configuracoes.output_formats'))

    with tab_ai:
        st.subheader(t('configuracoes.ai_title'))
        st.caption(t('configuracoes.ai_subtitle'))

        from ai_assistant import (
            AI_MODELS,
            check_model_available,
            check_ollama_status,
            get_default_ai_tier,
            test_ollama_inference,
        )

        default_tier = st.session_state.get('ai_tier', get_default_ai_tier())
        if default_tier not in AI_MODELS:
            default_tier = get_default_ai_tier()

        st.info(t('configuracoes.ai_ollama_info'))

        tier_options = {
            "lite": t('configuracoes.ai_tier_lite_label'),
            "standard": t('configuracoes.ai_tier_standard_label'),
            "premium": t('configuracoes.ai_tier_premium_label'),
        }
        selected_tier = st.radio(
            t('configuracoes.ai_select_tier'),
            options=list(tier_options.keys()),
            format_func=lambda x: tier_options[x],
            index=list(tier_options.keys()).index(default_tier),
            key="cfg_ai_tier"
        )
        st.session_state['ai_tier'] = selected_tier
        model_info = AI_MODELS[selected_tier]

        c_ai1, c_ai2 = st.columns(2)
        with c_ai1:
            st.markdown(t('configuracoes.ai_connection'))
            ai_url = st.text_input(
                t('configuracoes.ai_url_label'),
                value=st.session_state.get('ai_ollama_url', 'http://localhost:11434'),
                key="cfg_ai_url"
            )
            st.session_state['ai_ollama_url'] = ai_url

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                connection_clicked = st.button(t('configuracoes.ai_test_connection'), key="cfg_ai_test")
            with btn_col2:
                inference_clicked = st.button(t('configuracoes.ai_test_inference'), key="cfg_ai_infer_test")

            if connection_clicked:
                status = check_ollama_status(ai_url)
                st.session_state['cfg_ai_status_result'] = status
                if status['online']:
                    st.success(t('configuracoes.ai_online', count=len(status['models'])))
                    for m in status['models']:
                        model_name = m.get('name', 'unknown')
                        model_size = m.get('size', 0)
                        size_gb = model_size / (1024**3) if model_size else 0
                        st.caption(f"  • `{model_name}` ({size_gb:.1f} GB)")
                    if not check_model_available(model_info['model'], ai_url):
                        st.warning(t('configuracoes.ai_model_not_installed', model=model_info['model']))
                else:
                    st.error(t('configuracoes.ai_offline', error=status.get('error', '')))
                    st.code("# Para iniciar o Ollama:\nollama serve", language="bash")

            if inference_clicked:
                inference_result = test_ollama_inference(model_info['model'], ai_url)
                st.session_state['cfg_ai_inference_result'] = inference_result
                if inference_result['success']:
                    st.success(t(
                        'configuracoes.ai_inference_ok',
                        elapsed=f"{inference_result['elapsed_seconds']:.1f}",
                        response=inference_result['response'],
                    ))
                else:
                    st.warning(t('configuracoes.ai_inference_failed', error=inference_result['error']))

            cached_status = st.session_state.get('cfg_ai_status_result')
            if cached_status and not connection_clicked:
                if cached_status.get('online'):
                    st.caption(t('configuracoes.ai_status_cached', count=len(cached_status.get('models', []))))
                else:
                    st.caption(t('configuracoes.ai_status_cached_error', error=cached_status.get('error', '')))

            cached_inference = st.session_state.get('cfg_ai_inference_result')
            if cached_inference and not inference_clicked:
                if cached_inference.get('success'):
                    st.caption(t(
                        'configuracoes.ai_inference_cached',
                        elapsed=f"{cached_inference['elapsed_seconds']:.1f}",
                        model=cached_inference['model_used'],
                    ))
                else:
                    st.caption(t(
                        'configuracoes.ai_inference_cached_error',
                        model=cached_inference['model_used'],
                        error=cached_inference['error'],
                    ))

        with c_ai2:
            st.markdown(t('configuracoes.ai_hardware'))
            st.info(t(
                'configuracoes.ai_model_info',
                model=model_info['model'],
                vram=model_info['vram'],
                ctx=f"{model_info['options']['num_ctx']:,}",
            ))
            if selected_tier == 'lite':
                st.caption(t('configuracoes.ai_tier_lite'))
            elif selected_tier == 'standard':
                st.caption(t('configuracoes.ai_tier_standard'))
            else:
                st.caption(t('configuracoes.ai_tier_premium'))
            st.markdown(t('configuracoes.ai_install_model'))
            st.code(f"ollama pull {model_info['model']}", language="bash")

        st.divider()
        st.markdown(t('configuracoes.ai_quick_guide'))
        st.code(
            t('configuracoes.ai_quick_guide_code') + "\n"
            "ollama pull qwen3.5:4b           # Lite (8GB VRAM)\n"
            "ollama pull qwen3.5:9b-q8_0     # Standard (16GB VRAM)\n"
            "ollama pull qwen3.5:27b-q4_K_M  # Premium (24GB VRAM)\n\n"
            + t('configuracoes.ai_quick_guide_code_end'), language="bash")

    with tab_brand:
        import base64
        st.subheader(t('configuracoes.brand_title'))
        st.caption(t('configuracoes.brand_subtitle'))

        b1, b2 = st.columns([1, 1])
        with b1:
            st.markdown(t('configuracoes.brand_logo'))
            logo_file = st.file_uploader(
                t('configuracoes.brand_logo_upload'), type=['png', 'jpg', 'jpeg'],
                key='cfg_brand_logo')
            if logo_file is not None:
                raw = logo_file.read()
                if len(raw) > 500 * 1024:
                    st.warning(t('configuracoes.brand_logo_large', size=len(raw)//1024))
                st.session_state['rpt_logo_b64'] = base64.b64encode(raw).decode('ascii')
                st.session_state['rpt_logo_name'] = logo_file.name
                st.success(t('configuracoes.brand_logo_loaded', name=logo_file.name))

            current_logo = st.session_state.get('rpt_logo_b64')
            if current_logo:
                st.caption(t(
                    'configuracoes.brand_logo_current',
                    name=st.session_state.get('rpt_logo_name', '(sem nome)'),
                ))
                st.image(base64.b64decode(current_logo), width=160)
                if st.button(t('configuracoes.brand_logo_remove'), key='cfg_brand_logo_clear'):
                    st.session_state.pop('rpt_logo_b64', None)
                    st.session_state.pop('rpt_logo_name', None)
                    st.rerun()

            st.markdown(t('configuracoes.brand_colors'))
            primary = st.color_picker(
                t('configuracoes.brand_primary'),
                value=st.session_state.get('rpt_brand_primary', '#818cf8'),
                key='cfg_brand_primary')
            st.session_state['rpt_brand_primary'] = primary
            accent = st.color_picker(
                t('configuracoes.brand_accent'),
                value=st.session_state.get('rpt_brand_accent', '#34d399'),
                key='cfg_brand_accent')
            st.session_state['rpt_brand_accent'] = accent

            st.markdown(t('configuracoes.brand_watermark'))
            watermark = st.text_input(
                t('configuracoes.brand_watermark_label'),
                value=st.session_state.get('rpt_brand_watermark', ''),
                placeholder=t('configuracoes.brand_watermark_placeholder'),
                key='cfg_brand_wm')
            st.session_state['rpt_brand_watermark'] = watermark

        with b2:
            st.markdown(t('configuracoes.brand_signatures'))
            st.caption(t('configuracoes.brand_signatures_caption'))
            sigs = st.session_state.get('rpt_signatures', [{'name': '', 'role': ''}] * 2)
            while len(sigs) < 4:
                sigs.append({'name': '', 'role': ''})
            sigs = sigs[:4]

            new_sigs = []
            for i in range(4):
                with st.expander(t('configuracoes.brand_signature_n', n=i + 1), expanded=(i < 2)):
                    nm = st.text_input(
                        t('configuracoes.brand_sig_name', n=i + 1),
                        value=sigs[i].get('name', ''),
                        key=f'cfg_brand_sig_name_{i}')
                    rl = st.text_input(
                        t('configuracoes.brand_sig_role', n=i + 1),
                        value=sigs[i].get('role', ''),
                        key=f'cfg_brand_sig_role_{i}')
                    new_sigs.append({'name': nm, 'role': rl})
            st.session_state['rpt_signatures'] = new_sigs

            st.markdown(t('configuracoes.brand_preview'))
            st.markdown(
                f"<div style='padding:14px;border-radius:8px;background:#0f172a;color:#f1f5f9;"
                f"border-left:4px solid {primary};font-family:Segoe UI,sans-serif;'>"
                f"<div style='color:{primary};font-weight:700;font-size:1rem;'>"
                f"{t('configuracoes.brand_example_title')}</div>"
                f"<div style='font-size:0.85rem;margin-top:6px;'>{t('configuracoes.brand_example_text')} "
                f"<span style='color:{accent};font-weight:600;'>{t('configuracoes.brand_example_accent')}</span> "
                f"{t('configuracoes.brand_example_applied')}</div>"
                f"</div>", unsafe_allow_html=True)

    with tab_audit:
        st.subheader(t('configuracoes.audit_title'))
        st.caption(t('configuracoes.audit_subtitle'))
        audit_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'audit_trail.jsonl')
        if os.path.exists(audit_file):
            trail = get_audit_trail(limit=50)
            if trail:
                # Total real do arquivo, não o tamanho da fatia exibida.
                total_eventos = count_audit_events()
                st.markdown(t('configuracoes.audit_events', count=total_eventos))
                show_truncation(len(trail), total_eventos, t('configuracoes.unit_events'))
                trail_df = pd.DataFrame(trail)
                if 'timestamp' in trail_df.columns:
                    trail_df = trail_df.sort_values('timestamp', ascending=False)
                display_cols = [c for c in ['timestamp', 'action', 'user', 'details'] if c in trail_df.columns]
                st.dataframe(trail_df[display_cols], use_container_width=True, hide_index=True, height=400)
                if st.button(t('configuracoes.audit_verify'), key="audit_verify"):
                    integrity = verify_audit_integrity()
                    is_valid = integrity.get('invalid', 0) == 0 and integrity.get('chain_breaks', 0) == 0
                    if is_valid:
                        st.success(t('configuracoes.audit_intact'))
                    else:
                        st.error(t('configuracoes.audit_broken'))
                    st.caption(t('configuracoes.audit_summary', total=integrity.get('total', 0),
                                 invalid=integrity.get('invalid', 0),
                                 breaks=integrity.get('chain_breaks', 0),
                                 hmac=integrity.get('hmac_failures', 0),
                                 checkpoints=integrity.get('checkpoints', 0)))
                    if integrity.get('details'):
                        with st.expander(t('configuracoes.audit_problem_events')):
                            st.dataframe(pd.DataFrame(integrity['details']),
                                         use_container_width=True, hide_index=True)
            else:
                st.info(t('configuracoes.audit_no_events'))
        else:
            st.info(t('configuracoes.audit_no_file'))

    st.divider()
    st.subheader(t('configuracoes.about_title'))
    st.markdown(t('configuracoes.about_content'))
