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

from audit_logger import get_audit_trail, verify_audit_integrity

from i18n import t

logger = logging.getLogger(__name__)


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
                "🔒 Air-gapped (somente cache local)",
                value=bool(st.session_state.get('air_gapped', False)),
                key="cfg_air_gapped",
                help="Desativa chamadas externas à IP-API. Use com ip_cache.json pré-populado.",
            )
            st.session_state.air_gapped = air_gapped
            if air_gapped:
                st.warning("Modo air-gapped ativo: IPs sem cache local não serão enriquecidos.")
            api_key = st.text_input(
                t('configuracoes.api_key_label'),
                value=st.session_state.api_key, type="password",
                placeholder=t('configuracoes.api_key_placeholder'),
                disabled=air_gapped)
            st.session_state.api_key = api_key
            if air_gapped:
                st.info("API Key ignorada em modo air-gapped.")
            elif api_key:
                st.success(t('configuracoes.api_key_configured'))
            else:
                st.info(t('configuracoes.api_free_info'))

            st.subheader(t('configuracoes.cache_title'))
            st.session_state.use_cache = st.toggle(
                t('configuracoes.use_cache'), value=st.session_state.use_cache)
            if os.path.exists('ip_cache.json'):
                try:
                    with open('ip_cache.json', 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    from helpers.signed_cache import is_signed_envelope
                    n_entries = (
                        len(cache_data.get('payload', {}))
                        if is_signed_envelope(cache_data)
                        else len(cache_data)
                    )
                    signed_note = " (HMAC)" if is_signed_envelope(cache_data) else ""
                    st.caption(t('configuracoes.cache_count', count=n_entries) + signed_note)
                    c_exp, c_clr = st.columns(2)
                    with c_exp:
                        if st.button(t('configuracoes.export_signed_cache'), key='btn_export_signed_cache'):
                            try:
                                from helpers.signed_cache import build_signed_package, get_cache_hmac_secret
                                if not get_cache_hmac_secret():
                                    st.error(t('configuracoes.signed_cache_no_secret'))
                                else:
                                    payload = (
                                        cache_data['payload']
                                        if is_signed_envelope(cache_data)
                                        else cache_data
                                    )
                                    pkg = build_signed_package(payload)
                                    st.download_button(
                                        t('configuracoes.download_signed_cache'),
                                        json.dumps(pkg, ensure_ascii=False, indent=2),
                                        'ip_cache.signed.json',
                                        'application/json',
                                        key='dl_signed_cache',
                                    )
                            except Exception as e:
                                st.error(str(e))
                    with c_clr:
                        if st.button(t('configuracoes.clear_cache')):
                            os.remove('ip_cache.json')
                            st.success(t('configuracoes.cache_cleared'))
                            st.rerun()
                except Exception as e:
                    logger.warning(f"Erro ao ler cache: {e}")

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
                            with open('ip_cache.json', 'w', encoding='utf-8') as f:
                                json.dump(pkg, f, ensure_ascii=False)
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
                    if os.path.exists('processing_history.json'):
                        os.remove('processing_history.json')
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
            with st.expander("Formato 1: Genérico (Lista de IPs)"):
                st.code("191.13.51.97\n2804:18:18bf:9681:1:0:70f2:df19\n187.37.136.128", language=None)
            with st.expander("Formato 2: Meta Platforms (Instagram/Facebook)"):
                st.code("IP Address\n24.152.81.150:22859\nTime\n2025-09-29 11:15:01 UTC", language=None)
            with st.expander("Formato 3: WhatsApp"):
                st.code("Time\n2025-12-10 18:58:48 UTC\nIP Address\n2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7", language=None)
            with st.expander("Formato 4: Google"):
                st.code("IP ACTIVITY\n\nTimestamp   IP Address  Activity Type\n2023-02-25 04:34:32 Z   187.37.136.128    Login", language=None)
            with st.expander("Formato 5: TikTok (Events IP Data)"):
                st.code("Date: 27/07/2026 03:04:43PM (UTC +00)\nIP: 203.0.113.45\nEvent: video_play\nCountry: Brazil", language=None)
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
        st.code("""# 1. Instalar Ollama (Windows: baixe em https://ollama.com)
# 2. Baixar o modelo desejado
ollama pull qwen3.5:4b           # Lite (8GB VRAM)
ollama pull qwen3.5:9b-q8_0     # Standard (16GB VRAM)
ollama pull qwen3.5:27b-q4_K_M  # Premium (24GB VRAM)

# 3. Verificar se está rodando
ollama list

# 4. No app, use primeiro: Testar Conexão
# 5. Depois rode: Teste de Inferência""", language="bash")

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
                f"<div style='color:{primary};font-weight:700;font-size:1rem;'>Exemplo de Título</div>"
                f"<div style='font-size:0.85rem;margin-top:6px;'>Texto de exemplo com "
                f"<span style='color:{accent};font-weight:600;'>acento</span> aplicado.</div>"
                f"</div>", unsafe_allow_html=True)

    with tab_audit:
        st.subheader(t('configuracoes.audit_title'))
        st.caption(t('configuracoes.audit_subtitle'))
        audit_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'audit_trail.jsonl')
        if os.path.exists(audit_file):
            trail = get_audit_trail(limit=50)
            if trail:
                st.markdown(t('configuracoes.audit_events', count=len(trail)))
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
            else:
                st.info(t('configuracoes.audit_no_events'))
        else:
            st.info(t('configuracoes.audit_no_file'))

    st.divider()
    st.subheader(t('configuracoes.about_title'))
    st.markdown(t('configuracoes.about_content'))
