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

    tab_api, tab_ai, tab_audit = st.tabs([
        t('configuracoes.tab_api'), t('configuracoes.tab_ai'), t('configuracoes.tab_audit')
    ])

    with tab_api:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("🔌 API IP-API")
            api_key = st.text_input("API Key (opcional, para plano pago)",
                value=st.session_state.api_key, type="password",
                placeholder="Deixe vazio para usar API gratuita")
            st.session_state.api_key = api_key
            if api_key:
                st.success("🔑 API Key configurada. Consultas ilimitadas via HTTPS.")
            else:
                st.info("Sem API Key. Usando API gratuita (45 req/min).")

            st.subheader("💾 Cache")
            st.session_state.use_cache = st.toggle("Usar cache", value=st.session_state.use_cache)
            if os.path.exists('ip_cache.json'):
                try:
                    with open('ip_cache.json', 'r') as f:
                        cache_data = json.load(f)
                    st.caption(f"Cache: **{len(cache_data)}** IPs armazenados")
                    if st.button("🗑️ Limpar Cache"):
                        os.remove('ip_cache.json')
                        st.success("Cache limpo!")
                        st.rerun()
                except Exception as e:
                    logger.warning(f"Erro ao ler cache: {e}")

            st.subheader("📜 Histórico")
            if st.session_state.history:
                st.caption(f"**{len(st.session_state.history)}** processamentos registrados")
                if st.button("🗑️ Limpar Histórico"):
                    st.session_state.history = []
                    if os.path.exists('processing_history.json'):
                        os.remove('processing_history.json')
                    st.success("Histórico limpo!")
                    st.rerun()

            st.subheader("🔎 Shodan API")
            if os.getenv('SHODAN_API_KEY', ''):
                st.success("🔑 Shodan API Key configurada via `.env`.")
            else:
                st.info("Configure `SHODAN_API_KEY` no arquivo `.env`. Obtenha em https://shodan.io")

            st.subheader("🧅 Tor Exit Nodes")
            tor_auto_check = st.toggle("Verificar Tor Exit Nodes automaticamente",
                value=st.session_state.get('tor_auto_check', False),
                key="cfg_tor_toggle")
            st.session_state['tor_auto_check'] = tor_auto_check
            if tor_auto_check:
                st.caption("IPs serão verificados contra a lista de Tor exit nodes durante o processamento.")

            tor_cache_status = get_tor_exit_cache_status(ttl_hours=TOR_CACHE_TTL_HOURS)
            if tor_cache_status.get('available'):
                cached_at = tor_cache_status.get('cached_at')
                cached_label = (
                    datetime.fromtimestamp(cached_at).strftime('%d/%m/%Y %H:%M:%S')
                    if cached_at else 'desconhecido'
                )
                freshness = 'atual' if not tor_cache_status.get('is_stale') else 'expirado'
                st.caption(
                    f"Cache Tor: {tor_cache_status.get('node_count', 0)} IPs · "
                    f"última atualização em {cached_label} · idade {tor_cache_status.get('age_hours', 0):.1f}h · {freshness}"
                )
            else:
                st.caption("Cache Tor ainda não foi gerado localmente.")

            if st.button("🔄 Atualizar lista Tor", key="cfg_tor_refresh"):
                with st.status("Atualizando lista Tor com torbulkexitlist + Onionoo...") as status:
                    result = update_tor_exit_nodes_cache()
                    st.session_state['cfg_tor_refresh_result'] = result
                    if result['success']:
                        total = result['node_count']
                        bulk_total = result['source_counts'].get('torbulkexitlist', 0)
                        onionoo_total = result['source_counts'].get('onionoo', 0)
                        label = f"✅ Lista Tor atualizada: {total} IPs únicos"
                        if result.get('source_errors'):
                            label += " (com falha parcial)"
                        status.update(label=label, state="complete")
                    else:
                        status.update(label="❌ Falha ao atualizar a lista Tor", state="error")

            refresh_result = st.session_state.get('cfg_tor_refresh_result')
            if refresh_result:
                if refresh_result.get('success'):
                    st.success(
                        "Lista Tor consolidada com sucesso: "
                        f"{refresh_result['node_count']} IPs únicos "
                        f"({refresh_result['source_counts'].get('torbulkexitlist', 0)} via torbulkexitlist, "
                        f"{refresh_result['source_counts'].get('onionoo', 0)} via Onionoo)."
                    )
                    if refresh_result.get('source_errors'):
                        warning_details = '; '.join(
                            f"{source}: {error}"
                            for source, error in refresh_result['source_errors'].items()
                        )
                        st.warning(f"Atualização parcial. Fontes com problema: {warning_details}")
                else:
                    st.error(refresh_result.get('error', 'Falha ao atualizar lista Tor.'))

            st.caption("Automação local: execute `venv\\Scripts\\python.exe tor_updater.py --skip-if-fresh` a cada 6–12 horas.")

        with c2:
            st.subheader("📄 Formatos Suportados")
            with st.expander("Formato 1: Genérico (Lista de IPs)"):
                st.code("191.13.51.97\n2804:18:18bf:9681:1:0:70f2:df19\n187.37.136.128", language=None)
            with st.expander("Formato 2: Meta Platforms (Instagram/Facebook)"):
                st.code("IP Address\n24.152.81.150:22859\nTime\n2025-09-29 11:15:01 UTC", language=None)
            with st.expander("Formato 3: WhatsApp"):
                st.code("Time\n2025-12-10 18:58:48 UTC\nIP Address\n2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7", language=None)
            with st.expander("Formato 4: Google"):
                st.code("IP ACTIVITY\n\nTimestamp   IP Address  Activity Type\n2023-02-25 04:34:32 Z   187.37.136.128    Login", language=None)
            st.subheader("📤 Formatos de Saída")
            st.markdown("- **CSV** — formato principal\n- **JSON** — array de objetos\n- **PDF** — relatório formatado")

    with tab_ai:
        st.subheader("🤖 Assistente AI (Ollama)")
        st.caption("Configure o assistente AI local para análise investigativa de IPs")

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

        st.info("Ollama não faz parte do requirements.txt: ele é um serviço local externo, acessado via HTTP pelo projeto.")

        tier_options = {
            "lite": "💚 Lite — Qwen3.5 4B (8GB VRAM)",
            "standard": "💙 Standard — Qwen3.5 9B Q8 (16GB VRAM)",
            "premium": "💜 Premium — Qwen3.5 27B Q4 (24GB VRAM)",
        }
        selected_tier = st.radio(
            "Selecione o tier de acordo com sua GPU",
            options=list(tier_options.keys()),
            format_func=lambda x: tier_options[x],
            index=list(tier_options.keys()).index(default_tier),
            key="cfg_ai_tier"
        )
        st.session_state['ai_tier'] = selected_tier
        model_info = AI_MODELS[selected_tier]

        c_ai1, c_ai2 = st.columns(2)
        with c_ai1:
            st.markdown("**Conexão Ollama**")
            ai_url = st.text_input(
                "URL do Ollama",
                value=st.session_state.get('ai_ollama_url', 'http://localhost:11434'),
                key="cfg_ai_url"
            )
            st.session_state['ai_ollama_url'] = ai_url

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                connection_clicked = st.button("🔌 Testar Conexão", key="cfg_ai_test")
            with btn_col2:
                inference_clicked = st.button("⚡ Teste de Inferência", key="cfg_ai_infer_test")

            if connection_clicked:
                status = check_ollama_status(ai_url)
                st.session_state['cfg_ai_status_result'] = status
                if status['online']:
                    st.success(f"✅ Ollama online — {len(status['models'])} modelo(s) instalado(s)")
                    for m in status['models']:
                        model_name = m.get('name', 'unknown')
                        model_size = m.get('size', 0)
                        size_gb = model_size / (1024**3) if model_size else 0
                        st.caption(f"  • `{model_name}` ({size_gb:.1f} GB)")
                    if not check_model_available(model_info['model'], ai_url):
                        st.warning(f"⚠️ Modelo selecionado `{model_info['model']}` não está instalado. "
                                   f"Execute: `ollama pull {model_info['model']}`")
                else:
                    st.error(f"❌ Ollama offline: {status.get('error', '')}")
                    st.code("# Para iniciar o Ollama:\nollama serve", language="bash")

            if inference_clicked:
                inference_result = test_ollama_inference(model_info['model'], ai_url)
                st.session_state['cfg_ai_inference_result'] = inference_result
                if inference_result['success']:
                    st.success(
                        f"✅ Inferência OK em {inference_result['elapsed_seconds']:.1f}s — resposta: "
                        f"`{inference_result['response']}`"
                    )
                else:
                    st.warning(f"⚠️ Teste de inferência falhou: {inference_result['error']}")

            cached_status = st.session_state.get('cfg_ai_status_result')
            if cached_status and not connection_clicked:
                if cached_status.get('online'):
                    st.caption(f"Status recente: Ollama online com {len(cached_status.get('models', []))} modelo(s).")
                else:
                    st.caption(f"Status recente: {cached_status.get('error', '')}")

            cached_inference = st.session_state.get('cfg_ai_inference_result')
            if cached_inference and not inference_clicked:
                if cached_inference.get('success'):
                    st.caption(
                        f"Último smoke test: OK em {cached_inference['elapsed_seconds']:.1f}s com `{cached_inference['model_used']}`."
                    )
                else:
                    st.caption(
                        f"Último smoke test falhou para `{cached_inference['model_used']}`: {cached_inference['error']}"
                    )

        with c_ai2:
            st.markdown("**Modelo por Hardware**")
            st.info(f"**Modelo:** `{model_info['model']}`\n\n"
                    f"**VRAM estimada:** {model_info['vram']}\n\n"
                    f"**Contexto:** {model_info['options']['num_ctx']:,} tokens")
            if selected_tier == 'lite':
                st.caption("Recomendado para smoke test, fallback automático e uso mais responsivo.")
            elif selected_tier == 'standard':
                st.caption("Equilíbrio entre qualidade e tempo de resposta. Se houver timeout, o sistema tenta fallback Lite.")
            else:
                st.caption("Maior qualidade, mas mais sensível a tempo de resposta e VRAM disponível.")
            st.markdown("**Instalar Modelo:**")
            st.code(f"ollama pull {model_info['model']}", language="bash")

        st.divider()
        st.markdown("**Guia Rápido de Instalação do Ollama:**")
        st.code("""# 1. Instalar Ollama (Windows: baixe em https://ollama.com)
# 2. Baixar o modelo desejado
ollama pull qwen3.5:4b           # Lite (8GB VRAM)
ollama pull qwen3.5:9b-q8_0     # Standard (16GB VRAM)
ollama pull qwen3.5:27b-q4_K_M  # Premium (24GB VRAM)

# 3. Verificar se está rodando
ollama list

# 4. No app, use primeiro: Testar Conexão
# 5. Depois rode: Teste de Inferência""", language="bash")

    with tab_audit:
        st.subheader("📋 Audit Trail")
        st.caption("Cadeia de custódia — registro de todas as ações realizadas.")
        audit_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'audit_trail.jsonl')
        if os.path.exists(audit_file):
            trail = get_audit_trail(limit=50)
            if trail:
                st.markdown(f"**{len(trail)}** eventos mais recentes:")
                trail_df = pd.DataFrame(trail)
                if 'timestamp' in trail_df.columns:
                    trail_df = trail_df.sort_values('timestamp', ascending=False)
                display_cols = [c for c in ['timestamp', 'action', 'user', 'details'] if c in trail_df.columns]
                st.dataframe(trail_df[display_cols], width='stretch', hide_index=True, height=400)
                if st.button("🔒 Verificar Integridade", key="audit_verify"):
                    is_valid = verify_audit_integrity()
                    if is_valid:
                        st.success("✅ Audit trail íntegro.")
                    else:
                        st.error("❌ FALHA DE INTEGRIDADE!")
            else:
                st.info("Nenhum evento registrado.")
        else:
            st.info("Arquivo de audit trail ainda não foi criado.")

    st.divider()
    st.subheader("ℹ️ Sobre")
    st.markdown("""
    **Log Enrichment v5.2 Pro** — Ferramenta de enriquecimento de IPs para análise de logs de acesso.

    **Funcionalidades:**
    Dashboard de estatísticas · Mapa interativo · Heatmap · Detecção de anomalias ·
    Relatório PDF · Exportação multi-formato · **VPN/Proxy heurístico** ·
    **Confiança de IP** · **Padrões de vida (DBSCAN)** · **Audit trail forense** ·
    **VirusTotal** · **Relay Chains** · **Fingerprint de Dispositivo** ·
    **WiFi Compartilhado** · **Silêncio Digital** ·
    **Grafo Interativo** · **Sparklines** ·
    **Replay Temporal** · **Saúde dos Dados** · **Score Unificado** ·
    **KML Animado** · **Perfil Residencial/Corporativo** · **Precisão Geográfica**
    """)
