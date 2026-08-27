"""
Análise Avançada - Correlação
Correlação Cruzada, WiFi Compartilhado, Relay Chains.
"""

import streamlit as st
import pandas as pd
import os
import io

from analysis import (
    cross_target_correlation,
    detect_shared_wifi, detect_relay_chains,
)
from components.visualizations import render_side_by_side_comparison
from i18n import t

# Teto de alvos mantidos em memória para correlação cruzada.
# Cada um é uma cópia integral do DataFrame do alvo.
MAX_STORED_TARGETS = 5

OUTPUT_CSV_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'output', 'csv')


def page_correlacao():
    from styles.components import section_header, empty_state
    section_header(t('correlacao.title'), divider="orange")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('correlacao.no_data'), "🔗", t('common.process_data_first'))
        return

    # ── Correlação Cruzada ──
    with st.container(border=True):
        st.subheader("🔗 Correlação Cruzada entre Alvos")
        st.info("Carregue múltiplos arquivos de resultado (.csv/.xlsx) para encontrar IPs em comum.")
        uploaded_files = st.file_uploader("Upload de arquivos", type=['xlsx', 'csv'],
                                          accept_multiple_files=True, key="corr_files")
        if uploaded_files and len(uploaded_files) >= 2:
            targets = {}
            for f in uploaded_files:
                try:
                    tdf = pd.read_csv(io.BytesIO(f.getvalue()), sep=';', encoding='utf-8-sig') if f.name.endswith('.csv') else pd.read_excel(io.BytesIO(f.getvalue()))
                    targets[os.path.splitext(f.name)[0]] = tdf
                except Exception as e:
                    st.error(f"Erro em {f.name}: {e}")
            if len(targets) >= 2:
                corr = cross_target_correlation(targets)
                if not corr.empty:
                    st.success(f"**{len(corr)}** IPs em comum!")
                    st.dataframe(corr, use_container_width=True, hide_index=True)
        if st.session_state.alvo and df is not None:
            if st.button("💾 Salvar resultado atual para correlação", key="save_target"):
                stored_now = st.session_state.stored_targets
                # Cada alvo guarda uma cópia integral do DataFrame. Sem teto,
                # dez alvos de 200k linhas ficam residentes ao mesmo tempo — e
                # relatorio.py relê todos de uma vez ao gerar o HTML.
                evicted = []
                while len(stored_now) >= MAX_STORED_TARGETS and \
                        st.session_state.alvo not in stored_now:
                    evicted.append(next(iter(stored_now)))
                    stored_now.pop(evicted[-1])
                stored_now[st.session_state.alvo] = df.copy()
                if evicted:
                    # Descartar um alvo em silêncio numa correlação multi-alvo
                    # falsearia o resultado; o analista precisa saber.
                    st.warning(
                        f"Limite de {MAX_STORED_TARGETS} alvos atingido — "
                        f"removido(s): {', '.join(evicted)}. "
                        "Salve novamente se precisar deles na correlação.")
                st.success(f"Armazenado ({len(stored_now)} alvos)")
        if len(st.session_state.stored_targets) >= 2:
            st.divider()
            if st.button("🔍 Correlacionar alvos armazenados", key="corr_stored"):
                corr = cross_target_correlation(st.session_state.stored_targets)
                if not corr.empty:
                    st.dataframe(corr, use_container_width=True, hide_index=True)
            st.divider()
            st.subheader("📊 Comparação Lado a Lado")
            names = list(st.session_state.stored_targets.keys())
            c1, c2 = st.columns(2)
            with c1:
                sel_a = st.selectbox("Alvo A", names, key="cmp_a")
            with c2:
                sel_b = st.selectbox("Alvo B", [n for n in names if n != sel_a] or names, key="cmp_b")
            if sel_a != sel_b:
                render_side_by_side_comparison(
                    st.session_state.stored_targets[sel_a],
                    st.session_state.stored_targets[sel_b], sel_a, sel_b)

    # ── WiFi Compartilhado ──
    with st.container(border=True):
        st.subheader("📡 Detecção de WiFi Compartilhado")
        stored = st.session_state.stored_targets
        if len(stored) >= 2:
            with st.popover("⚙️ Configurar"):
                tolerance = st.slider("Tolerância (seg)", 10, 300, 60, key="wifi_tol")
            shared = detect_shared_wifi(stored, tolerance_seconds=tolerance)
            if shared:
                st.dataframe(pd.DataFrame(shared), use_container_width=True, hide_index=True)
            else:
                st.success("✅ Nenhuma conexão WiFi compartilhada.")
        else:
            st.info("Armazene ao menos 2 alvos.")

    # ── Relay Chains ──
    with st.container(border=True):
        st.subheader("🔗 Detecção de Relay Chains")
        with st.popover("⚙️ Configurar"):
            max_gap = st.slider("Gap máximo (min)", 1, 60, 10, key="relay_gap")
        result = detect_relay_chains(df, max_gap_minutes=max_gap)
        chains = result.get('chains', [])
        if chains:
            st.warning(f"⚠️ **{len(chains)}** cadeia(s) de relay!")
            for i, chain in enumerate(chains):
                with st.expander(f"Cadeia #{i+1}"):
                    st.json(chain)
        else:
            st.success("✅ Nenhuma cadeia de relay.")
