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
from helpers.large_data import gate, show_truncation
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
        st.subheader(t('correlacao.cross_title'))
        st.info(t('correlacao.cross_info'))
        uploaded_files = st.file_uploader(t('correlacao.upload_files'), type=['xlsx', 'csv'],
                                          accept_multiple_files=True, key="corr_files")
        if uploaded_files and len(uploaded_files) >= 2:
            targets = {}
            for f in uploaded_files:
                try:
                    tdf = pd.read_csv(io.BytesIO(f.getvalue()), sep=';', encoding='utf-8-sig') if f.name.endswith('.csv') else pd.read_excel(io.BytesIO(f.getvalue()))
                    targets[os.path.splitext(f.name)[0]] = tdf
                except Exception as e:
                    st.error(t('correlacao.file_error', name=f.name, error=e))
            if len(targets) >= 2:
                corr = cross_target_correlation(targets)
                if not corr.empty:
                    st.success(t('correlacao.ips_in_common', count=len(corr)))
                    st.dataframe(corr, width='stretch', hide_index=True)
        if st.session_state.alvo and df is not None:
            if st.button(t('correlacao.save_for_correlation'), key="save_target"):
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
                    st.warning(t('correlacao.targets_evicted', max=MAX_STORED_TARGETS,
                                 names=', '.join(evicted)))
                st.success(t('correlacao.stored_count', count=len(stored_now)))
        if len(st.session_state.stored_targets) >= 2:
            st.divider()
            if st.button(t('correlacao.correlate_stored'), key="corr_stored"):
                corr = cross_target_correlation(st.session_state.stored_targets)
                if not corr.empty:
                    st.dataframe(corr, width='stretch', hide_index=True)
            st.divider()
            st.subheader(t('correlacao.side_by_side'))
            names = list(st.session_state.stored_targets.keys())
            c1, c2 = st.columns(2)
            with c1:
                sel_a = st.selectbox(t('correlacao.target_a'), names, key="cmp_a")
            with c2:
                sel_b = st.selectbox(t('correlacao.target_b'), [n for n in names if n != sel_a] or names,
                                     key="cmp_b")
            if sel_a != sel_b:
                render_side_by_side_comparison(
                    st.session_state.stored_targets[sel_a],
                    st.session_state.stored_targets[sel_b], sel_a, sel_b)

    # ── WiFi Compartilhado ──
    with st.container(border=True):
        st.subheader(t('correlacao.wifi_title'))
        stored = st.session_state.stored_targets
        if len(stored) >= 2:
            with st.popover(t('correlacao.configure')):
                tolerance = st.slider(t('correlacao.wifi_tolerance'), 10, 300, 60, key="wifi_tol")
            # Compara todos os alvos armazenados entre si: não roda sozinho a
            # cada rerun em dataset grande.
            if gate(t('correlacao.gate_wifi'), df, 'corr_wifi'):
                shared = detect_shared_wifi(stored, tolerance_seconds=tolerance)
                if shared:
                    st.dataframe(pd.DataFrame(shared), width='stretch', hide_index=True)
                else:
                    st.success(t('correlacao.no_shared_wifi'))
        else:
            st.info(t('correlacao.wifi_need_targets'))

    # ── Relay Chains ──
    with st.container(border=True):
        st.subheader(t('correlacao.relay_title'))
        with st.popover(t('correlacao.configure')):
            max_gap = st.slider(t('correlacao.relay_gap'), 1, 60, 10, key="relay_gap")
        if gate(t('correlacao.gate_relay'), df, 'corr_relay'):
            result = detect_relay_chains(df, max_gap_minutes=max_gap)
            chains = result.get('chains', [])
            # `chains` vem cortado em 20; o total real está em `total_chains`.
            # Antes a página mostrava o tamanho da fatia como se fosse o total.
            total = result.get('total_chains', len(chains))
            if chains:
                st.warning(t('correlacao.relay_found', count=total))
                for i, chain in enumerate(chains):
                    with st.expander(t('correlacao.relay_chain', num=i + 1)):
                        st.json(chain)
                show_truncation(len(chains), total, t('correlacao.unit_chains'))
            else:
                st.success(t('correlacao.no_relay'))
