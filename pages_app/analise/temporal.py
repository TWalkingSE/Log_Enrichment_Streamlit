"""
Análise Avançada - Padrões Temporais
Padrões Temporais, Timing por Provedor, Silêncio Digital, Validação TZ.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

from analysis import (
    analyze_time_patterns,
    detect_digital_silence, validate_timezone_consistency,
    analyze_provider_timing, detect_provider_transitions,
)
from helpers.large_data import cache_key, gate
from i18n import t


# `_df` não é hasheado (prefixo `_`); a identidade do cache vem de `key`,
# derivado da versão do dataset — hashear o frame a cada rerun era o custo.
@st.cache_data(show_spinner=False)
def _cached_time_patterns(_df, key):
    return analyze_time_patterns(_df)


@st.cache_data(show_spinner=False)
def _cached_digital_silence(_df, min_gap_hours, key):
    return detect_digital_silence(_df, min_gap_hours=min_gap_hours)


@st.cache_data(show_spinner=False)
def _cached_tz_consistency(_df, key):
    return validate_timezone_consistency(_df)


@st.cache_data(show_spinner=False)
def _cached_provider_timing(_df, min_records, key):
    return analyze_provider_timing(_df, min_records=min_records)


@st.cache_data(show_spinner=False)
def _cached_provider_transitions(_df, window_minutes, key):
    return detect_provider_transitions(_df, window_minutes=window_minutes)


def page_temporal():
    from styles.components import section_header, empty_state
    section_header(t('temporal.title'), divider="blue")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('temporal.no_data'), "🕐", t('common.process_data_first'))
        return

    # ── Padrões Temporais ──
    with st.container(border=True):
        st.subheader(t('temporal.patterns_title'))
        patterns = (_cached_time_patterns(df, cache_key('tpat', len(df)))
                    if gate('🕐 Analisar padrões temporais', df, 'temporal_patterns')
                    else {'hourly_counts': None})
        if patterns['hourly_counts'] is not None:
            c1, c2 = st.columns(2)
            c1.metric(t('temporal.routine_score'), f"{patterns['routine_score']}%")
            hours_str = ', '.join([f"{h}h" for h in patterns['most_active_hours'][:3]])
            c2.metric(t('temporal.most_active_hours'), hours_str)
            hourly_df = pd.DataFrame({'Hora': patterns['hourly_counts'].index,
                                      'Acessos': patterns['hourly_counts'].values})
            fig = px.bar(hourly_df, x='Hora', y='Acessos',
                         color='Acessos', color_continuous_scale='Viridis')
            fig.update_layout(height=300, showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='hourly_pattern')
            if patterns['activity_gaps']:
                st.warning(t('temporal.days_without_activity', count=len(patterns['activity_gaps'])))

    # ── Silêncio Digital ──
    with st.container(border=True):
        st.subheader(t('temporal.silence_title'))
        with st.popover("⚙️"):
            min_gap = st.slider(t('temporal.silence_gap_label'), 12, 168, 24, key="silence_gap")
        if gate('🌒 Detectar silêncio digital', df, 'temporal_silence'):
            result = _cached_digital_silence(df, min_gap, cache_key('sil', len(df), min_gap))
            silences = result.get('periods', [])
            if silences:
                st.warning(t('temporal.silence_found', count=len(silences)))
                for s in silences:
                    st.markdown(f"**{s.get('start', '')}** → **{s.get('end', '')}** ({s.get('gap_hours', 0):.0f}h)")
            else:
                st.success(t('temporal.no_silence'))

    # ── Validação TZ ──
    with st.container(border=True):
        st.subheader(t('temporal.tz_title'))
        tz_result = (_cached_tz_consistency(df, cache_key('tz', len(df)))
                     if gate('🌍 Validar consistência de fuso', df, 'temporal_tz')
                     else {})
        if tz_result.get('analyzed'):
            inconsistent = tz_result.get('inconsistencies', [])
            if inconsistent:
                st.warning(f"⚠️ **{len(inconsistent)}**")
                st.dataframe(pd.DataFrame(inconsistent), use_container_width=True, hide_index=True)
            else:
                st.success("✅")

    # ── Timing por Provedor ──
    with st.container(border=True):
        st.subheader(t('temporal.timing_title'))
        with st.popover("⚙️"):
            min_records = st.slider("min", 2, 20, 5, key="timing_min")

        timing_ok = gate('⏱️ Analisar timing por provedor', df, 'temporal_timing')
        timing = (_cached_provider_timing(df, min_records, cache_key('ptim', len(df), min_records))
                  if timing_ok else {})
        providers = timing.get('providers', {})
        vpn_sched = timing.get('vpn_schedule', {})

        if vpn_sched.get('detected'):
            st.error("🕵️ **Padrão VPN detectado!**")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**Horas exclusivas VPN:** {vpn_sched.get('exclusive_vpn_hours', [])}")
                st.markdown(f"**Provedores VPN:** {', '.join(vpn_sched.get('vpn_providers', []))}")
            with c2:
                st.markdown(f"**Horas residenciais:** {vpn_sched.get('residential_hours', [])}")
                st.markdown(f"**Provedores residenciais:** {', '.join(vpn_sched.get('residential_providers', []))}")

        if providers:
            for prov_name, info in providers.items():
                icon = '🏢' if info['usage_type'] == 'always_on' else '⏰' if info['usage_type'] == 'scheduled' else '💨'
                with st.expander(f"{icon} {prov_name} — {info['usage_type']} ({info['total_records']} registros)"):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Horas Ativo", info['active_hours'])
                    c2.metric("Sessão Média (min)", info['avg_session_minutes'])
                    peak_str = ', '.join([f"{h}h" for h in info['peak_hours']])
                    c3.metric("Horários Pico", peak_str)
                    hourly_df = pd.DataFrame({'Hora': list(range(24)), 'Registros': info['hourly_dist']})
                    fig = px.bar(hourly_df, x='Hora', y='Registros',
                                 color='Registros', color_continuous_scale='Viridis')
                    fig.update_layout(height=200, showlegend=False, coloraxis_showscale=False)
                    st.plotly_chart(fig, key=f'timing_{prov_name}')
        elif timing_ok:
            st.info("Dados insuficientes para análise de timing.")

    # ── Transições entre Provedores ──
    with st.container(border=True):
        st.subheader(t('temporal.transitions_title'))
        with st.popover("⚙️"):
            window = st.slider("window (min)", 10, 120, 30, key="timing_window")
        trans = (_cached_provider_transitions(df, window, cache_key('ptrans', len(df), window))
                 if gate('🔄 Detectar transições de provedor', df, 'temporal_trans')
                 else {})
        sandwiches = trans.get('sandwich_patterns', [])
        if sandwiches:
            st.warning(f"🔄 **{len(sandwiches)}** padrão(ões) sandwich (A→B→A) detectado(s)!")
            st.dataframe(pd.DataFrame(sandwiches), use_container_width=True, hide_index=True)
        transitions = trans.get('transitions', [])
        if transitions:
            st.dataframe(pd.DataFrame(transitions[:10]), use_container_width=True, hide_index=True)
        elif not sandwiches:
            st.success("✅ Nenhuma transição suspeita.")
