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
from i18n import t


def page_temporal():
    from styles.components import section_header, empty_state
    section_header(t('temporal.title'), divider="blue")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('temporal.no_data'), "🕐", t('common.process_data_first'))
        return

    # ── Padrões Temporais ──
    with st.container(border=True):
        st.subheader("🕐 Análise de Padrões Temporais")
        patterns = analyze_time_patterns(df)
        if patterns['hourly_counts'] is not None:
            c1, c2 = st.columns(2)
            c1.metric("Score de Rotina", f"{patterns['routine_score']}%")
            hours_str = ', '.join([f"{h}h" for h in patterns['most_active_hours'][:3]])
            c2.metric("Horários Mais Ativos", hours_str)
            hourly_df = pd.DataFrame({'Hora': patterns['hourly_counts'].index,
                                      'Acessos': patterns['hourly_counts'].values})
            fig = px.bar(hourly_df, x='Hora', y='Acessos',
                         color='Acessos', color_continuous_scale='Viridis')
            fig.update_layout(height=300, showlegend=False, coloraxis_showscale=False)
            st.plotly_chart(fig, key='hourly_pattern')
            if patterns['activity_gaps']:
                st.warning(f"⚠️ **{len(patterns['activity_gaps'])}** dias sem atividade")

    # ── Silêncio Digital ──
    with st.container(border=True):
        st.subheader("🔇 Silêncio Digital")
        with st.popover("⚙️ Configurar"):
            min_gap = st.slider("Gap mínimo (horas)", 12, 168, 24, key="silence_gap")
        result = detect_digital_silence(df, min_gap_hours=min_gap)
        silences = result.get('periods', [])
        if silences:
            st.warning(f"🔇 **{len(silences)}** período(s) de silêncio!")
            for s in silences:
                st.markdown(f"**{s.get('start', '')}** → **{s.get('end', '')}** ({s.get('gap_hours', 0):.0f}h)")
        else:
            st.success("✅ Nenhum silêncio digital significativo.")

    # ── Validação TZ ──
    with st.container(border=True):
        st.subheader("🕐 Validação de Fuso Horário")
        tz_result = validate_timezone_consistency(df)
        if tz_result.get('analyzed'):
            inconsistent = tz_result.get('inconsistencies', [])
            if inconsistent:
                st.warning(f"⚠️ **{len(inconsistent)}** inconsistência(s)!")
                st.dataframe(pd.DataFrame(inconsistent), width='stretch', hide_index=True)
            else:
                st.success("✅ Todos consistentes.")

    # ── Timing por Provedor ──
    with st.container(border=True):
        st.subheader("⏱️ Fingerprint de Timing por Provedor")
        with st.popover("⚙️ Configurar"):
            min_records = st.slider("Mínimo de registros por provedor", 2, 20, 5, key="timing_min")

        timing = analyze_provider_timing(df, min_records=min_records)
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
        else:
            st.info("Dados insuficientes para análise de timing.")

    # ── Transições entre Provedores ──
    with st.container(border=True):
        st.subheader("🔄 Transições entre Provedores")
        with st.popover("⚙️ Configurar"):
            window = st.slider("Janela de transição (min)", 10, 120, 30, key="timing_window")
        trans = detect_provider_transitions(df, window_minutes=window)
        sandwiches = trans.get('sandwich_patterns', [])
        if sandwiches:
            st.warning(f"🔄 **{len(sandwiches)}** padrão(ões) sandwich (A→B→A) detectado(s)!")
            st.dataframe(pd.DataFrame(sandwiches), width='stretch', hide_index=True)
        transitions = trans.get('transitions', [])
        if transitions:
            st.dataframe(pd.DataFrame(transitions[:10]), width='stretch', hide_index=True)
        elif not sandwiches:
            st.success("✅ Nenhuma transição suspeita.")
