"""
Log Enrichment - Página de Estatísticas
Dashboard analítico com foco operacional e séries visuais de leitura rápida.
"""

import logging

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from helpers.shared import detect_anomalies
from styles.theme import COLORS
from i18n import t

logger = logging.getLogger(__name__)

DAY_ORDER_EN = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
DAY_NAME_PT = {
    'Sunday': 'Domingo',
    'Monday': 'Segunda',
    'Tuesday': 'Terca',
    'Wednesday': 'Quarta',
    'Thursday': 'Quinta',
    'Friday': 'Sexta',
    'Saturday': 'Sabado',
}

CONNECTION_COLORS = {
    'Residencial': COLORS['success'],
    'Movel': COLORS['mobile'],
    'Proxy/VPN': COLORS['danger'],
    'Hosting': COLORS['hosting'],
}


def _hex_to_rgba(hex_color, alpha):
    hex_color = hex_color.lstrip('#')
    red = int(hex_color[0:2], 16)
    green = int(hex_color[2:4], 16)
    blue = int(hex_color[4:6], 16)
    return f'rgba({red}, {green}, {blue}, {alpha})'


def _to_bool_series(series):
    return series.fillna(False).map(lambda value: str(value).strip().lower() == 'true')


def _prepare_datetime_frame(df):
    if 'Data' not in df.columns:
        return pd.DataFrame()

    df_t = df.copy()
    df_t['Data_parsed'] = pd.to_datetime(df_t['Data'], format='mixed', errors='coerce')
    return df_t.dropna(subset=['Data_parsed'])


def _build_focus_line_chart(dataframe, x_col, y_col, title, subtitle='', accent=COLORS['text'], tickangle=0):
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dataframe[x_col],
        y=dataframe[y_col],
        mode='lines+markers',
        line=dict(color=accent, width=3.5, shape='spline', smoothing=0.5),
        fill='tozeroy',
        fillcolor=_hex_to_rgba(accent, 0.12),
        marker=dict(
            size=13,
            color=COLORS['text_muted'],
            line=dict(color='#f8fafc', width=2.5),
        ),
        hovertemplate='%{x}<br><b>%{y}</b><extra></extra>',
    ))

    title_text = f"<b>{title}</b>"
    if subtitle:
        title_text += f"<br><span style='font-size:12px;color:{COLORS['text_muted']}'>{subtitle}</span>"

    fig.update_layout(
        title=dict(text=title_text, x=0.02, y=0.97, xanchor='left', yanchor='top'),
        height=320,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor=_hex_to_rgba('#ffffff', 0.02),
        margin=dict(l=12, r=18, t=86, b=12),
        font=dict(color=COLORS['text']),
        hoverlabel=dict(
            bgcolor=COLORS['surface_elevated'],
            bordercolor=accent,
            font=dict(color=COLORS['text']),
        ),
        xaxis=dict(
            tickangle=tickangle,
            showgrid=False,
            showline=False,
            zeroline=False,
            tickfont=dict(color=COLORS['text_muted']),
        ),
        yaxis=dict(
            rangemode='tozero',
            gridcolor=_hex_to_rgba(COLORS['border'], 0.35),
            zeroline=False,
            tickfont=dict(color=COLORS['text_muted']),
        ),
    )
    return fig


def _build_horizontal_bar_chart(dataframe, label_col, value_col, title, accent, height=320):
    opacities = [max(0.28, 0.95 - index * 0.07) for index in range(len(dataframe))]
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=dataframe[value_col],
        y=dataframe[label_col],
        orientation='h',
        marker=dict(
            color=[_hex_to_rgba(accent, opacity) for opacity in opacities],
            line=dict(color=_hex_to_rgba('#ffffff', 0.08), width=1),
        ),
        text=dataframe[value_col],
        textposition='outside',
        hovertemplate='%{y}<br><b>%{x}</b><extra></extra>',
    ))
    fig.update_layout(
        title=dict(text=f'<b>{title}</b>', x=0.02, xanchor='left'),
        height=height,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=12, r=28, t=52, b=12),
        font=dict(color=COLORS['text']),
        xaxis=dict(showgrid=False, zeroline=False, tickfont=dict(color=COLORS['text_muted'])),
        yaxis=dict(categoryorder='total ascending', showgrid=False, tickfont=dict(color=COLORS['text_muted'])),
    )
    return fig


def _build_connection_mix_chart(df):
    if not all(column in df.columns for column in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        return None

    proxy_series = _to_bool_series(df['Ip_Proxy'])
    hosting_series = _to_bool_series(df['Ip_Hospedagem'])
    mobile_series = _to_bool_series(df['Ip_Movel'])
    residencial_series = ~(proxy_series | hosting_series | mobile_series)

    mix_df = pd.DataFrame({
        'Tipo': ['Residencial', 'Movel', 'Proxy/VPN', 'Hosting'],
        'Qtd': [
            int(residencial_series.sum()),
            int(mobile_series.sum()),
            int(proxy_series.sum()),
            int(hosting_series.sum()),
        ],
    })
    mix_df = mix_df[mix_df['Qtd'] > 0]
    if mix_df.empty:
        return None

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=mix_df['Tipo'],
        y=mix_df['Qtd'],
        marker=dict(color=[CONNECTION_COLORS[item] for item in mix_df['Tipo']]),
        text=mix_df['Qtd'],
        textposition='outside',
        hovertemplate='%{x}<br><b>%{y}</b><extra></extra>',
    ))
    fig.update_layout(
        title=dict(text='<b>Mix de Conexao</b><br><span style="font-size:12px;color:#94a3b8">Leitura rapida do perfil de infraestrutura</span>', x=0.02, xanchor='left'),
        height=320,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=12, r=12, t=74, b=12),
        font=dict(color=COLORS['text']),
        xaxis=dict(showgrid=False, tickfont=dict(color=COLORS['text_muted'])),
        yaxis=dict(rangemode='tozero', gridcolor=_hex_to_rgba(COLORS['border'], 0.35), tickfont=dict(color=COLORS['text_muted'])),
    )
    return fig


def _provider_spotlight_data(df, df_dates):
    if 'Ip_Dono' not in df.columns or 'Ip' not in df.columns:
        return [], pd.DataFrame(), ''

    providers = df['Ip_Dono'].fillna('').replace('', 'Nao informado')
    provider_options = providers.value_counts().head(8).index.tolist()
    if not provider_options:
        return [], pd.DataFrame(), ''

    selected_provider = st.selectbox('Provedor em destaque', provider_options, key='stats_provider_spotlight')

    provider_mask = providers == selected_provider
    provider_df = df.loc[provider_mask].copy()
    spotlight_df = provider_df['Ip'].value_counts().head(10).reset_index()
    spotlight_df.columns = ['Endereco', 'Conexoes']
    spotlight_df['Endereco'] = spotlight_df['Endereco'].map(lambda value: value if len(str(value)) <= 18 else f"{str(value)[:15]}...")

    subtitle_parts = []
    if not df_dates.empty:
        provider_dates = df_dates.loc[provider_mask].copy()
        provider_dates = provider_dates.dropna(subset=['Data_parsed'])
        if not provider_dates.empty:
            start = provider_dates['Data_parsed'].min().strftime('%d/%m/%Y')
            end = provider_dates['Data_parsed'].max().strftime('%d/%m/%Y')
            subtitle_parts.append(f'(utilizada em conexoes entre {start} e {end})')

    if 'Ip_Regiao' in provider_df.columns:
        regions = [region for region in provider_df['Ip_Regiao'].dropna().astype(str).unique()[:3] if region]
        if regions:
            subtitle_parts.append(f"Regioes de: {', '.join(regions)}")

    subtitle = '<br>'.join(subtitle_parts)
    return provider_options, spotlight_df, subtitle


def page_estatisticas():
    from styles.components import empty_state, section_header

    section_header(
        t('estatisticas.title'),
        t('estatisticas.subtitle'),
        divider='violet',
    )

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('estatisticas.no_data'), '📈', t('common.process_data_first'))
        return

    total = len(df)
    unique_ips = df['Ip'].nunique() if 'Ip' in df.columns else 0
    n_providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0
    n_regions = df['Ip_Regiao'].dropna().nunique() if 'Ip_Regiao' in df.columns else 0

    proxy_pct = 0.0
    mobile_pct = 0.0
    if 'Ip_Proxy' in df.columns and total > 0:
        proxy_pct = _to_bool_series(df['Ip_Proxy']).sum() / total * 100
    if 'Ip_Movel' in df.columns and total > 0:
        mobile_pct = _to_bool_series(df['Ip_Movel']).sum() / total * 100

    trend_suffix = ''
    df_dates = _prepare_datetime_frame(df)
    if len(df_dates) >= 4:
        try:
            sorted_dates = df_dates['Data_parsed'].sort_values().reset_index(drop=True)
            middle = sorted_dates.iloc[len(sorted_dates) // 2]
            first_half = int((sorted_dates < middle).sum())
            second_half = int((sorted_dates >= middle).sum())
            if first_half > 0:
                variation = ((second_half - first_half) / first_half) * 100
                if variation > 10:
                    trend_suffix = f' ↑{abs(variation):.0f}%'
                elif variation < -10:
                    trend_suffix = f' ↓{abs(variation):.0f}%'
        except Exception:
            logger.exception('Falha ao calcular tendencia da atividade')

    top_suspect_ip = ''
    if 'Ip_Proxy' in df.columns and 'Ip' in df.columns:
        proxy_ips = df[_to_bool_series(df['Ip_Proxy'])]
        if not proxy_ips.empty:
            top_suspect_ip = proxy_ips['Ip'].value_counts().index[0]

    cards = [
        ('📋', str(total), f'Total Registros{trend_suffix}'),
        ('🌐', str(unique_ips), 'IPs Unicos'),
        ('🏢', str(n_providers), 'Provedores'),
        ('🗺️', str(n_regions), 'Regioes'),
        ('🛡️', f'{proxy_pct:.1f}%', 'Proxy/VPN'),
        ('📱', f'{mobile_pct:.1f}%', 'Movel'),
    ]
    card_cols = st.columns(len(cards))
    for index, (icon, value, label) in enumerate(cards):
        with card_cols[index]:
            with st.container(border=True):
                st.metric(f'{icon} {label}', value)

    if top_suspect_ip:
        st.error(f'🚨 **IP mais suspeito:** `{top_suspect_ip}` com sinais de proxy/VPN no conjunto analisado.')

    st.markdown('### Spotlight Operacional')
    spotlight_col, mix_col = st.columns([1.8, 1])
    with spotlight_col:
        provider_options, spotlight_df, provider_subtitle = _provider_spotlight_data(df, df_dates)
        with st.container(border=True):
            if provider_options and not spotlight_df.empty:
                spotlight_title = provider_options[0]
                selected_provider = st.session_state.get('stats_provider_spotlight', provider_options[0])
                spotlight_title = str(selected_provider).upper()
                fig = _build_focus_line_chart(
                    spotlight_df,
                    'Endereco',
                    'Conexoes',
                    spotlight_title,
                    provider_subtitle,
                    accent='#d4d4d8',
                    tickangle=-35,
                )
                st.plotly_chart(fig, width='stretch', key='stats_spotlight_provider')
            else:
                st.info('Nao ha dados suficientes para destacar um provedor.')

    with mix_col:
        with st.container(border=True):
            mix_fig = _build_connection_mix_chart(df)
            if mix_fig is not None:
                st.plotly_chart(mix_fig, width='stretch', key='stats_connection_mix')
            else:
                st.info('Sem dados suficientes para classificar o tipo de conexao.')

    st.markdown('### Ritmo de Uso')
    rhythm_col1, rhythm_col2 = st.columns(2)
    with rhythm_col1:
        with st.container(border=True):
            if not df_dates.empty:
                hourly_df = pd.DataFrame({
                    'Horario': [f'{hour:02d}:00' for hour in range(24)],
                    'Conexoes': df_dates['Data_parsed'].dt.hour.value_counts().reindex(range(24), fill_value=0).tolist(),
                })
                fig = _build_focus_line_chart(
                    hourly_df,
                    'Horario',
                    'Conexoes',
                    'Horarios',
                    'Faixas de maior intensidade ao longo do dia',
                    accent='#e5e7eb',
                    tickangle=-45,
                )
                st.plotly_chart(fig, width='stretch', key='stats_hourly')
            else:
                st.info('Sem datas validas para montar a serie horaria.')

    with rhythm_col2:
        with st.container(border=True):
            if not df_dates.empty:
                weekday_counts = df_dates['Data_parsed'].dt.day_name().value_counts().reindex(DAY_ORDER_EN, fill_value=0)
                weekday_df = pd.DataFrame({
                    'Dia': [DAY_NAME_PT[day] for day in DAY_ORDER_EN],
                    'Conexoes': weekday_counts.tolist(),
                })
                fig = _build_focus_line_chart(
                    weekday_df,
                    'Dia',
                    'Conexoes',
                    'Dias da Semana',
                    'Concentracao operacional por dia observado',
                    accent=COLORS['primary'],
                )
                st.plotly_chart(fig, width='stretch', key='stats_weekday')
            else:
                st.info('Sem datas validas para montar a serie semanal.')

    st.markdown('### Panorama Temporal e Territorial')
    panel_col1, panel_col2 = st.columns([1.4, 1])
    with panel_col1:
        with st.container(border=True):
            if not df_dates.empty:
                daily_df = (
                    df_dates.groupby(df_dates['Data_parsed'].dt.date)
                    .size()
                    .reset_index(name='Acessos')
                    .rename(columns={'Data_parsed': 'Dia'})
                )
                daily_df.columns = ['Dia', 'Acessos']
                daily_df['Dia'] = pd.to_datetime(daily_df['Dia'])
                fig = _build_focus_line_chart(
                    daily_df,
                    'Dia',
                    'Acessos',
                    'Timeline de Atividade',
                    'Serie diaria para identificar picos e janelas de silencio',
                    accent=COLORS['accent'],
                )
                fig.update_xaxes(tickformat='%d/%m')
                st.plotly_chart(fig, width='stretch', key='stats_daily_timeline')
            else:
                st.info('Sem datas validas para montar a timeline diaria.')

    with panel_col2:
        with st.container(border=True):
            if 'Ip_Regiao' in df.columns:
                region_df = df['Ip_Regiao'].fillna('Nao informado').value_counts().head(8).reset_index()
                region_df.columns = ['Regiao', 'Qtd']
                fig = _build_horizontal_bar_chart(region_df, 'Regiao', 'Qtd', 'Regioes Mais Ativas', COLORS['secondary'])
                st.plotly_chart(fig, width='stretch', key='stats_regions')
            else:
                st.info('Sem dados de regiao para o ranking territorial.')

    st.markdown('### Ranking de IPs e Calor Temporal')
    rank_col1, rank_col2 = st.columns([1.2, 1])
    with rank_col1:
        with st.container(border=True):
            if 'Ip' in df.columns:
                top_ips_df = df['Ip'].value_counts().head(12).reset_index()
                top_ips_df.columns = ['IP', 'Ocorrencias']
                fig = _build_horizontal_bar_chart(top_ips_df, 'IP', 'Ocorrencias', 'Top 12 IPs Mais Recorrentes', COLORS['info'], height=360)
                st.plotly_chart(fig, width='stretch', key='stats_top_ips')
            else:
                st.info('Sem coluna de IP para montar o ranking.')

    with rank_col2:
        with st.container(border=True):
            if not df_dates.empty:
                heat_df = df_dates.copy()
                heat_df['Hora'] = heat_df['Data_parsed'].dt.hour
                heat_df['DiaSemana'] = heat_df['Data_parsed'].dt.day_name().map(DAY_NAME_PT)
                heat_df['DiaSemana'] = pd.Categorical(
                    heat_df['DiaSemana'],
                    categories=[DAY_NAME_PT[item] for item in DAY_ORDER_EN],
                    ordered=True,
                )
                heat_pivot = heat_df.groupby(['DiaSemana', 'Hora']).size().reset_index(name='Acessos')
                heat_pivot = heat_pivot.pivot_table(index='DiaSemana', columns='Hora', values='Acessos', fill_value=0, observed=False)

                fig = go.Figure(data=go.Heatmap(
                    z=heat_pivot.values,
                    x=[f'{hour:02d}h' for hour in heat_pivot.columns],
                    y=heat_pivot.index,
                    colorscale=[
                        [0.0, _hex_to_rgba(COLORS['surface_elevated'], 0.8)],
                        [0.25, _hex_to_rgba(COLORS['info'], 0.55)],
                        [0.55, _hex_to_rgba(COLORS['warning'], 0.75)],
                        [1.0, _hex_to_rgba(COLORS['danger'], 0.9)],
                    ],
                    hovertemplate='%{y} - %{x}<br><b>%{z}</b> acessos<extra></extra>',
                ))
                fig.update_layout(
                    title=dict(text='<b>Mapa de Calor Temporal</b><br><span style="font-size:12px;color:#94a3b8">Hora x dia da semana para leitura de padrao</span>', x=0.02, xanchor='left'),
                    height=360,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    margin=dict(l=12, r=12, t=74, b=12),
                    font=dict(color=COLORS['text']),
                    xaxis=dict(tickfont=dict(color=COLORS['text_muted'])),
                    yaxis=dict(tickfont=dict(color=COLORS['text_muted'])),
                )
                st.plotly_chart(fig, width='stretch', key='stats_heatmap')
            else:
                st.info('Sem datas validas para gerar o mapa de calor.')

    st.markdown('### Anomalias e Detalhamento')
    anomalies = detect_anomalies(df)
    if anomalies:
        st.warning(f'**{len(anomalies)}** IPs com localizacao incomum detectados.')
        st.dataframe(pd.DataFrame(anomalies), width='stretch', hide_index=True)
    else:
        st.success('Nenhuma anomalia detectada no conjunto atual.')

    st.subheader('📋 Detalhamento por Provedor')
    if 'Ip_Dono' in df.columns:
        provider_table = df.groupby('Ip_Dono').agg(
            Total=('Ip', 'count'),
            Unicos=('Ip', 'nunique'),
            Cidades=('Ip_Cidade', lambda values: ', '.join(values.dropna().astype(str).unique()[:5])),
            Regioes=('Ip_Regiao', lambda values: ', '.join(values.dropna().astype(str).unique()[:3])),
        ).sort_values('Total', ascending=False).reset_index()
        provider_table.columns = ['Provedor', 'Total', 'Unicos', 'Cidades', 'Regioes']
        st.dataframe(provider_table, width='stretch', height=380, hide_index=True)