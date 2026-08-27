"""
html_report_generator.py — Gerador de Relatório HTML Interativo Standalone
=============================================================================
Gera um único arquivo .html self-contained com:
- CSS e JavaScript embutidos
- Gráficos Plotly interativos (zoom, hover, pan)
- Mapa Folium interativo
- Seções condicionais (só inclui quando há dados)
- Filtros de pesquisa em tabelas
- Expandir/colapsar seções
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from validators import as_bool, bool_series, parse_data

logger = logging.getLogger(__name__)

# Path do template
_TEMPLATE_PATH = Path(__file__).parent / "templates" / "report_template.html"


def _safe(val):
    """Sanitiza valores para exibição no template."""
    if pd.isna(val):
        return ""
    return str(val)


def _build_findings(df, analyses, n_total):
    """Compila achados principais para o sumário executivo."""
    findings = []

    proxy_n = hosting_n = mobile_n = 0
    if all(c in df.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        proxy_n = int(bool_series(df, 'Ip_Proxy').sum())
        hosting_n = int(bool_series(df, 'Ip_Hospedagem').sum())
        mobile_n = int(bool_series(df, 'Ip_Movel').sum())

    if proxy_n + hosting_n > n_total * 0.3:
        findings.append(f'Alto uso de anonimização ({proxy_n + hosting_n} conexões via proxy/hosting)')

    vpn = analyses.get('vpn_heuristics', {})
    if vpn and vpn.get('score', 0) >= 50:
        findings.append(f'Indicadores de VPN detectados (score: {vpn["score"]})')

    jumps = analyses.get('impossible_jumps')
    if isinstance(jumps, pd.DataFrame) and not jumps.empty:
        findings.append(f'{len(jumps)} salto(s) impossível(is) detectado(s)')
    elif isinstance(jumps, list) and len(jumps) > 0:
        findings.append(f'{len(jumps)} salto(s) impossível(is) detectado(s)')

    risk = analyses.get('risk_scores')
    if isinstance(risk, pd.DataFrame) and not risk.empty and 'Score' in risk.columns:
        high_risk = len(risk[risk['Score'] >= 70])
        if high_risk > 0:
            findings.append(f'{high_risk} IP(s) com risco elevado (>= 70)')

    return findings, proxy_n, hosting_n, mobile_n


# Linhas por bloco ao calcular o hash de integridade do dataset.
_HASH_CHUNK_ROWS = 50000
# Teto de marcadores no mapa do relatório. Cada marcador vira ~500 bytes de
# HTML inline, e o branca escapa o mapa inteiro dentro de um iframe srcdoc
# (multiplicador de 4-6x sobre a string final).
MAX_MAP_MARKERS = 5000


def _hash_dataframe_csv(df, chunk_rows=_HASH_CHUNK_ROWS):
    """SHA-256 do CSV do DataFrame, sem materializá-lo inteiro em memória.

    Idêntico a `sha256(df.to_csv(index=False).encode('utf-8'))`: o primeiro
    bloco carrega o cabeçalho e os demais não, exatamente como o CSV único.
    """
    digest = hashlib.sha256()
    total = len(df)
    if total == 0:
        return hashlib.sha256(df.to_csv(index=False).encode('utf-8')).hexdigest()
    for start in range(0, total, chunk_rows):
        piece = df.iloc[start:start + chunk_rows]
        digest.update(piece.to_csv(index=False, header=(start == 0)).encode('utf-8'))
    return digest.hexdigest()


def _generate_map_html(df):
    """Gera mapa Folium com layers por tipo, popups ricos, legenda e fit bounds."""
    try:
        import folium
        from folium.plugins import MarkerCluster, Fullscreen
        from branca.element import Template, MacroElement
    except ImportError:
        logger.warning("folium não disponível — mapa omitido")
        return ""

    df_map = df.copy()
    df_map['Ip_Lat'] = pd.to_numeric(df_map.get('Ip_Lat'), errors='coerce')
    df_map['Ip_Lon'] = pd.to_numeric(df_map.get('Ip_Lon'), errors='coerce')
    df_map = df_map.dropna(subset=['Ip_Lat', 'Ip_Lon'])
    df_map = df_map[(df_map['Ip_Lat'] != 0) | (df_map['Ip_Lon'] != 0)]

    if df_map.empty:
        return ""

    ip_col = 'Ip' if 'Ip' in df_map.columns else 'Sender IP'

    # Agrega por (lat, lon, ip) para popups consolidados
    grouping_cols = ['Ip_Lat', 'Ip_Lon', ip_col]
    extra_cols = [c for c in ['Ip_Pais', 'Ip_Cidade', 'Ip_Dono',
                              'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel'] if c in df_map.columns]
    agg = (df_map.groupby(grouping_cols, dropna=False)
                  .agg(_count=(ip_col, 'size'),
                       **{c: (c, 'first') for c in extra_cols})
                  .reset_index())

    # Truncagem visível: mantém os pontos de maior ocorrência e declara
    # no próprio mapa o que ficou de fora.
    marker_note = ''
    if len(agg) > MAX_MAP_MARKERS:
        total_markers = len(agg)
        total_records = int(agg['_count'].sum())
        agg = agg.nlargest(MAX_MAP_MARKERS, '_count')
        kept_records = int(agg['_count'].sum())
        pct = kept_records / total_records * 100 if total_records else 0
        marker_note = (
            f'Mapa exibindo os {MAX_MAP_MARKERS:,} pontos de maior ocorrência '
            f'de {total_markers:,} ({pct:.1f}% dos registros).'
        ).replace(',', '.')
        logger.info("Mapa do relatório truncado: %d de %d marcadores",
                    MAX_MAP_MARKERS, total_markers)

    center_lat = float(agg['Ip_Lat'].mean())
    center_lon = float(agg['Ip_Lon'].mean())
    # Fundo sem chave de API. Os tiles da CARTO passaram a voltar carimbados
    # com "API KEY REQUIRED" por cima do mapa, o que num laudo entregue
    # inutiliza a figura. Ver helpers/geo.TILE_SOURCES.
    from helpers.geo import (DEFAULT_TILE_RELATORIO, TILE_SOURCES,
                             TILE_SOURCES_COM_ROTULO)

    m = folium.Map(location=[center_lat, center_lon], zoom_start=3,
                   tiles=None, control_scale=True)
    for nome in TILE_SOURCES_COM_ROTULO:
        fonte = TILE_SOURCES[nome]
        folium.TileLayer(
            tiles=fonte['url'], attr=fonte['attr'], name=nome, overlay=False,
            show=(nome == DEFAULT_TILE_RELATORIO),
        ).add_to(m)

    # Feature groups por categoria
    fg_resid = folium.FeatureGroup(name='Residencial / Móvel', show=True)
    fg_hosting = folium.FeatureGroup(name='Hosting / Datacenter', show=True)
    fg_proxy = folium.FeatureGroup(name='Proxy / VPN', show=True)
    cluster_resid = MarkerCluster().add_to(fg_resid)
    cluster_hosting = MarkerCluster().add_to(fg_hosting)
    cluster_proxy = MarkerCluster().add_to(fg_proxy)

    lats, lons = [], []
    for _, row in agg.iterrows():
        ip = str(row.get(ip_col, 'N/A'))
        cidade = _safe(row.get('Ip_Cidade'))
        pais = _safe(row.get('Ip_Pais'))
        dono = _safe(row.get('Ip_Dono'))
        count = int(row['_count'])

        is_proxy = as_bool(row.get('Ip_Proxy'), field='Ip_Proxy')
        is_hosting = as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem')
        is_mobile = as_bool(row.get('Ip_Movel'), field='Ip_Movel')

        if is_proxy:
            color, tipo, target = '#f87171', 'Proxy/VPN', cluster_proxy
        elif is_hosting:
            color, tipo, target = '#fbbf24', 'Hosting', cluster_hosting
        elif is_mobile:
            color, tipo, target = '#60a5fa', 'Móvel', cluster_resid
        else:
            color, tipo, target = '#34d399', 'Residencial', cluster_resid

        popup_html = (
            f'<div style="font-family:Segoe UI,Arial,sans-serif;min-width:220px;">'
            f'<div style="font-weight:600;font-size:13px;margin-bottom:4px;">{ip}</div>'
            f'<div style="font-size:11px;color:#475569;">'
            f'<b>Tipo:</b> <span style="color:{color}">{tipo}</span><br>'
            f'<b>Local:</b> {cidade or "—"}, {pais or "—"}<br>'
            f'<b>Provedor:</b> {dono or "—"}<br>'
            f'<b>Ocorrências:</b> {count}'
            f'</div></div>'
        )

        # Raio proporcional ao log do count
        import math
        radius = min(4 + math.log1p(count) * 2, 16)

        folium.CircleMarker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            radius=radius,
            color=color,
            weight=1.5,
            fill=True,
            fill_color=color,
            fill_opacity=0.75,
            popup=folium.Popup(popup_html, max_width=300),
            tooltip=f"{ip} ({count})",
        ).add_to(target)

        lats.append(row['Ip_Lat'])
        lons.append(row['Ip_Lon'])

    fg_resid.add_to(m)
    fg_hosting.add_to(m)
    fg_proxy.add_to(m)
    folium.LayerControl(collapsed=False, position='topright').add_to(m)
    Fullscreen(position='topleft').add_to(m)

    # Fit bounds
    if lats and lons and (max(lats) != min(lats) or max(lons) != min(lons)):
        m.fit_bounds([[min(lats), min(lons)], [max(lats), max(lons)]], padding=(20, 20))

    # Legenda customizada
    legend_html = """
    {% macro html(this, kwargs) %}
    <div style="position: fixed; bottom: 20px; left: 20px; z-index: 9999;
                background: rgba(15,23,42,0.92); color: #f1f5f9;
                padding: 10px 14px; border-radius: 8px; font-size: 12px;
                font-family: Segoe UI, Arial, sans-serif;
                box-shadow: 0 4px 14px rgba(0,0,0,0.4); border: 1px solid #334155;">
      <div style="font-weight:600;margin-bottom:6px;">Tipo de Conexão</div>
      <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#34d399;margin-right:6px;"></span>Residencial</div>
      <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#60a5fa;margin-right:6px;"></span>Móvel</div>
      <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#fbbf24;margin-right:6px;"></span>Hosting</div>
      <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f87171;margin-right:6px;"></span>Proxy/VPN</div>
      <div style="font-size:10px;color:#94a3b8;margin-top:6px;">Tamanho ∝ ocorrências</div>
    </div>
    {% endmacro %}
    """
    macro = MacroElement()
    macro._template = Template(legend_html)
    m.get_root().add_child(macro)

    html = m._repr_html_()
    if marker_note:
        html = (f'<p style="font-size:0.8rem;color:#f59e0b;margin:0 0 8px;">'
                f'&#9888; {marker_note}</p>' + html)
    return html


def _plotly_to_div(fig, width=900, height=420):
    """Converte figura Plotly em div HTML embutido."""
    return fig.to_html(
        full_html=False,
        include_plotlyjs='cdn',
        default_width=width,
        default_height=height,
    )


def _generate_provider_plot(df, n_total):
    """Gráfico de barras horizontais dos top provedores."""
    if 'Ip_Dono' not in df.columns:
        return ""
    pc = df['Ip_Dono'].value_counts().head(10).reset_index()
    if pc.empty:
        return ""
    pc.columns = ['Provedor', 'Qtd']
    fig = px.bar(pc, x='Qtd', y='Provedor', orientation='h',
                 color='Qtd', color_continuous_scale='Viridis',
                 title='Top 10 Provedores')
    fig.update_layout(
        yaxis={'categoryorder': 'total ascending'},
        coloraxis_showscale=False,
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
    )
    fig.update_xaxes(showgrid=True, gridcolor='rgba(148,163,184,0.1)')
    fig.update_yaxes(showgrid=False)
    return _plotly_to_div(fig)


def _generate_connection_plot(df, n_total, proxy_n, hosting_n, mobile_n):
    """Gráfico donut de tipos de conexão."""
    normal_n = n_total - proxy_n - hosting_n - mobile_n
    labels = ['Residencial', 'Móvel', 'Proxy/VPN', 'Hosting']
    values = [max(normal_n, 0), mobile_n, proxy_n, hosting_n]
    colors = ['#34d399', '#60a5fa', '#f87171', '#fbbf24']

    if sum(values) == 0:
        return ""

    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.55,
        marker_colors=colors,
        textinfo='label+percent',
        textfont_size=12,
        hovertemplate='%{label}: %{value} (%{percent})<extra></extra>',
    )])
    fig.update_layout(
        title='Tipos de Conexão',
        showlegend=False,
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
    )
    return _plotly_to_div(fig, height=380)


def _generate_period_plot(df):
    """Gráfico de barras por período do dia."""
    if 'Periodo' not in df.columns:
        return ""
    pc = df['Periodo'].value_counts().reset_index()
    if pc.empty:
        return ""
    pc.columns = ['Periodo', 'Acessos']
    fig = px.bar(pc, x='Periodo', y='Acessos', color='Acessos',
                 color_continuous_scale='Viridis', title='Atividade por Período')
    fig.update_layout(
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
    )
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(showgrid=True, gridcolor='rgba(148,163,184,0.1)')
    return _plotly_to_div(fig, height=380)


def _generate_timeline_plot(df, risk_df=None):
    """Timeline cronológica: scatter por timestamp colorido por provedor/risco."""
    if 'Data' not in df.columns:
        return ""
    work = df.copy()
    work['_dt'] = parse_data(work['Data'])
    work = work.dropna(subset=['_dt'])
    if work.empty:
        return ""

    ip_col = 'Sender IP' if 'Sender IP' in work.columns else 'Ip'

    # Mapa IP -> score de risco (se disponível)
    score_map = {}
    if isinstance(risk_df, pd.DataFrame) and not risk_df.empty and 'IP' in risk_df.columns:
        score_map = dict(zip(risk_df['IP'].astype(str), risk_df['Score']))

    work['_ip'] = work.get(ip_col, '').astype(str)
    work['_score'] = work['_ip'].map(score_map).fillna(0)
    work['_prov'] = work.get('Ip_Dono', '').astype(str)
    work['_city'] = work.get('Ip_Cidade', '').astype(str)

    # Amostrar se muito grande (mantém legibilidade)
    if len(work) > 5000:
        work = work.sample(5000, random_state=42).sort_values('_dt')

    fig = px.scatter(
        work, x='_dt', y='_prov',
        color='_score',
        color_continuous_scale=[(0, '#34d399'), (0.4, '#fbbf24'), (0.7, '#f87171')],
        range_color=[0, 100],
        hover_data={'_ip': True, '_city': True, '_score': ':.0f', '_dt': '|%Y-%m-%d %H:%M', '_prov': False},
        labels={'_dt': 'Data', '_prov': 'Provedor', '_score': 'Risco', '_ip': 'IP', '_city': 'Cidade'},
        title='Timeline Cronológica',
    )
    fig.update_traces(marker=dict(size=7, opacity=0.75, line=dict(width=0)))
    fig.update_layout(
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
        coloraxis_colorbar=dict(title='Risco', thickness=12),
    )
    fig.update_xaxes(showgrid=True, gridcolor='rgba(148,163,184,0.1)')
    fig.update_yaxes(showgrid=False, automargin=True)
    return _plotly_to_div(fig, height=480)


def _generate_heatmap_plot(df):
    """Heatmap hora × dia da semana de atividade."""
    if 'Data' not in df.columns:
        return ""
    work = df.copy()
    work['_dt'] = parse_data(work['Data'])
    work = work.dropna(subset=['_dt'])
    if work.empty:
        return ""

    work['_hour'] = work['_dt'].dt.hour
    work['_dow'] = work['_dt'].dt.dayofweek  # 0=Mon

    matrix = work.groupby(['_dow', '_hour']).size().unstack(fill_value=0)
    matrix = matrix.reindex(index=range(7), columns=range(24), fill_value=0)

    dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']
    horas = [f'{h:02d}h' for h in range(24)]

    fig = go.Figure(data=go.Heatmap(
        z=matrix.values,
        x=horas, y=dias,
        colorscale='Viridis',
        hovertemplate='%{y} %{x}<br>Acessos: %{z}<extra></extra>',
        colorbar=dict(title='Acessos', thickness=12),
    ))
    fig.update_layout(
        title='Atividade por Hora × Dia da Semana',
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
    )
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(showgrid=False, autorange='reversed')
    return _plotly_to_div(fig, height=380)


def _generate_sankey_plot(df, max_per_level=8):
    """Sankey País → Provedor → Tipo de Conexão."""
    needed = ['Ip_Pais', 'Ip_Dono']
    if not all(c in df.columns for c in needed):
        return ""
    work = df.copy()
    work['Ip_Pais'] = work['Ip_Pais'].fillna('Desconhecido').astype(str)
    work['Ip_Dono'] = work['Ip_Dono'].fillna('Desconhecido').astype(str)

    def _conn_type(row):
        if as_bool(row.get('Ip_Proxy'), field='Ip_Proxy'):
            return 'Proxy/VPN'
        if as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem'):
            return 'Hosting'
        if as_bool(row.get('Ip_Movel'), field='Ip_Movel'):
            return 'Móvel'
        return 'Residencial'

    # Limita top-N de cada nível ANTES de classificar: o apply por linha rodava
    # sobre o DataFrame inteiro para depois descartar quase tudo.
    top_countries = set(work['Ip_Pais'].value_counts().head(max_per_level).index)
    top_providers = set(work['Ip_Dono'].value_counts().head(max_per_level).index)
    work = work[work['Ip_Pais'].isin(top_countries) & work['Ip_Dono'].isin(top_providers)]
    if work.empty:
        return ""

    work = work.copy()
    work['_conn'] = np.select(
        [bool_series(work, 'Ip_Proxy'),
         bool_series(work, 'Ip_Hospedagem'),
         bool_series(work, 'Ip_Movel')],
        ['Proxy/VPN', 'Hosting', 'Móvel'],
        default='Residencial')

    # Constrói nós e fluxos
    countries = sorted(work['Ip_Pais'].unique())
    providers = sorted(work['Ip_Dono'].unique())
    conns = ['Residencial', 'Móvel', 'Hosting', 'Proxy/VPN']

    nodes = list(countries) + list(providers) + conns
    node_idx = {n: i for i, n in enumerate(nodes)}

    source, target, value = [], [], []
    # País -> Provedor
    cp = work.groupby(['Ip_Pais', 'Ip_Dono']).size().reset_index(name='n')
    for _, r in cp.iterrows():
        source.append(node_idx[r['Ip_Pais']])
        target.append(node_idx[r['Ip_Dono']])
        value.append(int(r['n']))
    # Provedor -> Tipo conexão
    pc = work.groupby(['Ip_Dono', '_conn']).size().reset_index(name='n')
    for _, r in pc.iterrows():
        if r['_conn'] not in node_idx:
            continue
        source.append(node_idx[r['Ip_Dono']])
        target.append(node_idx[r['_conn']])
        value.append(int(r['n']))

    if not value:
        return ""

    node_colors = (
        ['#60a5fa'] * len(countries) +
        ['#818cf8'] * len(providers) +
        ['#34d399', '#60a5fa', '#fbbf24', '#f87171']
    )

    fig = go.Figure(data=[go.Sankey(
        node=dict(label=nodes, color=node_colors,
                  pad=14, thickness=14,
                  line=dict(color='rgba(148,163,184,0.3)', width=0.5)),
        link=dict(source=source, target=target, value=value,
                  color='rgba(129,140,248,0.25)'),
    )])
    fig.update_layout(
        title=f'Fluxo País → Provedor → Tipo (top {max_per_level})',
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font_color='#f1f5f9',
    )
    return _plotly_to_div(fig, height=460)


def generate_html_report(df, alvo, config=None, analyses=None, audit_hash=None):
    """
    Gera relatório HTML interativo standalone.

    Args:
        df: DataFrame com dados enriquecidos
        alvo: Identificador do alvo
        config: dict com configurações do relatório
        analyses: dict com resultados de análises avançadas
        audit_hash: hash SHA-256 do audit trail

    Returns:
        bytes: conteúdo HTML do relatório
    """
    config = config or {}
    analyses = analyses or {}

    n_total = len(df)
    n_unique = df['Ip'].nunique() if 'Ip' in df.columns else 0
    n_countries = df['Ip_Pais'].dropna().nunique() if 'Ip_Pais' in df.columns else 0
    n_providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0

    findings, proxy_n, hosting_n, mobile_n = _build_findings(df, analyses, n_total)
    proxy_pct = proxy_n / max(n_total, 1) * 100
    hosting_pct = hosting_n / max(n_total, 1) * 100
    mobile_pct = mobile_n / max(n_total, 1) * 100

    # Período
    periodo_inicio = periodo_fim = dias_atividade = ""
    if 'Data' in df.columns:
        dates = pd.to_datetime(df['Data'], errors='coerce').dropna()
        if len(dates) > 0:
            periodo_inicio = dates.min().strftime('%d/%m/%Y')
            periodo_fim = dates.max().strftime('%d/%m/%Y')
            dias_atividade = dates.dt.date.nunique()

    # Hash dos dados, em blocos.
    # `df.to_csv()` inteiro produzia UMA string contígua com todo o dataset e
    # `.encode()` uma segunda cópia — duas alocações gigantes só para calcular
    # um digest. O resultado é byte-a-byte idêntico ao anterior (mesmo CSV,
    # apenas alimentado ao hash em pedaços).
    data_hash = _hash_dataframe_csv(df)

    # ----- BRANDING -----
    branding_in = config.get('branding') or {}
    branding = {
        'logo_b64': branding_in.get('logo_b64', ''),
        'primary_color': branding_in.get('primary_color', ''),
        'accent_color': branding_in.get('accent_color', ''),
        'watermark': (branding_in.get('watermark') or '').strip(),
    }

    # ----- CADEIA DE CUSTÓDIA -----
    coc_in = config.get('coc') or {}
    coc = {
        'input_file': coc_in.get('input_file', ''),
        'input_hash': coc_in.get('input_hash', ''),
        'output_file': coc_in.get('output_file', ''),
        'operator': coc_in.get('operator', ''),
        'hostname': coc_in.get('hostname', ''),
        'enrichment_source': coc_in.get('enrichment_source', 'ip-api.com'),
        # v5.3: coerção de booleanos corrigida (1/0 e VERDADEIRO passaram a ser
        # reconhecidos). Relatórios v5.2 e v5.3 podem divergir sobre o mesmo
        # arquivo de entrada — por isso a versão consta na cadeia de custódia.
        'tool_version': coc_in.get('tool_version', 'Log Enrichment v5.3'),
        'receipt_hash': coc_in.get('receipt_hash', ''),
        'generated_at_iso': coc_in.get('generated_at_iso', datetime.now().isoformat()),
    }

    # ----- ASSINATURAS -----
    signatures = []
    for s in (config.get('signatures') or []):
        name = (s.get('name') or '').strip()
        role = (s.get('role') or '').strip()
        if name or role:
            signatures.append({'name': name, 'role': role})

    # ----- QUALIDADE DOS DADOS -----
    def _present(col):
        if col not in df.columns:
            return 0
        non_na = df[col].notna().sum()
        empty = (df[col].astype(str).str.strip() == '').sum()
        return int(non_na) - int(empty)

    geo_present = _present('Ip_Lat') if 'Ip_Lat' in df.columns else 0
    prov_present = _present('Ip_Dono')
    city_present = _present('Ip_Cidade')
    country_present = _present('Ip_Pais')
    data_quality = {
        'total': n_total,
        'unique_ips': n_unique,
        'with_geo': geo_present,
        'with_geo_pct': geo_present / max(n_total, 1) * 100,
        'with_provider': prov_present,
        'with_provider_pct': prov_present / max(n_total, 1) * 100,
        'with_city': city_present,
        'with_country': country_present,
        'missing_geo': max(n_total - geo_present, 0),
        'missing_geo_pct': max(n_total - geo_present, 0) / max(n_total, 1) * 100,
    }

    # ----- GRÁFICOS -----
    provider_plot = _generate_provider_plot(df, n_total)
    connection_plot = _generate_connection_plot(df, n_total, proxy_n, hosting_n, mobile_n)
    period_plot = _generate_period_plot(df)
    risk_df_for_plot = analyses.get('risk_scores') if isinstance(analyses.get('risk_scores'), pd.DataFrame) else None
    timeline_plot = _generate_timeline_plot(df, risk_df_for_plot)
    heatmap_plot = _generate_heatmap_plot(df)
    sankey_plot = _generate_sankey_plot(df)

    # ----- MAPA -----
    map_html = _generate_map_html(df)
    has_geo = bool(map_html)

    # ----- TABELAS -----
    provider_table = []
    if 'Ip_Dono' in df.columns:
        for prov, cnt in df['Ip_Dono'].value_counts().head(15).items():
            provider_table.append({
                'provedor': str(prov),
                'ocorrencias': cnt,
                'pct': cnt / max(n_total, 1) * 100,
            })

    country_table = []
    if 'Ip_Pais' in df.columns:
        for pais, cnt in df['Ip_Pais'].value_counts().head(10).items():
            country_table.append({'pais': str(pais), 'ocorrencias': cnt, 'pct': cnt / max(n_total, 1) * 100})

    region_table = []
    if 'Ip_Regiao' in df.columns:
        for reg, cnt in df['Ip_Regiao'].value_counts().head(10).items():
            region_table.append({'regiao': str(reg), 'ocorrencias': cnt})

    period_table = []
    if 'Periodo' in df.columns:
        for per, cnt in df['Periodo'].value_counts().items():
            period_table.append({'periodo': str(per), 'acessos': cnt, 'pct': cnt / max(n_total, 1) * 100})

    # ----- RISK SCORES -----
    risk_scores = []
    risk_high = risk_med = risk_low = 0
    risk_df = analyses.get('risk_scores')
    if isinstance(risk_df, pd.DataFrame) and not risk_df.empty and 'Score' in risk_df.columns:
        risk_high = len(risk_df[risk_df['Score'] >= 70])
        risk_med = len(risk_df[(risk_df['Score'] >= 40) & (risk_df['Score'] < 70)])
        risk_low = len(risk_df[risk_df['Score'] < 40])
        for _, r in risk_df.head(20).iterrows():
            risk_scores.append({
                'ip': str(r.get('IP', '')),
                'score': int(r.get('Score', 0)),
                'classificacao': str(r.get('Fatores', '')),
                'breakdown': r.get('Breakdown') if isinstance(r.get('Breakdown'), list) else [],
                'provedor': str(r.get('Ip_Dono', r.get('Provedor', ''))),
                'cidade': str(r.get('Ip_Cidade', r.get('Cidade', ''))),
            })

    # ----- IMPOSSIBLE JUMPS -----
    impossible_jumps = []
    jumps = analyses.get('impossible_jumps')
    if isinstance(jumps, pd.DataFrame) and not jumps.empty:
        for _, r in jumps.head(20).iterrows():
            impossible_jumps.append({
                'de_ip': str(r.get('De_IP', '')),
                'para_ip': str(r.get('Para_IP', '')),
                'de_cidade': str(r.get('De_Cidade', '')),
                'para_cidade': str(r.get('Para_Cidade', '')),
                'distancia': r.get('Distancia_km', 0),
                'tempo': r.get('Tempo_h', 0),
                'velocidade': r.get('Velocidade_kmh', 0),
            })
    elif isinstance(jumps, list):
        for j in jumps[:20]:
            impossible_jumps.append({
                'de_ip': j.get('De_IP', j.get('from_ip', '')),
                'para_ip': j.get('Para_IP', j.get('to_ip', '')),
                'de_cidade': j.get('De_Cidade', ''),
                'para_cidade': j.get('Para_Cidade', ''),
                'distancia': j.get('Distancia_km', j.get('distance_km', 0)),
                'tempo': j.get('Tempo_h', j.get('time_hours', 0)),
                'velocidade': j.get('Velocidade_kmh', j.get('speed_kmh', 0)),
            })

    # ----- VPN HEURISTICS -----
    vpn_heuristics = analyses.get('vpn_heuristics', {})
    if not vpn_heuristics or vpn_heuristics.get('score', 0) <= 0:
        vpn_heuristics = None

    # ----- IP CONFIDENCE -----
    ip_confidence = []
    ip_conf_df = analyses.get('ip_confidence')
    if isinstance(ip_conf_df, pd.DataFrame) and not ip_conf_df.empty:
        for _, r in ip_conf_df.head(20).iterrows():
            ip_confidence.append({
                'ip': str(r.get('IP', '')),
                'score': int(r.get('Confidence', 0)),
                'classificacao': str(r.get('Classification', '')),
                'motivo': str(r.get('Motivo', ''))[:80],
            })

    # ----- BASE LOCATIONS -----
    base_locations = analyses.get('base_locations', {})
    if base_locations and not (base_locations.get('home') or base_locations.get('work')):
        base_locations = None

    # ----- LIFE PATTERNS -----
    life_patterns = analyses.get('life_patterns')
    if not life_patterns or not life_patterns.get('has_data'):
        life_patterns = None

    # ----- TOP IPs -----
    top_ips = []
    if 'Ip' in df.columns:
        for ip, cnt in df['Ip'].value_counts().head(20).items():
            ip_data = df[df['Ip'] == ip].iloc[0]
            top_ips.append({
                'ip': str(ip),
                'count': cnt,
                'provedor': str(ip_data.get('Ip_Dono', '')),
                'pais': str(ip_data.get('Ip_Pais', '')),
                'cidade': str(ip_data.get('Ip_Cidade', '')),
            })

    # ----- RAW DATA -----
    raw_data = []
    raw_headers = []
    if config.get('include_raw_data', False):
        export_cols = [c for c in ['Data', 'Ip', 'Ip_Pais', 'Ip_Regiao', 'Ip_Cidade', 'Ip_Dono']
                       if c in df.columns]
        if export_cols:
            sample = df[export_cols].head(100)
            raw_headers = export_cols
            for _, r in sample.iterrows():
                raw_data.append([_safe(v) for v in r.values])

    # ----- BEHAVIORAL PROFILE -----
    behavioral_profile = analyses.get('behavioral_profile', {})
    if not behavioral_profile or not behavioral_profile.get('resumo'):
        behavioral_profile = None

    # ----- DIGITAL SILENCE -----
    digital_silence = analyses.get('digital_silence')
    if not (isinstance(digital_silence, dict) and digital_silence.get('detected')):
        digital_silence = None
    elif digital_silence:
        # cap periods rendered in report
        ds = dict(digital_silence)
        ds['periods'] = ds.get('periods', [])[:30]
        digital_silence = ds

    # ----- SUBNET PATTERNS -----
    subnet_patterns = analyses.get('subnet_patterns')
    if isinstance(subnet_patterns, dict) and subnet_patterns.get('subnets'):
        sp = dict(subnet_patterns)
        # only show subnets with > 1 IP (more interesting)
        relevant = [s for s in sp.get('subnets', []) if s.get('ip_count', 0) >= 2]
        if not relevant:
            relevant = sp.get('subnets', [])[:5]
        sp['subnets'] = relevant[:20]
        sp['dominant_subnets'] = sp.get('dominant_subnets', [])[:5]
        subnet_patterns = sp
    else:
        subnet_patterns = None

    # ----- TIMEZONE CONSISTENCY -----
    tz_consistency = analyses.get('timezone_consistency')
    if isinstance(tz_consistency, dict) and tz_consistency.get('analyzed') and \
       tz_consistency.get('total_inconsistencies', 0) > 0:
        tc = dict(tz_consistency)
        tc['inconsistencies'] = tc.get('inconsistencies', [])[:30]
        tz_consistency = tc
    else:
        tz_consistency = None

    # ----- PROVIDER TIMING -----
    provider_timing = analyses.get('provider_timing')
    provider_timing_view = None
    if isinstance(provider_timing, dict) and provider_timing.get('providers'):
        prov_list = []
        for name, info in provider_timing['providers'].items():
            peak_hrs = info.get('peak_hours', [])
            prov_list.append({
                'provedor': name,
                'tipo_uso': info.get('usage_type', ''),
                'registros': info.get('total_records', 0),
                'horas_ativas': info.get('active_hours', 0),
                'sessao_min': info.get('avg_session_minutes', 0),
                'pico': ', '.join(f"{h:02d}h" for h in peak_hrs[:3]),
            })
        prov_list.sort(key=lambda x: x['registros'], reverse=True)
        provider_timing_view = {
            'providers': prov_list[:20],
            'vpn_schedule': provider_timing.get('vpn_schedule', {}),
        }

    # ----- GEO CHANGES (cache history) -----
    geo_changes = analyses.get('geo_changes')
    if isinstance(geo_changes, dict) and geo_changes.get('total_changes', 0) > 0:
        gc = dict(geo_changes)
        gc['changed_ips'] = gc.get('changed_ips', [])[:30]
        geo_changes = gc
    else:
        geo_changes = None

    # ----- SHARED WIFI (cross-target) -----
    shared_wifi = analyses.get('shared_wifi')
    if isinstance(shared_wifi, list) and shared_wifi:
        shared_wifi = shared_wifi[:30]
    else:
        shared_wifi = None

    # ----- CROSS-TARGET CORRELATION -----
    cross_correlation_raw = analyses.get('cross_correlation')
    cross_correlation = None
    if isinstance(cross_correlation_raw, pd.DataFrame) and not cross_correlation_raw.empty:
        cc_rows = []
        for _, r in cross_correlation_raw.head(30).iterrows():
            cc_rows.append({
                'ip': str(r.get('IP', r.get('Ip', ''))),
                'alvos': str(r.get('Alvos', r.get('Targets', ''))),
                'ocorrencias': int(r.get('Ocorrencias', r.get('Count', 0)) or 0),
                'provedor': str(r.get('Ip_Dono', r.get('Provedor', ''))),
                'pais': str(r.get('Ip_Pais', r.get('Pais', ''))),
                'cidade': str(r.get('Ip_Cidade', r.get('Cidade', ''))),
            })
        if cc_rows:
            cross_correlation = cc_rows
    elif isinstance(cross_correlation_raw, list) and cross_correlation_raw:
        cross_correlation = cross_correlation_raw[:30]

    # ----- RENDER -----
    try:
        from jinja2 import Template
    except ImportError:
        logger.error("Jinja2 não está instalado — necessário para gerar relatório HTML")
        raise

    template_text = _TEMPLATE_PATH.read_text(encoding='utf-8')
    template = Template(template_text)

    html = template.render(
        title=config.get('title', 'Relatório de Análise de IPs'),
        alvo=alvo,
        case_number=config.get('case_number', ''),
        analyst=config.get('analyst', ''),
        organization=config.get('organization', ''),
        classification=config.get('classification', ''),
        generated_at=datetime.now().strftime('%d/%m/%Y %H:%M'),
        data_hash=data_hash,
        audit_hash=audit_hash or '',
        branding=branding,
        coc=coc,
        signatures=signatures,
        data_quality=data_quality,
        n_total=n_total,
        n_unique_ips=n_unique,
        n_countries=n_countries,
        n_providers=n_providers,
        dias_atividade=dias_atividade,
        proxy_pct=proxy_pct,
        hosting_pct=hosting_pct,
        mobile_pct=mobile_pct,
        periodo_inicio=periodo_inicio,
        periodo_fim=periodo_fim,
        findings=findings,
        has_geo=has_geo,
        map_html=map_html,
        country_table=country_table,
        region_table=region_table,
        provider_plot=provider_plot,
        provider_table=provider_table,
        connection_plot=connection_plot,
        period_plot=period_plot,
        period_table=period_table,
        timeline_plot=timeline_plot,
        heatmap_plot=heatmap_plot,
        sankey_plot=sankey_plot,
        risk_scores=risk_scores,
        risk_high=risk_high,
        risk_med=risk_med,
        risk_low=risk_low,
        impossible_jumps=impossible_jumps,
        vpn_heuristics=vpn_heuristics,
        ip_confidence=ip_confidence,
        base_locations=base_locations,
        life_patterns=life_patterns,
        top_ips=top_ips,
        raw_headers=raw_headers,
        raw_data=raw_data,
        behavioral_profile=behavioral_profile,
        digital_silence=digital_silence,
        subnet_patterns=subnet_patterns,
        tz_consistency=tz_consistency,
        provider_timing=provider_timing_view,
        geo_changes=geo_changes,
        shared_wifi=shared_wifi,
        cross_correlation=cross_correlation,
    )

    return html.encode('utf-8')
