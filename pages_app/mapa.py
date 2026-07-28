"""
Log Enrichment - Pagina do Mapa
Mapa 2D investigativo com Folium/Leaflet, clusters, heatmap, rota temporal e ferramentas avancadas.
"""

import json
import logging
import math
import os

import folium
import pandas as pd
import plotly.express as px
import streamlit as st
from folium.plugins import Fullscreen, HeatMap, MarkerCluster, MeasureControl, MiniMap
from streamlit_folium import st_folium

from analysis import (
    calculate_movement_area,
    check_geofence,
    classify_dataframe,
    classify_infrastructure,
    compare_periods,
    detect_base_locations,
    detect_impossible_jumps,
    detect_travel_pattern,
    export_kml,
    export_kml_animated,
    generate_behavioral_profile,
)
from components.visualizations import render_map_replay
from helpers.geo import build_cluster_popup, build_rich_popup, haversine_km

logger = logging.getLogger(__name__)

FOLIUM_TILE_SOURCES = {
    'Escuro': {
        'tiles': 'CartoDB dark_matter',
        'attr': '© OpenStreetMap contributors © CARTO',
    },
    'Escuro (sem labels)': {
        'tiles': 'https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png',
        'attr': '© OpenStreetMap contributors © CARTO',
    },
    'Claro': {
        'tiles': 'CartoDB positron',
        'attr': '© OpenStreetMap contributors © CARTO',
    },
    'Voyager': {
        'tiles': 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',
        'attr': '© OpenStreetMap contributors © CARTO',
    },
    'OpenStreetMap': {
        'tiles': 'OpenStreetMap',
        'attr': '© OpenStreetMap contributors',
    },
}

LEGEND_INFRA = [
    ('Residencial', '#22c55e', 'normal'),
    ('Movel', '#3b82f6', 'mobile'),
    ('Hosting', '#f97316', 'hosting'),
    ('Cloud', '#f59e0b', 'cloud'),
    ('Datacenter/VPN', '#f87171', 'datacenter_vpn'),
    ('Proxy/VPN/Tor', '#ef4444', 'proxy'),
]


def _is_true(value):
    return str(value).strip().lower() == 'true'


def _series_bool(df, column_name):
    if column_name not in df.columns:
        return pd.Series(False, index=df.index)
    return df[column_name].fillna(False).map(_is_true)


def _marker_radius(count):
    return max(4, min(14, 4 + math.log2(max(int(count), 1)) * 2.2))


def _tile_layer(style_name):
    return FOLIUM_TILE_SOURCES.get(style_name, FOLIUM_TILE_SOURCES['Escuro'])


def _create_base_map(df_map, tile_style, zoom_start=4):
    center_lat = float(df_map['Ip_Lat'].mean())
    center_lon = float(df_map['Ip_Lon'].mean())
    tile = _tile_layer(tile_style)

    fmap = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=zoom_start,
        tiles=None,
        control_scale=True,
    )
    folium.TileLayer(
        tiles=tile['tiles'],
        attr=tile['attr'],
        name=tile_style,
        overlay=False,
        control=False,
    ).add_to(fmap)
    Fullscreen(position='topleft').add_to(fmap)
    MiniMap(tile_layer='CartoDB positron', position='bottomright', width=120, height=120).add_to(fmap)
    MeasureControl(position='topleft', primary_length_unit='kilometers', secondary_length_unit='meters').add_to(fmap)
    return fmap


def _render_legend(df_map):
    counts = df_map['_infra_category'].value_counts().to_dict() if '_infra_category' in df_map.columns else {}
    items = []
    for label, color, category in LEGEND_INFRA:
        count = counts.get(category, 0)
        if count <= 0:
            continue
        items.append(
            f"<span style='display:inline-flex;align-items:center;margin-right:14px;'>"
            f"<span style='width:12px;height:12px;border-radius:50%;background:{color};display:inline-block;margin-right:6px;'></span>"
            f"<span style='font-size:12px;'>{label} ({count})</span>"
            f"</span>"
        )

    if items:
        st.markdown(''.join(items), unsafe_allow_html=True)


def _prepare_popup_row(row, ip_col):
    popup_row = row.copy()
    if 'Ip' not in popup_row or not popup_row.get('Ip'):
        popup_row['Ip'] = popup_row.get(ip_col, '')
    for column_name in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']:
        if column_name in popup_row:
            popup_row[column_name] = _is_true(popup_row[column_name])
    return popup_row


def _prepare_point_dataframe(df_map, ip_col, limit):
    point_df = df_map.copy()
    point_df['_marker_count'] = point_df[ip_col].map(point_df[ip_col].value_counts()).fillna(1).astype(int)
    dedupe_cols = [column for column in [ip_col, 'Ip_Lat', 'Ip_Lon', 'Ip_Cidade', 'Ip_Dono'] if column in point_df.columns]
    point_df = point_df.sort_values('_marker_count', ascending=False).drop_duplicates(subset=dedupe_cols)
    if len(point_df) > limit:
        point_df = point_df.head(limit)
    return point_df.sort_values('_marker_count')


def _marker_div_icon(color, count):
    """Create a DivIcon with the IP count displayed inside a colored circle."""
    size = max(24, min(40, int(20 + math.log2(max(count, 1)) * 5)))
    font = max(10, min(14, int(9 + math.log2(max(count, 1)) * 1.5)))
    label = str(count) if count < 1000 else f"{count / 1000:.0f}k"
    html = (
        f"<div style='width:{size}px;height:{size}px;border-radius:50%;background:{color};"
        f"border:2px solid rgba(255,255,255,0.85);display:flex;align-items:center;justify-content:center;"
        f"color:white;font-weight:700;font-size:{font}px;box-shadow:0 4px 12px rgba(0,0,0,0.3);"
        f"line-height:1;'>{label}</div>"
    )
    return folium.DivIcon(html=html, icon_size=(size, size), icon_anchor=(size // 2, size // 2))


def _add_marker_points(fmap, point_df, ip_col):
    ip_counts = point_df.set_index(ip_col)['_marker_count'].to_dict() if ip_col in point_df.columns else {}
    for _, row in point_df.iterrows():
        popup_row = _prepare_popup_row(row.to_dict(), ip_col)
        infra = classify_infrastructure(popup_row)
        popup_html = build_rich_popup(popup_row, ip_counts)
        count = int(row['_marker_count'])
        folium.Marker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            tooltip=f"{popup_row.get('Ip', '')} · {popup_row.get('Ip_Cidade', 'N/A')} ({count}x)",
            popup=folium.Popup(popup_html, max_width=360),
            icon=_marker_div_icon(infra['circle_color'], count),
        ).add_to(fmap)


def _render_markers_map(df_map, ip_col, tile_style):
    fmap = _create_base_map(df_map, tile_style)
    point_df = _prepare_point_dataframe(df_map, ip_col, limit=1200)
    _add_marker_points(fmap, point_df, ip_col)
    return fmap


def _render_clusters_map(df_map, ip_col, tile_style):
    fmap = _create_base_map(df_map, tile_style)
    cluster_layer = MarkerCluster(name='Clusters').add_to(fmap)

    cluster_df = df_map.copy()
    cluster_df['_lat_key'] = cluster_df['Ip_Lat'].round(2)
    cluster_df['_lon_key'] = cluster_df['Ip_Lon'].round(2)
    ip_counts = df_map[ip_col].value_counts().to_dict()

    groups = cluster_df.groupby(['_lat_key', '_lon_key'], sort=False)
    total_groups = 0
    for _, group in groups:
        total_groups += 1
        if total_groups > 600:
            break

        lat = float(group['Ip_Lat'].mean())
        lon = float(group['Ip_Lon'].mean())
        rows = []
        for item in group.head(20).to_dict('records'):
            prepared = _prepare_popup_row(item, ip_col)
            rows.append(prepared)

        first_row = rows[0]
        infra = classify_infrastructure(first_row)
        popup_html = build_cluster_popup(rows, ip_counts)
        badge = (
            f"<div style='width:34px;height:34px;border-radius:50%;background:{infra['circle_color']};"
            f"border:2px solid rgba(255,255,255,0.85);display:flex;align-items:center;justify-content:center;"
            f"color:white;font-weight:700;font-size:12px;box-shadow:0 6px 16px rgba(0,0,0,0.25);'>"
            f"{len(group)}</div>"
        )
        folium.Marker(
            location=[lat, lon],
            tooltip=f"{first_row.get('Ip_Cidade', 'N/A')} · {len(group)} registro(s)",
            popup=folium.Popup(popup_html, max_width=420),
            icon=folium.DivIcon(html=badge),
        ).add_to(cluster_layer)

    return fmap


def _render_heatmap_map(df_map, ip_col, tile_style):
    fmap = _create_base_map(df_map, tile_style)
    point_df = _prepare_point_dataframe(df_map, ip_col, limit=1800)
    point_df['_weight'] = point_df['_marker_count'].clip(upper=25)
    heat_data = point_df[['Ip_Lat', 'Ip_Lon', '_weight']].values.tolist()
    HeatMap(
        heat_data,
        radius=24,
        blur=18,
        min_opacity=0.25,
        max_zoom=10,
        gradient={
            0.20: '#22c55e',
            0.45: '#38bdf8',
            0.65: '#f59e0b',
            0.85: '#f97316',
            1.00: '#ef4444',
        },
    ).add_to(fmap)

    for _, row in point_df.head(150).iterrows():
        popup_row = _prepare_popup_row(row.to_dict(), ip_col)
        infra = classify_infrastructure(popup_row)
        folium.CircleMarker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            radius=max(3, _marker_radius(row['_marker_count']) - 2),
            color=infra['circle_color'],
            fill=True,
            fill_color=infra['circle_color'],
            fill_opacity=0.35,
            weight=1,
            tooltip=f"{popup_row.get('Ip', '')} · {popup_row.get('Ip_Cidade', 'N/A')}",
        ).add_to(fmap)

    return fmap


def _prepare_route_dataframe(df_map, max_points=450):
    route_df = df_map.copy()
    route_df['_dt'] = pd.to_datetime(route_df['Data'], format='mixed', errors='coerce') if 'Data' in route_df.columns else pd.NaT
    route_df = route_df.dropna(subset=['_dt']).sort_values('_dt')
    if len(route_df) > max_points:
        step = max(1, len(route_df) // max_points)
        route_df = route_df.iloc[::step].copy()
    return route_df


def _render_route_map(df_map, ip_col, tile_style):
    route_df = _prepare_route_dataframe(df_map)
    if route_df.empty or len(route_df) < 2:
        return None

    fmap = _create_base_map(route_df, tile_style)
    coordinates = route_df[['Ip_Lat', 'Ip_Lon']].values.tolist()
    folium.PolyLine(coordinates, color='#cbd5e1', weight=4, opacity=0.7).add_to(fmap)

    ip_counts = df_map[ip_col].value_counts().to_dict()
    for _, row in route_df.iterrows():
        popup_row = _prepare_popup_row(row.to_dict(), ip_col)
        infra = classify_infrastructure(popup_row)
        folium.CircleMarker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            radius=5,
            color=infra['circle_color'],
            fill=True,
            fill_color=infra['circle_color'],
            fill_opacity=0.85,
            weight=2,
            tooltip=str(row.get('Data', ''))[:16],
            popup=folium.Popup(build_rich_popup(popup_row, ip_counts), max_width=360),
        ).add_to(fmap)

    start_row = _prepare_popup_row(route_df.iloc[0].to_dict(), ip_col)
    end_row = _prepare_popup_row(route_df.iloc[-1].to_dict(), ip_col)
    folium.Marker(
        location=[route_df.iloc[0]['Ip_Lat'], route_df.iloc[0]['Ip_Lon']],
        tooltip='Inicio da sequencia',
        popup=folium.Popup(build_rich_popup(start_row, ip_counts), max_width=360),
        icon=folium.DivIcon(html="<div style='font-size:18px;'>🟢</div>"),
    ).add_to(fmap)
    folium.Marker(
        location=[route_df.iloc[-1]['Ip_Lat'], route_df.iloc[-1]['Ip_Lon']],
        tooltip='Ultimo ponto observado',
        popup=folium.Popup(build_rich_popup(end_row, ip_counts), max_width=360),
        icon=folium.DivIcon(html="<div style='font-size:18px;'>🔴</div>"),
    ).add_to(fmap)
    return fmap


def _render_investigative_map(df_map, ip_col, tile_style):
    fmap = _create_base_map(df_map, tile_style)
    point_df = _prepare_point_dataframe(df_map, ip_col, limit=900)
    ip_counts = df_map[ip_col].value_counts().to_dict()

    if 'Data' in df_map.columns:
        route_df = _prepare_route_dataframe(df_map, max_points=220)
        if not route_df.empty and len(route_df) >= 2:
            folium.PolyLine(
                route_df[['Ip_Lat', 'Ip_Lon']].values.tolist(),
                color='#a5b4fc',
                weight=3,
                opacity=0.45,
                dash_array='8 12',
            ).add_to(fmap)

    for _, row in point_df.iterrows():
        popup_row = _prepare_popup_row(row.to_dict(), ip_col)
        infra = classify_infrastructure(popup_row)
        count = int(row['_marker_count'])
        folium.Marker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            tooltip=f"{popup_row.get('Ip', '')} · {popup_row.get('Ip_Cidade', 'N/A')} ({count}x)",
            popup=folium.Popup(build_rich_popup(popup_row, ip_counts), max_width=360),
            icon=_marker_div_icon(infra['circle_color'], count),
        ).add_to(fmap)

        if popup_row.get('_infra_category') in ('proxy', 'datacenter_vpn'):
            folium.Circle(
                location=[row['Ip_Lat'], row['Ip_Lon']],
                radius=max(1500, row['_marker_count'] * 180),
                color='#ef4444',
                weight=2,
                fill=False,
                opacity=0.45,
            ).add_to(fmap)

    bases = detect_base_locations(df_map)
    if bases.get('home'):
        home = bases['home']
        folium.Marker(
            location=[home['lat'], home['lon']],
            tooltip='Provavel residencia',
            popup=f"Residencia provavel: {home['city']}, {home['region']} ({home['count']} acessos noturnos)",
            icon=folium.DivIcon(html="<div style='font-size:22px;'>🏠</div>"),
        ).add_to(fmap)
    if bases.get('work'):
        work = bases['work']
        folium.Marker(
            location=[work['lat'], work['lon']],
            tooltip='Provavel trabalho',
            popup=f"Trabalho provavel: {work['city']}, {work['region']} ({work['count']} acessos diurnos)",
            icon=folium.DivIcon(html="<div style='font-size:22px;'>🏢</div>"),
        ).add_to(fmap)

    return fmap


def _render_travel_preview_map(df_map, tile_style):
    route_df = _prepare_route_dataframe(df_map, max_points=180)
    if route_df.empty or len(route_df) < 2:
        return None

    preview_df = route_df.drop_duplicates(subset=['Ip_Cidade']) if 'Ip_Cidade' in route_df.columns else route_df
    if len(preview_df) < 2:
        return None

    fmap = _create_base_map(preview_df, tile_style, zoom_start=5)
    folium.PolyLine(preview_df[['Ip_Lat', 'Ip_Lon']].values.tolist(), color='#38bdf8', weight=4, opacity=0.75).add_to(fmap)

    for order, (_, row) in enumerate(preview_df.iterrows(), start=1):
        folium.Marker(
            location=[row['Ip_Lat'], row['Ip_Lon']],
            tooltip=f"{order}. {row.get('Ip_Cidade', 'N/A')}",
            popup=f"{row.get('Ip_Cidade', 'N/A')} · {str(row.get('Data', ''))[:16]}",
            icon=folium.DivIcon(
                html=(
                    "<div style='width:28px;height:28px;border-radius:50%;background:#0f172a;"
                    "border:2px solid #38bdf8;color:#e2e8f0;display:flex;align-items:center;"
                    f"justify-content:center;font-size:12px;font-weight:700;'>{order}</div>"
                )
            ),
        ).add_to(fmap)
    return fmap


def page_mapa():
    st.header('🗺️ Mapa de Geolocalizacao', divider='blue')
    st.caption('Mapa 2D investigativo com Leaflet/Folium — marcadores, clusters, heatmap, rota temporal e visao operacional.')

    df = st.session_state.df_resultado
    if df is None or df.empty:
        st.info('📭 Nenhum dado. Processe na aba **Entrada**.')
        return

    if 'Ip_Lat' not in df.columns or 'Ip_Lon' not in df.columns:
        st.warning('⚠️ Sem coordenadas. Reprocesse os IPs.')
        return

    df_m = df.copy()
    df_m['Ip_Lat'] = pd.to_numeric(df_m['Ip_Lat'], errors='coerce')
    df_m['Ip_Lon'] = pd.to_numeric(df_m['Ip_Lon'], errors='coerce')
    df_m = df_m.dropna(subset=['Ip_Lat', 'Ip_Lon'])
    df_m = df_m[(df_m['Ip_Lat'] != 0) | (df_m['Ip_Lon'] != 0)]

    if df_m.empty:
        cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ip_cache.json')
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as file_handler:
                    ip_cache = json.load(file_handler)
                df_m = df.copy()
                df_m['Ip_Lat'] = df_m['Ip'].map(lambda ip: ip_cache.get(ip, {}).get('Ip_Lat'))
                df_m['Ip_Lon'] = df_m['Ip'].map(lambda ip: ip_cache.get(ip, {}).get('Ip_Lon'))
                df_m['Ip_Lat'] = pd.to_numeric(df_m['Ip_Lat'], errors='coerce')
                df_m['Ip_Lon'] = pd.to_numeric(df_m['Ip_Lon'], errors='coerce')
                df_m = df_m.dropna(subset=['Ip_Lat', 'Ip_Lon'])
                df_m = df_m[(df_m['Ip_Lat'] != 0) | (df_m['Ip_Lon'] != 0)]
                if not df_m.empty:
                    st.session_state.df_resultado['Ip_Lat'] = st.session_state.df_resultado['Ip'].map(
                        lambda ip: ip_cache.get(ip, {}).get('Ip_Lat')
                    )
                    st.session_state.df_resultado['Ip_Lon'] = st.session_state.df_resultado['Ip'].map(
                        lambda ip: ip_cache.get(ip, {}).get('Ip_Lon')
                    )
                    st.toast(f'📍 Coordenadas recuperadas do cache para {len(df_m)} registros')
            except Exception as exc:
                logger.warning('Erro ao recuperar coordenadas do cache: %s', exc)

    if df_m.empty:
        st.warning('⚠️ Nenhum IP com coordenadas validas.')
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    ip_counts = df[ip_col].value_counts().to_dict()

    filter_col1, filter_col2, filter_col3, filter_col4, filter_col5 = st.columns([1.45, 1.4, 1.05, 1.25, 1])
    with filter_col1:
        providers = ['Todos'] + sorted(df_m['Ip_Dono'].dropna().unique().tolist()) if 'Ip_Dono' in df_m.columns else ['Todos']
        selected_provider = st.selectbox('Provedor', providers, key='map_provider')
    with filter_col2:
        cities = ['Todas'] + sorted(df_m['Ip_Cidade'].dropna().unique().tolist()) if 'Ip_Cidade' in df_m.columns else ['Todas']
        selected_city = st.selectbox('Cidade', cities, key='map_city')
    with filter_col3:
        selected_types = st.multiselect(
            'Tipo',
            ['Residencial', 'Movel', 'Proxy/VPN', 'Hosting'],
            default=['Residencial', 'Movel', 'Proxy/VPN', 'Hosting'],
            key='map_types',
        )
    with filter_col4:
        map_view = st.selectbox(
            'Visualizacao',
            ['Marcadores', 'Clusters', 'Heatmap', 'Rota Temporal', 'Visao Investigativa'],
            key='map_view',
        )
    with filter_col5:
        tile_style = st.selectbox('Estilo do Mapa', list(FOLIUM_TILE_SOURCES.keys()), key='map_tile_style')

    if 'Data' in df_m.columns:
        df_m['_dt_filter'] = pd.to_datetime(df_m['Data'], format='mixed', errors='coerce')
        valid_dates = df_m['_dt_filter'].dropna()
        if len(valid_dates) > 1:
            min_date = valid_dates.min().date()
            max_date = valid_dates.max().date()
            if min_date < max_date:
                selected_dates = st.slider(
                    'Periodo no mapa',
                    min_value=min_date,
                    max_value=max_date,
                    value=(min_date, max_date),
                    key='map_date_slider',
                    format='DD/MM/YY',
                )
                start_date, end_date = selected_dates
                start_ts = pd.Timestamp(start_date)
                end_ts = pd.Timestamp(end_date) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
                df_m = df_m[(df_m['_dt_filter'] >= start_ts) & (df_m['_dt_filter'] <= end_ts)]
        df_m = df_m.drop(columns=['_dt_filter'], errors='ignore')

    if selected_provider != 'Todos' and 'Ip_Dono' in df_m.columns:
        df_m = df_m[df_m['Ip_Dono'] == selected_provider]
    if selected_city != 'Todas' and 'Ip_Cidade' in df_m.columns:
        df_m = df_m[df_m['Ip_Cidade'] == selected_city]

    if selected_types and all(column in df_m.columns for column in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        proxy_series = _series_bool(df_m, 'Ip_Proxy')
        hosting_series = _series_bool(df_m, 'Ip_Hospedagem')
        mobile_series = _series_bool(df_m, 'Ip_Movel')
        filters = []
        if 'Residencial' in selected_types:
            filters.append(~proxy_series & ~hosting_series & ~mobile_series)
        if 'Movel' in selected_types:
            filters.append(mobile_series)
        if 'Proxy/VPN' in selected_types:
            filters.append(proxy_series)
        if 'Hosting' in selected_types:
            filters.append(hosting_series)
        if filters:
            combined = filters[0]
            for current_filter in filters[1:]:
                combined = combined | current_filter
            df_m = df_m[combined]

    if df_m.empty:
        st.warning('Nenhum IP com os filtros selecionados.')
        return

    proxy_series = _series_bool(df_m, 'Ip_Proxy')
    classified_df = classify_dataframe(df_m)

    metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns(5)
    with metric_col1:
        st.metric('IPs no Mapa', len(classified_df))
    with metric_col2:
        st.metric('IPs Unicos', classified_df[ip_col].nunique() if ip_col in classified_df.columns else 0)
    with metric_col3:
        st.metric('Cidades', classified_df['Ip_Cidade'].dropna().nunique() if 'Ip_Cidade' in classified_df.columns else 0)
    with metric_col4:
        st.metric('Paises', classified_df['Ip_Pais'].dropna().nunique() if 'Ip_Pais' in classified_df.columns else 0)
    with metric_col5:
        st.metric('🛡️ Proxy/VPN', int(proxy_series.sum()))

    n_datacenter = int(classified_df['_infra_category'].isin(['proxy', 'datacenter_vpn']).sum())
    n_cloud = int((classified_df['_infra_category'] == 'cloud').sum())

    if n_datacenter > 0:
        alert_rows = classified_df[classified_df['_infra_category'].isin(['proxy', 'datacenter_vpn'])]
        alert_ips = ', '.join(alert_rows[ip_col].astype(str).unique()[:5])
        alert_providers = ', '.join(alert_rows['Ip_Dono'].dropna().astype(str).unique()[:5]) if 'Ip_Dono' in alert_rows.columns else 'N/A'
        st.error(
            f'🛡️ **{n_datacenter} registro(s) com Proxy/VPN/Datacenter detectados**\n\n'
            f'IPs: {alert_ips or "N/A"}  \nProvedores: {alert_providers or "N/A"}  \n'
            '*A localizacao exibida pode representar o servidor, nao o usuario final.*'
        )

    if n_cloud > 0:
        cloud_rows = classified_df[classified_df['_infra_category'] == 'cloud']
        cloud_ips = ', '.join(cloud_rows[ip_col].astype(str).unique()[:5])
        cloud_providers = ', '.join(cloud_rows['Ip_Dono'].dropna().astype(str).unique()[:5]) if 'Ip_Dono' in cloud_rows.columns else 'N/A'
        st.warning(
            f'☁️ **{n_cloud} registro(s) em Cloud Publica**\n\n'
            f'IPs: {cloud_ips or "N/A"}  \nProvedores: {cloud_providers or "N/A"}  \n'
            '*O IP pode pertencer a aplicacao, bot ou infraestrutura compartilhada.*'
        )

    main_map = None
    if map_view == 'Clusters':
        main_map = _render_clusters_map(classified_df, ip_col, tile_style)
    elif map_view == 'Heatmap':
        main_map = _render_heatmap_map(classified_df, ip_col, tile_style)
    elif map_view == 'Rota Temporal':
        main_map = _render_route_map(classified_df, ip_col, tile_style)
        if main_map is None:
            st.warning('Sem dados temporais suficientes para montar a rota cronologica.')
    elif map_view == 'Visao Investigativa':
        main_map = _render_investigative_map(classified_df, ip_col, tile_style)
    else:
        main_map = _render_markers_map(classified_df, ip_col, tile_style)

    if main_map is not None:
        st_folium(main_map, use_container_width=True, height=650, returned_objects=[], key='main_map')
        _render_legend(classified_df)

    st.divider()
    tool_tabs = st.tabs(['🌐 Exportar', '📍 Geofencing', '⚡ Anomalias', '🧠 Perfil', '📅 Comparacao', '📊 Estatisticas', '📐 Area', '✈️ Viagens'])

    with tool_tabs[0]:
        export_col1, export_col2, export_col3 = st.columns(3)
        with export_col1:
            st.subheader('🌐 KML (Google Earth)')
            if st.button('Gerar KML', key='map_kml_btn'):
                try:
                    kml_data = export_kml(df, ip_col=ip_col)
                    st.download_button('📥 Baixar KML', kml_data, 'ip_locations.kml', 'application/vnd.google-earth.kml+xml', key='map_kml_dl')
                except Exception as exc:
                    st.error(f'Erro ao gerar KML: {exc}')
        with export_col2:
            st.subheader('🎬 KML Animado')
            if st.button('Gerar KML Temporal', key='map_kml_anim_btn'):
                try:
                    kml_anim = export_kml_animated(df, ip_col=ip_col)
                    st.download_button('📥 Baixar KML Animado', kml_anim, 'rota_temporal.kml', 'application/vnd.google-earth.kml+xml', key='map_kml_anim_dl')
                    st.caption('Abra no Google Earth Pro para ver a animacao temporal.')
                except Exception as exc:
                    st.error(f'Erro ao gerar KML temporal: {exc}')
        with export_col3:
            st.subheader('📦 GeoJSON')
            if st.button('Exportar GeoJSON', key='map_geojson_btn'):
                features = []
                for _, row in classified_df.iterrows():
                    features.append({
                        'type': 'Feature',
                        'geometry': {'type': 'Point', 'coordinates': [row['Ip_Lon'], row['Ip_Lat']]},
                        'properties': {
                            'ip': row.get(ip_col, ''),
                            'provedor': row.get('Ip_Dono', ''),
                            'cidade': row.get('Ip_Cidade', ''),
                            'pais': row.get('Ip_Pais', ''),
                            'data': str(row.get('Data', '')),
                        },
                    })
                geojson = json.dumps({'type': 'FeatureCollection', 'features': features}, indent=2, ensure_ascii=False)
                st.download_button('📥 Baixar GeoJSON', geojson, 'ip_locations.geojson', 'application/geo+json', key='map_geojson_dl')

    with tool_tabs[1]:
        st.subheader('📍 Geofencing')
        geo_col1, geo_col2, geo_col3 = st.columns(3)
        with geo_col1:
            geo_lat = st.number_input('Latitude centro', value=-15.7801, format='%.4f', key='map_geo_lat')
        with geo_col2:
            geo_lon = st.number_input('Longitude centro', value=-47.9292, format='%.4f', key='map_geo_lon')
        with geo_col3:
            geo_radius = st.number_input('Raio (km)', value=500, min_value=1, key='map_geo_radius')

        if st.button('Verificar Geofence', key='map_geo_btn'):
            inside, outside = check_geofence(df, geo_lat, geo_lon, geo_radius)
            if len(outside) > 0:
                st.warning(f'⚠️ **{len(outside)}** IPs fora da cerca ({geo_radius} km).')
                out_columns = [ip_col, 'Ip_Cidade', 'Ip_Regiao', 'Ip_Pais', 'Ip_Dono', 'Data']
                available_columns = [column for column in out_columns if column in outside.columns]
                st.dataframe(
                    outside[available_columns + ['_distance_km']].rename(columns={'_distance_km': 'Distancia (km)'}),
                    hide_index=True,
                )
            else:
                st.success(f'✅ Todos os IPs ficaram dentro da cerca de {geo_radius} km.')

    with tool_tabs[2]:
        st.subheader('⚡ Deteccao de Saltos Impossiveis')
        max_speed = st.slider('Velocidade maxima (km/h)', 100, 2000, 900, key='map_anom_speed')
        jumps = detect_impossible_jumps(df, max_speed_kmh=max_speed)
        if not jumps.empty:
            st.error(f'🚨 **{len(jumps)}** saltos impossiveis detectados (>{max_speed} km/h).')
            st.dataframe(jumps, hide_index=True, use_container_width=True)
        else:
            st.success('✅ Nenhum salto impossivel detectado.')

        st.divider()
        st.subheader('🏠 Deteccao de Locais Base')
        bases = detect_base_locations(df)
        base_col1, base_col2 = st.columns(2)
        with base_col1:
            if bases.get('home'):
                home = bases['home']
                st.metric('🏠 Provavel Residencia', f"{home['city']}, {home['region']}")
                st.caption(f"Provedor: {home['provider']} | {home['count']} acessos noturnos")
            else:
                st.info('Sem dados suficientes para detectar residencia.')
        with base_col2:
            if bases.get('work'):
                work = bases['work']
                st.metric('🏢 Provavel Trabalho', f"{work['city']}, {work['region']}")
                st.caption(f"Provedor: {work['provider']} | {work['count']} acessos diurnos")
            else:
                st.info('Sem dados suficientes para detectar trabalho.')

    with tool_tabs[3]:
        st.subheader('🧠 Perfil Comportamental')
        target_name = st.session_state.alvo or 'desconhecido'
        profile = generate_behavioral_profile(df, alvo=target_name)

        profile_col1, profile_col2, profile_col3, profile_col4 = st.columns(4)
        with profile_col1:
            st.metric('📅 Dias Monitorados', profile['dias_monitorados'])
        with profile_col2:
            st.metric('🔢 Registros', profile['total_registros'])
        with profile_col3:
            st.metric('🌐 IPs Unicos', profile['ips_unicos'])
        with profile_col4:
            st.metric('⏰ Padrao', profile['padrao_atividade'] or 'N/A')

        if profile['resumo']:
            st.code(profile['resumo'], language=None)

        profile_list_col1, profile_list_col2 = st.columns(2)
        with profile_list_col1:
            if profile['provedores']:
                st.markdown('**Provedores utilizados:**')
                for provider in profile['provedores']:
                    st.markdown(f'- {provider}')
        with profile_list_col2:
            if profile['cidades_visitadas']:
                st.markdown('**Cidades visitadas:**')
                for city in profile['cidades_visitadas']:
                    st.markdown(f'- {city}')

        if 'Data' in df.columns:
            st.divider()
            st.subheader('📈 Timeline de Atividade')
            profile_df = df.copy()
            profile_df['_dt'] = pd.to_datetime(profile_df['Data'], errors='coerce')
            profile_df = profile_df.dropna(subset=['_dt'])
            if not profile_df.empty:
                profile_df['_date'] = profile_df['_dt'].dt.date
                daily = profile_df.groupby('_date').size().reset_index(name='Acessos')
                daily.columns = ['Data', 'Acessos']
                fig_timeline = px.area(daily, x='Data', y='Acessos', color_discrete_sequence=['#818cf8'])
                fig_timeline.update_layout(
                    height=250,
                    margin=dict(l=0, r=0, t=10, b=10),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                )
                st.plotly_chart(fig_timeline, use_container_width=True, key='map_profile_timeline')

                profile_df['_hour'] = profile_df['_dt'].dt.hour
                profile_df['_dow'] = profile_df['_dt'].dt.day_name()
                heat = profile_df.groupby(['_dow', '_hour']).size().reset_index(name='count')
                day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                heat_pivot = heat.pivot_table(index='_dow', columns='_hour', values='count', fill_value=0)
                heat_pivot = heat_pivot.reindex(day_order)
                fig_heat = px.imshow(
                    heat_pivot,
                    aspect='auto',
                    color_continuous_scale='YlOrRd',
                    labels=dict(x='Hora', y='Dia', color='Acessos'),
                )
                fig_heat.update_layout(
                    height=250,
                    margin=dict(l=0, r=0, t=10, b=10),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                )
                st.plotly_chart(fig_heat, use_container_width=True, key='map_profile_heatmap')

    with tool_tabs[4]:
        st.subheader('📅 Comparacao Temporal')
        if 'Data' in df.columns:
            date_series = pd.to_datetime(df['Data'], errors='coerce').dropna()
            if not date_series.empty:
                min_date = date_series.min().date()
                max_date = date_series.max().date()
                mid_date = min_date + (max_date - min_date) / 2
                split_date = st.date_input('Data de divisao', value=mid_date, min_value=min_date, max_value=max_date, key='map_cmp_split')
                comparison = compare_periods(df, split_date=str(split_date))
                if comparison:
                    comp_col1, comp_col2 = st.columns(2)
                    period_a = comparison['periodo_a']
                    period_b = comparison['periodo_b']
                    with comp_col1:
                        st.markdown('### Periodo A')
                        st.metric('Registros', period_a['registros'])
                        st.metric('IPs Unicos', period_a['ips_unicos'])
                    with comp_col2:
                        st.markdown('### Periodo B')
                        st.metric('Registros', period_b['registros'])
                        st.metric('IPs Unicos', period_b['ips_unicos'])

                    if comparison.get('mudancas'):
                        st.divider()
                        for change in comparison['mudancas']:
                            st.warning(f'📌 {change}')
        else:
            st.info('Sem dados de data para comparacao.')

    with tool_tabs[5]:
        st.subheader('📊 Estatisticas Geograficas')
        geo_col1, geo_col2 = st.columns(2)
        with geo_col1:
            if 'Ip_Pais' in classified_df.columns:
                country_counts = classified_df['Ip_Pais'].value_counts().head(15).reset_index()
                country_counts.columns = ['Pais', 'Qtd']
                fig = px.bar(country_counts, x='Qtd', y='Pais', orientation='h', color='Qtd', color_continuous_scale='Viridis')
                fig.update_layout(
                    height=400,
                    showlegend=False,
                    yaxis={'categoryorder': 'total ascending'},
                    coloraxis_showscale=False,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                )
                st.plotly_chart(fig, key='map_geo_country')
        with geo_col2:
            if 'Ip_Cidade' in classified_df.columns:
                city_counts = classified_df['Ip_Cidade'].value_counts().head(15).reset_index()
                city_counts.columns = ['Cidade', 'Qtd']
                fig = px.bar(city_counts, x='Qtd', y='Cidade', orientation='h', color='Qtd', color_continuous_scale='Magma')
                fig.update_layout(
                    height=400,
                    showlegend=False,
                    yaxis={'categoryorder': 'total ascending'},
                    coloraxis_showscale=False,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                )
                st.plotly_chart(fig, key='map_geo_city')

    with tool_tabs[6]:
        st.subheader('📐 Area de Movimentacao')
        try:
            area_data = calculate_movement_area(classified_df)
            area_col1, area_col2, area_col3 = st.columns(3)
            with area_col1:
                st.metric('📐 Area Total', f"{area_data['area_km2']:,.1f} km²")
            with area_col2:
                st.metric('📏 Raio Maximo', f"{area_data['max_distance_km']:,.1f} km")
            with area_col3:
                st.metric('📍 Localizacoes', area_data['num_points'])

            if area_data['area_km2'] > 0:
                hull_map = folium.Map(location=area_data['center'], zoom_start=5, tiles='CartoDB dark_matter')
                folium.Polygon(
                    locations=area_data['hull_coords'],
                    color='#818cf8',
                    weight=2,
                    fill=True,
                    fill_color='#818cf8',
                    fill_opacity=0.15,
                ).add_to(hull_map)
                for _, row in classified_df.drop_duplicates(subset=[ip_col]).iterrows():
                    infra = classify_infrastructure(row)
                    folium.CircleMarker(
                        location=[row['Ip_Lat'], row['Ip_Lon']],
                        radius=4,
                        color=infra['circle_color'],
                        fill=True,
                        fill_color=infra['circle_color'],
                        fill_opacity=0.85,
                        tooltip=f"{row.get(ip_col, '')} - {row.get('Ip_Cidade', '')}",
                    ).add_to(hull_map)
                st_folium(hull_map, use_container_width=True, height=400, returned_objects=[], key='map_hull_map')
        except Exception as exc:
            st.warning(f'Nao foi possivel calcular a area: {exc}')

    with tool_tabs[7]:
        st.subheader('✈️ Padrao de Viagem')
        segments = detect_travel_pattern(df)
        if segments:
            travel_df = pd.DataFrame(segments)
            st.metric('Deslocamentos detectados', len(travel_df))
            st.dataframe(travel_df, use_container_width=True, hide_index=True)

            route = [segments[0]['De']]
            for segment in segments:
                if segment['Para'] != route[-1]:
                    route.append(segment['Para'])
            st.markdown(f"**Rota:** {' → '.join(route)}")
            total_km = sum(segment['Distancia_km'] for segment in segments)
            st.caption(f'Distancia total percorrida: **{total_km:,.0f} km**')

            travel_map = _render_travel_preview_map(classified_df, tile_style)
            if travel_map is not None:
                st_folium(travel_map, use_container_width=True, height=350, returned_objects=[], key='map_travel_preview')
        else:
            st.info('Nenhum deslocamento entre cidades detectado.')

    st.divider()
    st.subheader('▶️ Replay Temporal no Mapa')
    render_map_replay(df)