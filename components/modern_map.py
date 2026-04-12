"""
Log Enrichment - Modern Map Visualizations (pydeck / deck.gl)
GPU-accelerated 3D maps with ScatterplotLayer, HexagonLayer, HeatmapLayer,
ArcLayer, PathLayer, TripsLayer and GlobeView.
"""

import logging
import math
import pandas as pd
import pydeck as pdk

from analysis import classify_infrastructure

logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================

CARTO_DARK = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json"
CARTO_DARK_NOLABELS = "https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json"
CARTO_POSITRON = "https://basemaps.cartocdn.com/gl/positron-gl-style/style.json"
CARTO_VOYAGER = "https://basemaps.cartocdn.com/gl/voyager-gl-style/style.json"

MAP_STYLES = {
    'Escuro': CARTO_DARK,
    'Escuro (sem labels)': CARTO_DARK_NOLABELS,
    'Claro': CARTO_POSITRON,
    'Voyager': CARTO_VOYAGER,
    'OpenStreetMap': CARTO_VOYAGER,
}

# Infrastructure category → RGBA color
INFRA_COLORS = {
    'proxy':         [239, 68, 68],     # red
    'datacenter_vpn':[248, 113, 113],   # lighter red
    'cloud':         [245, 158, 11],    # amber
    'hosting':       [249, 115, 22],    # orange
    'mobile':        [59, 130, 246],    # blue
    'normal':        [34, 197, 94],     # green
}

INFRA_COLORS_ALPHA = {k: v + [200] for k, v in INFRA_COLORS.items()}


# ============================================================
# DATA PREPARATION
# ============================================================

def prepare_map_dataframe(df, color_mode='infra'):
    """
    Add pydeck-compatible color, radius and elevation columns to DataFrame.
    color_mode: 'infra' (default), 'provider', 'temporal', 'risk'
    Returns a copy with _color_r/g/b/a, _radius, _elevation, _category columns.
    """
    df_out = df.copy()

    ip_col = 'Sender IP' if 'Sender IP' in df_out.columns else 'Ip'
    ip_counts = df_out[ip_col].value_counts().to_dict() if ip_col in df_out.columns else {}

    # Always compute category (needed for alert layer / legend)
    categories = []
    for _, row in df_out.iterrows():
        infra = classify_infrastructure(row)
        categories.append(infra['category'])
    df_out['_category'] = categories

    # Access count per IP
    df_out['_count'] = df_out[ip_col].map(ip_counts).fillna(1).astype(int) if ip_col in df_out.columns else 1

    # --- Color assignment based on mode ---
    if color_mode == 'provider':
        df_out = _assign_colors_by_provider(df_out)
    elif color_mode == 'temporal':
        df_out = _assign_colors_by_time(df_out)
    elif color_mode == 'risk':
        df_out = _assign_colors_by_risk(df_out)
    else:  # 'infra' (default)
        df_out = _assign_colors_by_infra(df_out)

    # Proportional radius: log scale so 1 access ≈ 400, 100 accesses ≈ 1600
    df_out['_radius'] = df_out['_count'].apply(lambda c: int(400 + 400 * math.log2(max(c, 1))))

    # Proportional opacity: 1 access → 120 alpha, many → 230
    max_count = df_out['_count'].max() if len(df_out) > 0 else 1
    if max_count <= 1:
        df_out['_color_a'] = 180
    else:
        df_out['_color_a'] = df_out['_count'].apply(
            lambda c: int(120 + 110 * (math.log2(max(c, 1)) / math.log2(max(max_count, 2))))
        )

    # Elevation for 3D column mode
    df_out['_elevation'] = df_out['_count'] * 500

    # Infra label (always useful for tooltips)
    label_map = {
        'proxy': '🛡️ Proxy/VPN/Tor', 'datacenter_vpn': '🏢 Datacenter/VPN',
        'cloud': '☁️ Cloud', 'hosting': '🖥️ Hosting',
        'mobile': '📱 Móvel', 'normal': '🏠 Residencial',
    }
    df_out['_infra_label'] = df_out['_category'].map(label_map).fillna('🏠 Residencial')

    # Safe string columns for tooltip
    for col in ['Ip', 'Ip_Dono', 'Ip_Cidade', 'Ip_Regiao', 'Ip_Pais', 'Ip_AS', 'Data', 'Periodo']:
        if col in df_out.columns:
            df_out[col] = df_out[col].fillna('N/A').astype(str)

    return df_out


def _assign_colors_by_infra(df):
    """Color by infrastructure type (original behavior)."""
    colors_r, colors_g, colors_b = [], [], []
    for cat in df['_category']:
        rgba = INFRA_COLORS.get(cat, [34, 197, 94])
        colors_r.append(rgba[0])
        colors_g.append(rgba[1])
        colors_b.append(rgba[2])
    df['_color_r'] = colors_r
    df['_color_g'] = colors_g
    df['_color_b'] = colors_b
    df['_color_mode_label'] = df['_category'].map({
        'proxy': 'Proxy/VPN', 'datacenter_vpn': 'Datacenter', 'cloud': 'Cloud',
        'hosting': 'Hosting', 'mobile': 'Móvel', 'normal': 'Residencial',
    }).fillna('Residencial')
    return df


# Provider color palette — 10 distinguishable colors for top providers
_PROVIDER_PALETTE = [
    [129, 140, 248],   # indigo
    [34, 197, 94],     # green
    [245, 158, 11],    # amber
    [239, 68, 68],     # red
    [59, 130, 246],    # blue
    [168, 85, 247],    # purple
    [236, 72, 153],    # pink
    [20, 184, 166],    # teal
    [249, 115, 22],    # orange
    [234, 179, 8],     # yellow
]
_OTHER_COLOR = [100, 116, 139]  # slate for "Outros"


def _assign_colors_by_provider(df):
    """Color by ISP/provider — top 10 get unique colors, rest gray."""
    col = 'Ip_Dono' if 'Ip_Dono' in df.columns else None
    if col is None:
        return _assign_colors_by_infra(df)

    top_providers = df[col].value_counts().head(10).index.tolist()
    prov_color_map = {p: _PROVIDER_PALETTE[i] for i, p in enumerate(top_providers)}

    colors_r, colors_g, colors_b, labels = [], [], [], []
    for prov in df[col]:
        rgb = prov_color_map.get(prov, _OTHER_COLOR)
        colors_r.append(rgb[0])
        colors_g.append(rgb[1])
        colors_b.append(rgb[2])
        labels.append(prov if prov in prov_color_map else 'Outros')
    df['_color_r'] = colors_r
    df['_color_g'] = colors_g
    df['_color_b'] = colors_b
    df['_color_mode_label'] = labels
    return df


def _assign_colors_by_time(df):
    """Color by temporal gradient: blue (oldest) → red (newest)."""
    if 'Data' not in df.columns:
        return _assign_colors_by_infra(df)

    dt = pd.to_datetime(df['Data'], format='mixed', errors='coerce')
    min_ts = dt.min()
    max_ts = dt.max()

    if pd.isna(min_ts) or pd.isna(max_ts) or min_ts == max_ts:
        return _assign_colors_by_infra(df)

    # Normalize to 0..1
    t_norm = (dt - min_ts) / (max_ts - min_ts)
    t_norm = t_norm.fillna(0.5).clip(0, 1)

    # Blue [59,130,246] → Red [239,68,68]
    df['_color_r'] = (59 + t_norm * (239 - 59)).astype(int)
    df['_color_g'] = (130 + t_norm * (68 - 130)).astype(int)
    df['_color_b'] = (246 + t_norm * (68 - 246)).astype(int)
    df['_color_mode_label'] = t_norm.apply(
        lambda t: 'Mais antigo' if t < 0.33 else ('Intermediário' if t < 0.66 else 'Mais recente')
    )
    return df


def _assign_colors_by_risk(df):
    """Color by risk: green (safe) → yellow → red (risky). Based on proxy/hosting/datacenter flags."""
    scores = []
    for _, row in df.iterrows():
        s = 0
        if row.get('Ip_Proxy', False):
            s += 80
        cat = row.get('_category', 'normal') if '_category' in df.columns else 'normal'
        if cat == 'datacenter_vpn':
            s += 60
        elif cat == 'cloud':
            s += 40
        elif cat == 'hosting':
            s += 30
        elif cat == 'mobile':
            s += 5
        scores.append(min(s, 100))

    df['_risk_score'] = scores
    max_s = max(scores) if scores else 1
    if max_s == 0:
        max_s = 1

    # Green [34,197,94] → Yellow [245,158,11] → Red [239,68,68]
    colors_r, colors_g, colors_b, labels = [], [], [], []
    for s in scores:
        t = s / max_s
        if t < 0.5:
            # green → yellow
            t2 = t * 2
            colors_r.append(int(34 + t2 * (245 - 34)))
            colors_g.append(int(197 + t2 * (158 - 197)))
            colors_b.append(int(94 + t2 * (11 - 94)))
        else:
            # yellow → red
            t2 = (t - 0.5) * 2
            colors_r.append(int(245 + t2 * (239 - 245)))
            colors_g.append(int(158 + t2 * (68 - 158)))
            colors_b.append(int(11 + t2 * (68 - 11)))
        labels.append('Baixo' if s < 20 else ('Médio' if s < 50 else 'Alto'))
    df['_color_r'] = colors_r
    df['_color_g'] = colors_g
    df['_color_b'] = colors_b
    df['_color_mode_label'] = labels
    return df


def get_view_state(df, pitch=45, zoom=4, bearing=0):
    """Create pydeck ViewState centered on DataFrame coordinates."""
    center_lat = df['Ip_Lat'].mean()
    center_lon = df['Ip_Lon'].mean()
    return pdk.ViewState(
        latitude=center_lat,
        longitude=center_lon,
        zoom=zoom,
        pitch=pitch,
        bearing=bearing,
    )


def get_map_style(style_name):
    """Return pydeck map_style URL for a given style name."""
    return MAP_STYLES.get(style_name, CARTO_DARK)


# ============================================================
# TOOLTIP TEMPLATES
# ============================================================

TOOLTIP_SINGLE = {
    "html": (
        "<div style='font-family:Segoe UI,sans-serif;padding:4px 0;'>"
        "<b style='font-size:14px;'>{Ip}</b> "
        "<span style='opacity:0.7;font-size:12px;'>({_count}x)</span><br/>"
        "<b>Tipo:</b> {_infra_label}<br/>"
        "<b>Provedor:</b> {Ip_Dono}<br/>"
        "<b>AS:</b> {Ip_AS}<br/>"
        "<b>Local:</b> {Ip_Cidade}, {Ip_Regiao} - {Ip_Pais}<br/>"
        "<b>Data:</b> {Data}<br/>"
        "<b>Período:</b> {Periodo}"
        "</div>"
    ),
    "style": {
        "backgroundColor": "#0f172a",
        "color": "#e2e8f0",
        "border": "1px solid #334155",
        "borderRadius": "8px",
        "padding": "10px 14px",
        "fontSize": "12px",
        "maxWidth": "360px",
    },
}

TOOLTIP_HEX = {
    "html": (
        "<div style='font-family:Segoe UI,sans-serif;'>"
        "<b>{elevationValue}</b> registros nesta área"
        "</div>"
    ),
    "style": {
        "backgroundColor": "#0f172a",
        "color": "#e2e8f0",
        "border": "1px solid #334155",
        "borderRadius": "8px",
        "padding": "8px 12px",
        "fontSize": "12px",
    },
}

TOOLTIP_ARC = {
    "html": (
        "<div style='font-family:Segoe UI,sans-serif;'>"
        "<b>{_from_city}</b> → <b>{_to_city}</b><br/>"
        "<span style='opacity:0.7;'>{_distance} km · {_count} conexões</span>"
        "</div>"
    ),
    "style": {
        "backgroundColor": "#0f172a",
        "color": "#e2e8f0",
        "border": "1px solid #334155",
        "borderRadius": "8px",
        "padding": "8px 12px",
        "fontSize": "12px",
    },
}


# ============================================================
# LAYER BUILDERS
# ============================================================

def create_scatterplot_layer(df, use_3d=False):
    """ScatterplotLayer (2D) or ColumnLayer (3D) for individual markers."""
    if use_3d:
        return pdk.Layer(
            "ColumnLayer",
            data=df,
            get_position='[Ip_Lon, Ip_Lat]',
            get_elevation='_elevation',
            elevation_scale=1,
            radius=1500,
            get_fill_color='[_color_r, _color_g, _color_b, _color_a]',
            pickable=True,
            auto_highlight=True,
            coverage=0.8,
        )
    return pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius='_radius',
        radius_min_pixels=4,
        radius_max_pixels=35,
        get_fill_color='[_color_r, _color_g, _color_b, _color_a]',
        pickable=True,
        auto_highlight=True,
    )


def create_alert_layer(df):
    """Pulsing alert rings for proxy/datacenter/cloud IPs — uses ScatterplotLayer with larger radius."""
    df_alert = df[df['_category'].isin(['proxy', 'datacenter_vpn'])].drop_duplicates(subset=['Ip'])
    if df_alert.empty:
        return None
    return pdk.Layer(
        "ScatterplotLayer",
        data=df_alert,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=3000,
        radius_min_pixels=12,
        radius_max_pixels=40,
        get_fill_color=[239, 68, 68, 60],
        get_line_color=[239, 68, 68, 180],
        stroked=True,
        line_width_min_pixels=2,
        pickable=False,
    )


def create_hexagon_layer(df, radius=5000, elevation_scale=100):
    """HexagonLayer 3D for density clustering."""
    return pdk.Layer(
        "HexagonLayer",
        data=df,
        get_position='[Ip_Lon, Ip_Lat]',
        radius=radius,
        elevation_scale=elevation_scale,
        elevation_range=[0, 3000],
        extruded=True,
        pickable=True,
        auto_highlight=True,
        color_range=[
            [34, 197, 94],      # green
            [34, 197, 94],      # green
            [245, 158, 11],     # amber
            [249, 115, 22],     # orange
            [239, 68, 68],      # red
            [185, 28, 28],      # dark red
        ],
    )


def create_heatmap_layer(df, radius=30, intensity=1, threshold=0.05):
    """HeatmapLayer for continuous density visualization."""
    return pdk.Layer(
        "HeatmapLayer",
        data=df,
        get_position='[Ip_Lon, Ip_Lat]',
        get_weight=1,
        radiusPixels=radius,
        intensity=intensity,
        threshold=threshold,
        color_range=[
            [34, 197, 94, 100],    # green
            [59, 130, 246, 160],   # blue
            [245, 158, 11, 200],   # amber
            [249, 115, 22, 220],   # orange
            [239, 68, 68, 255],    # red
        ],
        pickable=False,
    )


def create_path_layer(df):
    """
    PathLayer for temporal route between sorted points.
    Expects df sorted by Data_parsed with Ip_Lat/Ip_Lon.
    """
    coords = df[['Ip_Lon', 'Ip_Lat']].values.tolist()
    if len(coords) < 2:
        return None
    path_data = pd.DataFrame({'path': [coords]})
    return pdk.Layer(
        "PathLayer",
        data=path_data,
        get_path='path',
        get_color=[129, 140, 248, 200],  # indigo
        width_min_pixels=2,
        width_max_pixels=6,
        pickable=False,
    )


def create_arc_layer(df):
    """
    ArcLayer connecting sequential city-to-city movements.
    Returns (layer, arc_data_df) or (None, None) if insufficient data.
    """
    if 'Data' not in df.columns:
        return None, None

    df_sorted = df.copy()
    df_sorted['_dt'] = pd.to_datetime(df_sorted['Data'], format='mixed', errors='coerce')
    df_sorted = df_sorted.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_sorted) < 2:
        return None, None

    arcs = []
    prev = df_sorted.iloc[0]
    for i in range(1, len(df_sorted)):
        curr = df_sorted.iloc[i]
        from_city = str(prev.get('Ip_Cidade', ''))
        to_city = str(curr.get('Ip_Cidade', ''))
        if from_city == to_city:
            prev = curr
            continue
        from helpers.geo import haversine_km
        dist = haversine_km(prev['Ip_Lat'], prev['Ip_Lon'], curr['Ip_Lat'], curr['Ip_Lon'])
        if dist < 1:
            prev = curr
            continue
        src_color = INFRA_COLORS.get(prev.get('_category', 'normal'), [34, 197, 94])
        tgt_color = INFRA_COLORS.get(curr.get('_category', 'normal'), [34, 197, 94])
        arcs.append({
            'from_lat': prev['Ip_Lat'], 'from_lon': prev['Ip_Lon'],
            'to_lat': curr['Ip_Lat'], 'to_lon': curr['Ip_Lon'],
            '_from_city': from_city, '_to_city': to_city,
            '_distance': f"{dist:.0f}", '_count': '1',
            'src_r': src_color[0], 'src_g': src_color[1], 'src_b': src_color[2],
            'tgt_r': tgt_color[0], 'tgt_g': tgt_color[1], 'tgt_b': tgt_color[2],
        })
        prev = curr

    if not arcs:
        return None, None

    arc_df = pd.DataFrame(arcs)

    layer = pdk.Layer(
        "ArcLayer",
        data=arc_df,
        get_source_position='[from_lon, from_lat]',
        get_target_position='[to_lon, to_lat]',
        get_source_color='[src_r, src_g, src_b, 200]',
        get_target_color='[tgt_r, tgt_g, tgt_b, 200]',
        get_width=3,
        pickable=True,
        auto_highlight=True,
    )
    return layer, arc_df


def create_trips_layer(df, trail_length=80, current_time=None):
    """
    TripsLayer for animated temporal replay.
    Expects df sorted by _dt with columns Ip_Lat, Ip_Lon, _dt, _color_r/g/b.
    Returns (layer, timestamps_range) or (None, None).
    """
    if '_dt' not in df.columns or len(df) < 2:
        return None, None

    df_sorted = df.dropna(subset=['_dt']).sort_values('_dt')
    if len(df_sorted) < 2:
        return None, None

    min_ts = int(df_sorted['_dt'].min().timestamp())
    max_ts = int(df_sorted['_dt'].max().timestamp())

    if current_time is None:
        current_time = max_ts

    # Build trip path: single trip with all waypoints
    waypoints = []
    for _, row in df_sorted.iterrows():
        waypoints.append({
            'coordinates': [float(row['Ip_Lon']), float(row['Ip_Lat'])],
            'timestamp': int(row['_dt'].timestamp()) - min_ts,
        })

    trip_data = pd.DataFrame([{
        'path': waypoints,
        'color': [129, 140, 248],  # indigo
    }])

    layer = pdk.Layer(
        "TripsLayer",
        data=trip_data,
        get_path='path',
        get_timestamps='path',
        get_color='color',
        opacity=0.8,
        width_min_pixels=4,
        trail_length=trail_length,
        current_time=current_time - min_ts,
    )
    return layer, (min_ts, max_ts)


# ============================================================
# COMPLETE MAP BUILDERS
# ============================================================

def render_scatterplot_map(df, style='Escuro', use_3d=False, pitch=45):
    """Build complete ScatterplotLayer/ColumnLayer map deck."""
    actual_pitch = pitch if use_3d else 0
    layers = [create_scatterplot_layer(df, use_3d=use_3d)]
    alert = create_alert_layer(df)
    if alert:
        layers.append(alert)

    return pdk.Deck(
        layers=layers,
        initial_view_state=get_view_state(df, pitch=actual_pitch),
        map_style=get_map_style(style),
        tooltip=TOOLTIP_SINGLE,
    )


def render_hexagon_map(df, style='Escuro', radius=5000, elevation_scale=100):
    """Build complete HexagonLayer 3D map deck."""
    return pdk.Deck(
        layers=[create_hexagon_layer(df, radius=radius, elevation_scale=elevation_scale)],
        initial_view_state=get_view_state(df, pitch=50, zoom=4),
        map_style=get_map_style(style),
        tooltip=TOOLTIP_HEX,
    )


def render_heatmap(df, style='Escuro', radius=30, show_markers=False):
    """Build HeatmapLayer map, optionally with ScatterplotLayer overlay."""
    layers = [create_heatmap_layer(df, radius=radius)]
    tooltip = None
    if show_markers:
        df_unique = df.drop_duplicates(subset=['Ip'])
        layers.append(pdk.Layer(
            "ScatterplotLayer",
            data=df_unique,
            get_position='[Ip_Lon, Ip_Lat]',
            get_radius=600,
            radius_min_pixels=3,
            radius_max_pixels=15,
            get_fill_color='[_color_r, _color_g, _color_b, 160]',
            pickable=True,
            auto_highlight=True,
        ))
        tooltip = TOOLTIP_SINGLE
    return pdk.Deck(
        layers=layers,
        initial_view_state=get_view_state(df, pitch=0, zoom=4),
        map_style=get_map_style(style),
        tooltip=tooltip,
    )


def render_route_map(df, style='Escuro', use_3d=False):
    """Build PathLayer + ScatterplotLayer temporal route map."""
    if 'Data' not in df.columns:
        return None

    df_sorted = df.copy()
    df_sorted['_dt'] = pd.to_datetime(df_sorted['Data'], format='mixed', errors='coerce')
    df_sorted = df_sorted.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_sorted) < 2:
        return None

    layers = []
    path = create_path_layer(df_sorted)
    if path:
        layers.append(path)

    # Scatter markers for each point
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=df_sorted,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=1000,
        radius_min_pixels=5,
        radius_max_pixels=20,
        get_fill_color='[_color_r, _color_g, _color_b, _color_a]',
        pickable=True,
        auto_highlight=True,
    ))

    # Start / End markers as larger circles
    start = df_sorted.iloc[[0]].copy()
    end = df_sorted.iloc[[-1]].copy()
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=start,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=2500,
        radius_min_pixels=10,
        get_fill_color=[34, 197, 94, 220],  # green
        get_line_color=[255, 255, 255, 255],
        stroked=True,
        line_width_min_pixels=2,
        pickable=True,
    ))
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=end,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=2500,
        radius_min_pixels=10,
        get_fill_color=[239, 68, 68, 220],  # red
        get_line_color=[255, 255, 255, 255],
        stroked=True,
        line_width_min_pixels=2,
        pickable=True,
    ))

    pitch = 45 if use_3d else 0
    return pdk.Deck(
        layers=layers,
        initial_view_state=get_view_state(df_sorted, pitch=pitch, zoom=4),
        map_style=get_map_style(style),
        tooltip=TOOLTIP_SINGLE,
    )


def render_arc_map(df, style='Escuro'):
    """Build ArcLayer map showing city-to-city connections."""
    arc_layer, arc_df = create_arc_layer(df)
    if arc_layer is None:
        return None, None

    # Also add scatter markers for reference
    df_unique = df.drop_duplicates(subset=['Ip'])
    scatter = pdk.Layer(
        "ScatterplotLayer",
        data=df_unique,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=600,
        radius_min_pixels=3,
        radius_max_pixels=12,
        get_fill_color='[_color_r, _color_g, _color_b, 160]',
        pickable=True,
        auto_highlight=True,
    )

    deck = pdk.Deck(
        layers=[arc_layer, scatter],
        initial_view_state=get_view_state(df, pitch=50, zoom=4),
        map_style=get_map_style(style),
        tooltip=TOOLTIP_ARC,
    )
    return deck, arc_df


def render_globe_map(df):
    """Build GlobeView 3D with ScatterplotLayer."""
    view = pdk.View("GlobeView", controller=True, width="100%", height="100%")

    layers = [
        pdk.Layer(
            "GeoJsonLayer",
            id="base-map",
            data="https://d2ad6b4ur7yvpq.cloudfront.net/naturalearth-3.3.0/ne_50m_admin_0_scale_rank.geojson",
            stroked=False,
            filled=True,
            get_fill_color=[30, 41, 59, 200],
            get_line_color=[51, 65, 85],
        ),
        pdk.Layer(
            "ScatterplotLayer",
            data=df,
            get_position='[Ip_Lon, Ip_Lat]',
            get_radius=50000,
            radius_min_pixels=3,
            radius_max_pixels=15,
            get_fill_color='[_color_r, _color_g, _color_b, _color_a]',
            pickable=True,
            auto_highlight=True,
        ),
    ]

    view_state = pdk.ViewState(
        latitude=df['Ip_Lat'].mean(),
        longitude=df['Ip_Lon'].mean(),
        zoom=1,
    )

    return pdk.Deck(
        layers=layers,
        initial_view_state=view_state,
        views=[view],
        tooltip=TOOLTIP_SINGLE,
        parameters={"cull": True},
    )


def render_investigative_map(df, df_raw, style='Escuro', use_3d=False):
    """
    Composite investigative view: scatter (proportional) + path route + base locations + alerts.
    df: prepared pydeck dataframe (with _color_*, _radius columns)
    df_raw: original filtered dataframe (for base location detection)
    """
    layers = []

    # 1. Scatter layer — proportional radius (already computed in df)
    layers.append(create_scatterplot_layer(df, use_3d=False))

    # 2. Alert layer — proxy/datacenter highlights
    alert = create_alert_layer(df)
    if alert:
        layers.append(alert)

    # 3. Path layer — chronological route (thin, subtle)
    if 'Data' in df.columns:
        df_sorted = df.copy()
        df_sorted['_dt'] = pd.to_datetime(df_sorted['Data'], format='mixed', errors='coerce')
        df_sorted = df_sorted.dropna(subset=['_dt']).sort_values('_dt')
        if len(df_sorted) >= 2:
            path = create_path_layer(df_sorted)
            if path:
                # Override with a subtler color for investigative mode
                path.get_color = [129, 140, 248, 100]
                path.width_min_pixels = 1
                path.width_max_pixels = 3
                layers.append(path)

    # 4. Base locations — highlighted markers for home/work
    try:
        from analysis import detect_base_locations
        bases = detect_base_locations(df_raw)
        if bases:
            base_data = []
            for b in bases:
                base_data.append({
                    'Ip_Lon': b.get('lon', b.get('Ip_Lon', 0)),
                    'Ip_Lat': b.get('lat', b.get('Ip_Lat', 0)),
                    '_base_type': b.get('type', 'base'),
                    '_base_label': b.get('label', b.get('type', 'Base')),
                    '_base_count': b.get('count', 0),
                    '_base_provider': b.get('provider', b.get('Ip_Dono', 'N/A')),
                })
            if base_data:
                base_df = pd.DataFrame(base_data)
                # Home = green ring, Work = blue ring, other = purple
                base_colors = {
                    'home': [34, 197, 94, 220],
                    'work': [59, 130, 246, 220],
                }
                base_df['_br'] = base_df['_base_type'].apply(lambda t: base_colors.get(t, [168, 85, 247, 220])[0])
                base_df['_bg'] = base_df['_base_type'].apply(lambda t: base_colors.get(t, [168, 85, 247, 220])[1])
                base_df['_bb'] = base_df['_base_type'].apply(lambda t: base_colors.get(t, [168, 85, 247, 220])[2])
                base_df['_ba'] = base_df['_base_type'].apply(lambda t: base_colors.get(t, [168, 85, 247, 220])[3])

                # Large ring markers for base locations
                layers.append(pdk.Layer(
                    "ScatterplotLayer",
                    data=base_df,
                    get_position='[Ip_Lon, Ip_Lat]',
                    get_radius=5000,
                    radius_min_pixels=18,
                    radius_max_pixels=50,
                    get_fill_color='[_br, _bg, _bb, 40]',
                    get_line_color='[_br, _bg, _bb, _ba]',
                    stroked=True,
                    filled=True,
                    line_width_min_pixels=3,
                    pickable=True,
                    auto_highlight=True,
                ))
    except Exception as e:
        logger.debug(f"Base locations not available for investigative view: {e}")

    if not layers:
        return None

    pitch = 30 if use_3d else 0
    return pdk.Deck(
        layers=layers,
        initial_view_state=get_view_state(df, pitch=pitch, zoom=5),
        map_style=get_map_style(style),
        tooltip=TOOLTIP_SINGLE,
    )
