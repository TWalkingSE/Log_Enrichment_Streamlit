"""
Log Enrichment - UI Components for enhanced visualization
4.2 - Data Health Gauges
4.3 - Side-by-side target comparison
4.4 - Map temporal replay animation
4.5 - IP table sparklines
"""

import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import json
from styles.theme import COLORS


# ============================================================
# 4.2 - DATA HEALTH GAUGE DASHBOARD
# ============================================================

def render_health_gauges(health_metrics):
    """
    Render data health metrics as gauge charts (speedometers)
    with traffic-light colors (red/yellow/green).
    """
    if not health_metrics or health_metrics.get('total', 0) == 0:
        st.info("Nenhuma métrica de saúde disponível.")
        return

    gauges = [
        ('Score Geral', health_metrics.get('overall_score', 0), '%'),
        ('Cobertura IP', health_metrics.get('ip_coverage', 0), '%'),
        ('Provedores', health_metrics.get('provider_coverage', 0), '%'),
        ('Geolocalização', health_metrics.get('geo_coverage', 0), '%'),
        ('Datas', health_metrics.get('date_coverage', 0), '%'),
    ]

    cols = st.columns(len(gauges))
    for i, (title, value, suffix) in enumerate(gauges):
        with cols[i]:
            # Determine color
            if value >= 80:
                bar_color = COLORS['success']
                status = '✅'
            elif value >= 50:
                bar_color = COLORS['warning']
                status = '⚠️'
            else:
                bar_color = COLORS['danger']
                status = '❌'

            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=value,
                title={'text': f'{status} {title}', 'font': {'size': 13, 'color': COLORS['text']}},
                number={'suffix': suffix, 'font': {'size': 20, 'color': COLORS['text']}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': COLORS['text_dim'],
                             'tickfont': {'color': COLORS['text_muted'], 'size': 9}},
                    'bar': {'color': bar_color, 'thickness': 0.7},
                    'bgcolor': COLORS['surface_card'],
                    'borderwidth': 1,
                    'bordercolor': COLORS['border'],
                    'steps': [
                        {'range': [0, 50], 'color': 'rgba(239,68,68,0.1)'},
                        {'range': [50, 80], 'color': 'rgba(245,158,11,0.1)'},
                        {'range': [80, 100], 'color': 'rgba(34,197,94,0.1)'},
                    ],
                    'threshold': {
                        'line': {'color': COLORS['text'], 'width': 2},
                        'thickness': 0.75,
                        'value': value,
                    },
                },
            ))
            fig.update_layout(
                height=180,
                margin=dict(l=15, r=15, t=40, b=5),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': COLORS['text']},
            )
            st.plotly_chart(fig, use_container_width=True)

    # Additional metrics as a row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Registros", health_metrics.get('total', 0))
    with c2:
        st.metric("IPv4 / IPv6", f"{health_metrics.get('ipv4_ratio', 0)}% / {health_metrics.get('ipv6_ratio', 0)}%")
    with c3:
        st.metric("Proxy/VPN", f"{health_metrics.get('proxy_ratio', 0)}%")
    with c4:
        overall = health_metrics.get('overall_score', 0)
        label = 'Excelente' if overall >= 80 else 'Bom' if overall >= 60 else 'Regular' if overall >= 40 else 'Ruim'
        st.metric("Qualidade", label)


# ============================================================
# 4.3 - SIDE-BY-SIDE TARGET COMPARISON
# ============================================================

def render_side_by_side_comparison(df1, df2, name1='Alvo 1', name2='Alvo 2'):
    """
    Render a split-screen comparison of two targets with maps, timelines, and stats.
    """
    st.subheader(f"📊 Comparação: {name1} vs {name2}")

    # Stats comparison
    col1, col2 = st.columns(2)

    for col, df, name in [(col1, df1, name1), (col2, df2, name2)]:
        with col:
            st.markdown(f"### {name}")
            ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
            total = len(df)
            unique = df[ip_col].nunique() if ip_col in df.columns else 0
            providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0
            cities = df['Ip_Cidade'].dropna().nunique() if 'Ip_Cidade' in df.columns else 0
            proxy_pct = df['Ip_Proxy'].sum() / max(total, 1) * 100 if 'Ip_Proxy' in df.columns else 0

            m1, m2, m3 = st.columns(3)
            m1.metric("Registros", total)
            m2.metric("IPs Únicos", unique)
            m3.metric("Provedores", providers)

            m4, m5 = st.columns(2)
            m4.metric("Cidades", cities)
            m5.metric("Proxy %", f"{proxy_pct:.1f}%")

    # Timeline comparison
    st.subheader("📅 Timeline Comparativa")
    col1, col2 = st.columns(2)

    for col, df, name in [(col1, df1, name1), (col2, df2, name2)]:
        with col:
            if 'Data' in df.columns:
                df_t = df.copy()
                df_t['_dt'] = pd.to_datetime(df_t['Data'], format='mixed', errors='coerce')
                df_t = df_t.dropna(subset=['_dt'])
                if not df_t.empty:
                    daily = df_t.groupby(df_t['_dt'].dt.date).size().reset_index(name='count')
                    daily.columns = ['Data', 'Registros']
                    fig = px.area(daily, x='Data', y='Registros', title=name)
                    fig.update_layout(height=250, margin=dict(l=10, r=10, t=40, b=10))
                    st.plotly_chart(fig, use_container_width=True)

    # Provider comparison
    st.subheader("🏢 Provedores")
    col1, col2 = st.columns(2)
    for col, df, name in [(col1, df1, name1), (col2, df2, name2)]:
        with col:
            if 'Ip_Dono' in df.columns:
                pc = df['Ip_Dono'].value_counts().head(10).reset_index()
                pc.columns = ['Provedor', 'Qtd']
                fig = px.bar(pc, x='Qtd', y='Provedor', orientation='h',
                             title=name,
                             color='Qtd', color_continuous_scale='Viridis')
                fig.update_layout(height=300, margin=dict(l=10, r=10, t=40, b=10),
                                  showlegend=False, coloraxis_showscale=False,
                                  yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)

    # Convergence highlights
    st.subheader("🔗 Pontos de Convergência")
    ip_col1 = 'Sender IP' if 'Sender IP' in df1.columns else 'Ip'
    ip_col2 = 'Sender IP' if 'Sender IP' in df2.columns else 'Ip'
    ips1 = set(df1[ip_col1].dropna().unique()) if ip_col1 in df1.columns else set()
    ips2 = set(df2[ip_col2].dropna().unique()) if ip_col2 in df2.columns else set()
    shared = ips1 & ips2

    if shared:
        st.success(f"🔗 {len(shared)} IPs compartilhados encontrados!")
        shared_df = pd.DataFrame({'IP Compartilhado': sorted(shared)})
        st.dataframe(shared_df, hide_index=True)
    else:
        st.info("Nenhum IP compartilhado entre os alvos.")

    # Shared cities
    cities1 = set(df1['Ip_Cidade'].dropna().unique()) if 'Ip_Cidade' in df1.columns else set()
    cities2 = set(df2['Ip_Cidade'].dropna().unique()) if 'Ip_Cidade' in df2.columns else set()
    shared_cities = cities1 & cities2
    if shared_cities:
        st.info(f"🏙️ Cidades em comum: {', '.join(sorted(shared_cities))}")


# ============================================================
# 4.4 - MAP TEMPORAL REPLAY (ANIMATION)
# ============================================================

def render_map_replay(df, height=600):
    """
    Render an animated 2D map with temporal playback controls.
    Uses the embedded Leaflet.js replay to keep the experience consistent with the 2D map page.
    """
    if df is None or df.empty:
        st.info("Nenhum dado para animação.")
        return

    df_m = df.copy()
    df_m['_dt'] = pd.to_datetime(df_m.get('Data', pd.Series(dtype='object')),
                                  format='mixed', errors='coerce')
    df_m['Ip_Lat'] = pd.to_numeric(df_m.get('Ip_Lat'), errors='coerce')
    df_m['Ip_Lon'] = pd.to_numeric(df_m.get('Ip_Lon'), errors='coerce')
    df_m = df_m.dropna(subset=['_dt', 'Ip_Lat', 'Ip_Lon'])
    df_m = df_m[(df_m['Ip_Lat'] != 0) | (df_m['Ip_Lon'] != 0)]
    df_m = df_m.sort_values('_dt')

    if df_m.empty:
        st.warning("Nenhum dado com coordenadas e datas válidas.")
        return

    _render_leaflet_replay(df_m, height)


def _render_pydeck_replay(df_m, height=600):
    """Pydeck TripsLayer animated replay with Streamlit slider."""
    import pydeck as pdk
    from components.modern_map import prepare_map_dataframe, get_map_style, TOOLTIP_SINGLE

    # Limit for animation performance
    max_points = 2000
    if len(df_m) > max_points:
        st.info(f"Limitando animação a {max_points} pontos (total: {len(df_m)}).")
        df_m = df_m.head(max_points)

    df_pdk = prepare_map_dataframe(df_m)
    min_ts = int(df_m['_dt'].min().timestamp())
    max_ts = int(df_m['_dt'].max().timestamp())

    # Timeline slider
    rc1, rc2 = st.columns([4, 1])
    with rc1:
        current_time = st.slider(
            "Timeline",
            min_value=min_ts, max_value=max_ts, value=max_ts,
            format="",
            key="replay_slider",
            help="Arraste para controlar o tempo da animação"
        )
    with rc2:
        from datetime import datetime
        ts_label = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M')
        st.markdown(f"**{ts_label}**")
        pct = ((current_time - min_ts) / max(max_ts - min_ts, 1)) * 100
        st.caption(f"{pct:.0f}% concluído")

    # Filter data up to current_time
    df_visible = df_pdk[df_pdk['_dt'].apply(lambda x: x.timestamp()) <= current_time]

    if df_visible.empty:
        st.info("Nenhum ponto visível neste momento da timeline.")
        return

    # Build path from visible points
    coords = df_visible[['Ip_Lon', 'Ip_Lat']].values.tolist()
    path_data = pd.DataFrame({'path': [coords]}) if len(coords) >= 2 else None

    layers = []

    # Path line
    if path_data is not None:
        layers.append(pdk.Layer(
            "PathLayer",
            data=path_data,
            get_path='path',
            get_color=[129, 140, 248, 160],
            width_min_pixels=2,
            width_max_pixels=5,
        ))

    # Scatter markers for visible points
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=df_visible,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=800,
        radius_min_pixels=4,
        radius_max_pixels=20,
        get_fill_color='[_color_r, _color_g, _color_b, _color_a]',
        pickable=True,
        auto_highlight=True,
    ))

    # Start marker
    start = df_visible.iloc[[0]]
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=start,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=2000,
        radius_min_pixels=8,
        get_fill_color=[34, 197, 94, 220],
        get_line_color=[255, 255, 255, 255],
        stroked=True,
        line_width_min_pixels=2,
    ))

    # Current position marker (latest visible point)
    latest = df_visible.iloc[[-1]]
    layers.append(pdk.Layer(
        "ScatterplotLayer",
        data=latest,
        get_position='[Ip_Lon, Ip_Lat]',
        get_radius=2500,
        radius_min_pixels=10,
        get_fill_color=[56, 189, 248, 255],
        get_line_color=[255, 255, 255, 255],
        stroked=True,
        line_width_min_pixels=3,
    ))

    center_lat = df_visible['Ip_Lat'].mean()
    center_lon = df_visible['Ip_Lon'].mean()

    deck = pdk.Deck(
        layers=layers,
        initial_view_state=pdk.ViewState(
            latitude=center_lat, longitude=center_lon,
            zoom=5, pitch=30,
        ),
        map_style=get_map_style('Escuro'),
        tooltip=TOOLTIP_SINGLE,
    )
    st.pydeck_chart(deck, height=height - 60, key="replay_map")

    # Stats
    rc_s1, rc_s2, rc_s3 = st.columns(3)
    with rc_s1:
        st.metric("Pontos visíveis", len(df_visible))
    with rc_s2:
        st.metric("Total", len(df_m))
    with rc_s3:
        ip_col = 'Sender IP' if 'Sender IP' in df_visible.columns else 'Ip'
        st.metric("IPs únicos", df_visible[ip_col].nunique() if ip_col in df_visible.columns else 0)


def _render_leaflet_replay(df_m, height=600):
    """Fallback: Leaflet.js embedded HTML animation (original implementation)."""
    # Limit for performance
    if len(df_m) > 500:
        st.info(f"Limitando animação a 500 pontos (total: {len(df_m)}).")
        df_m = df_m.head(500)

    markers = []
    for _, row in df_m.iterrows():
        is_proxy = str(row.get('Ip_Proxy', '')).lower() == 'true'
        is_hosting = str(row.get('Ip_Hospedagem', '')).lower() == 'true'
        color = COLORS['danger'] if is_proxy else COLORS['hosting'] if is_hosting else COLORS['success']
        markers.append({
            'lat': float(row['Ip_Lat']),
            'lon': float(row['Ip_Lon']),
            'ip': str(row.get('Ip', '')),
            'time': row['_dt'].strftime('%Y-%m-%d %H:%M'),
            'provider': str(row.get('Ip_Dono', ''))[:30],
            'city': str(row.get('Ip_Cidade', '')),
            'color': color,
        })

    center_lat = df_m['Ip_Lat'].mean()
    center_lon = df_m['Ip_Lon'].mean()
    markers_json = json.dumps(markers, ensure_ascii=False)

    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            body {{ margin:0; font-family:'Segoe UI',sans-serif; }}
            #map {{ width:100%; height:{height-60}px; }}
            .controls {{
                background: rgba(15,23,42,0.95); padding: 10px 16px;
                display: flex; align-items: center; gap: 10px; height: 50px;
                border-top: 1px solid #334155;
            }}
            .ctrl-btn {{
                background: #1e293b; border: 1px solid #334155; color: #e2e8f0;
                padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
            }}
            .ctrl-btn:hover {{ background: #38bdf8; color: #0f172a; }}
            .ctrl-btn.active {{ background: #38bdf8; color: #0f172a; }}
            #progress {{ flex: 1; height: 6px; background: #1e293b; border-radius: 3px;
                         cursor: pointer; position: relative; }}
            #progress-bar {{ height: 100%; background: #38bdf8; border-radius: 3px; width: 0; transition: width 0.1s; }}
            #status {{ color: #94a3b8; font-size: 12px; min-width: 120px; text-align: right; }}
            .speed-select {{ background: #1e293b; border: 1px solid #334155; color: #e2e8f0;
                             padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div id="map"></div>
        <div class="controls">
            <button class="ctrl-btn" id="playBtn" onclick="togglePlay()">&#9654; Play</button>
            <button class="ctrl-btn" onclick="resetReplay()">&#9198; Reset</button>
            <div id="progress" onclick="seekTo(event)">
                <div id="progress-bar"></div>
            </div>
            <select class="speed-select" id="speed" onchange="setSpeed(this.value)">
                <option value="500">0.5x</option>
                <option value="200" selected>1x</option>
                <option value="100">2x</option>
                <option value="50">4x</option>
                <option value="20">10x</option>
            </select>
            <span id="status">0 / {len(markers)}</span>
        </div>
        <script>
            var markers = {markers_json};
            var map = L.map('map', {{ zoomControl: true }}).setView([{center_lat}, {center_lon}], 5);
            L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                maxZoom: 19, attribution: '&copy; CartoDB'
            }}).addTo(map);
            var displayedMarkers = [];
            var polyline = L.polyline([], {{color: '#38bdf8', weight: 2, opacity: 0.6}}).addTo(map);
            var currentIndex = 0, playing = false, interval = null, speed = 200;
            function addMarker(i) {{
                var m = markers[i];
                var circle = L.circleMarker([m.lat, m.lon], {{
                    radius: 6, fillColor: m.color, color: '#fff', weight: 1, fillOpacity: 0.8
                }}).addTo(map);
                circle.bindPopup('<b>' + m.ip + '</b><br>' + m.city + '<br>' + m.provider + '<br>' + m.time);
                displayedMarkers.push(circle);
                polyline.addLatLng([m.lat, m.lon]);
                document.getElementById('progress-bar').style.width = ((i+1)/markers.length*100) + '%';
                document.getElementById('status').textContent = (i+1) + ' / ' + markers.length;
            }}
            function togglePlay() {{
                if (playing) {{
                    clearInterval(interval); playing = false;
                    document.getElementById('playBtn').innerHTML = '&#9654; Play';
                    document.getElementById('playBtn').classList.remove('active');
                }} else {{
                    playing = true;
                    document.getElementById('playBtn').innerHTML = '&#9208; Pause';
                    document.getElementById('playBtn').classList.add('active');
                    interval = setInterval(function() {{
                        if (currentIndex < markers.length) {{ addMarker(currentIndex); currentIndex++; }}
                        else {{
                            clearInterval(interval); playing = false;
                            document.getElementById('playBtn').innerHTML = '&#9654; Play';
                            document.getElementById('playBtn').classList.remove('active');
                        }}
                    }}, speed);
                }}
            }}
            function resetReplay() {{
                clearInterval(interval); playing = false; currentIndex = 0;
                displayedMarkers.forEach(function(m) {{ map.removeLayer(m); }});
                displayedMarkers = []; polyline.setLatLngs([]);
                document.getElementById('playBtn').innerHTML = '&#9654; Play';
                document.getElementById('playBtn').classList.remove('active');
                document.getElementById('progress-bar').style.width = '0%';
                document.getElementById('status').textContent = '0 / ' + markers.length;
            }}
            function setSpeed(ms) {{ speed = parseInt(ms); if (playing) {{ clearInterval(interval); togglePlay(); togglePlay(); }} }}
            function seekTo(evt) {{
                var rect = document.getElementById('progress').getBoundingClientRect();
                var pct = (evt.clientX - rect.left) / rect.width;
                var targetIdx = Math.floor(pct * markers.length);
                resetReplay();
                for (var i = 0; i < targetIdx; i++) {{ addMarker(i); }}
                currentIndex = targetIdx;
            }}
        </script>
    </body>
    </html>'''

    components.html(html, height=height, scrolling=False)


# ============================================================
# 4.5 - IP TABLE WITH INLINE SPARKLINES
# ============================================================

def render_ip_table_with_sparklines(df):
    """
    Render the IP results table with inline sparkline charts showing
    each IP's frequency over time.
    """
    if df is None or df.empty:
        st.info("Nenhum dado disponível.")
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    if ip_col not in df.columns or 'Data' not in df.columns:
        st.warning("Colunas necessárias (IP, Data) não encontradas.")
        return

    df_s = df.copy()
    df_s['_dt'] = pd.to_datetime(df_s['Data'], format='mixed', errors='coerce')
    df_s = df_s.dropna(subset=['_dt'])

    if df_s.empty:
        return

    # Get top IPs
    top_ips = df_s[ip_col].value_counts().head(30)

    # Build sparkline data per IP
    date_range = pd.date_range(df_s['_dt'].min().date(), df_s['_dt'].max().date(), freq='D')
    rows = []

    for ip, count in top_ips.items():
        ip_data = df_s[df_s[ip_col] == ip]
        daily = ip_data.groupby(ip_data['_dt'].dt.date).size()
        spark_vals = [int(daily.get(d.date(), 0)) for d in date_range]

        # Classify
        provider = ip_data['Ip_Dono'].iloc[0] if 'Ip_Dono' in ip_data.columns else ''
        city = ip_data['Ip_Cidade'].iloc[0] if 'Ip_Cidade' in ip_data.columns else ''
        is_proxy = str(ip_data.get('Ip_Proxy', pd.Series()).iloc[0] if 'Ip_Proxy' in ip_data.columns and len(ip_data) > 0 else '').lower() == 'true'

        # Determine persistence
        active_days = sum(1 for v in spark_vals if v > 0)
        total_days = len(spark_vals) if spark_vals else 1
        persistence = active_days / total_days

        if persistence > 0.7:
            pattern = '🟢 Persistente'
        elif persistence > 0.3:
            pattern = '🟡 Regular'
        else:
            pattern = '🔴 Pontual'

        rows.append({
            'IP': str(ip),
            'Contagem': count,
            'Provedor': str(provider)[:25] if pd.notna(provider) else '',
            'Cidade': str(city) if pd.notna(city) else '',
            'Tipo': '🛡️ Proxy' if is_proxy else '� Residencial',
            'Padrão': pattern,
            'Dias Ativos': active_days,
            '_sparkline': spark_vals,
        })

    # Render as HTML table with SVG sparklines
    table_html = f'''<style>
        .spark-table {{ width:100%; border-collapse:collapse; font-family:'Segoe UI',sans-serif; font-size:13px; }}
        .spark-table th {{ background:{COLORS['surface_card']}; color:{COLORS['text_muted']}; padding:8px 10px; text-align:left; border-bottom:2px solid {COLORS['border']}; }}
        .spark-table td {{ padding:6px 10px; border-bottom:1px solid {COLORS['surface_card']}; color:{COLORS['text']}; }}
        .spark-table tr:hover {{ background:{COLORS['surface']}; }}
        .spark-svg {{ vertical-align: middle; }}
    </style>
    <table class="spark-table">
    <tr><th>IP</th><th>Qtd</th><th>Provedor</th><th>Cidade</th><th>Tipo</th><th>Padrão</th><th>Atividade</th></tr>'''

    for row in rows:
        spark = row['_sparkline']
        if spark and max(spark) > 0:
            max_val = max(spark)
            w = min(len(spark) * 3, 150)
            h = 20
            points = []
            for xi, v in enumerate(spark):
                x = xi * (w / max(len(spark) - 1, 1))
                y = h - (v / max_val * h) if max_val > 0 else h
                points.append(f'{x:.1f},{y:.1f}')
            svg = f'<svg class="spark-svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
            svg += f'<polyline points="{" ".join(points)}" fill="none" stroke="{COLORS["accent"]}" stroke-width="1.5"/>'
            svg += '</svg>'
        else:
            svg = f'<span style="color:{COLORS["text_dim"]};">—</span>'

        from html import escape as _he
        table_html += f'''<tr>
            <td><code>{_he(str(row["IP"]))}</code></td><td>{_he(str(row["Contagem"]))}</td>
            <td>{_he(str(row["Provedor"]))}</td><td>{_he(str(row["Cidade"]))}</td>
            <td>{_he(str(row["Tipo"]))}</td><td>{_he(str(row["Padrão"]))}</td><td>{svg}</td></tr>'''

    table_html += '</table>'
    st.markdown(table_html, unsafe_allow_html=True)
