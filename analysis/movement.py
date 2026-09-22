"""analysis.movement — split from analysis monolith."""
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)

def detect_impossible_jumps(df, max_speed_kmh=900, date_col='Data',
                            lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Detect physically impossible location jumps based on travel speed.
    Default max_speed_kmh=900 (commercial flight speed).

    Returns DataFrame with anomalous jumps.
    """
    df_j = df.copy()
    df_j[lat_col] = pd.to_numeric(df_j[lat_col], errors='coerce')
    df_j[lon_col] = pd.to_numeric(df_j[lon_col], errors='coerce')
    df_j['_dt'] = pd.to_datetime(df_j[date_col], errors='coerce')
    df_j = df_j.dropna(subset=[lat_col, lon_col, '_dt'])
    df_j = df_j[(df_j[lat_col] != 0) | (df_j[lon_col] != 0)]
    df_j = df_j.sort_values('_dt')

    if len(df_j) < 2:
        return pd.DataFrame(columns=['De_IP', 'Para_IP', 'De_Cidade', 'Para_Cidade',
                                     'Distancia_km', 'Tempo_h', 'Velocidade_kmh',
                                     'Data_De', 'Data_Para'])

    R = 6371
    rows = []
    prev = None
    for _, cur in df_j.iterrows():
        if prev is not None:
            dlat = np.radians(cur[lat_col] - prev[lat_col])
            dlon = np.radians(cur[lon_col] - prev[lon_col])
            a = np.sin(dlat/2)**2 + np.cos(np.radians(prev[lat_col])) * \
                np.cos(np.radians(cur[lat_col])) * np.sin(dlon/2)**2
            dist = R * 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))

            delta_h = (cur['_dt'] - prev['_dt']).total_seconds() / 3600
            if delta_h > 0 and dist > 10:
                speed = dist / delta_h
                if speed > max_speed_kmh:
                    rows.append({
                        'De_IP': prev.get('Ip', ''),
                        'Para_IP': cur.get('Ip', ''),
                        'De_Cidade': prev.get('Ip_Cidade', ''),
                        'Para_Cidade': cur.get('Ip_Cidade', ''),
                        'Distancia_km': round(dist, 1),
                        'Tempo_h': round(delta_h, 2),
                        'Velocidade_kmh': round(speed, 0),
                        'Data_De': prev['_dt'].strftime('%Y-%m-%d %H:%M'),
                        'Data_Para': cur['_dt'].strftime('%Y-%m-%d %H:%M'),
                    })
        prev = cur

    return pd.DataFrame(rows)


# ============================================================
# 20. BASE LOCATION DETECTION (home / work)
# ============================================================
def detect_base_locations(df, date_col='Data', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Detect probable home and work locations based on access patterns.
    Night (22-06) = home, Day (08-18) = work.

    Returns dict with 'home' and 'work' dicts containing lat, lon, city, count.
    """
    df_b = df.copy()
    df_b[lat_col] = pd.to_numeric(df_b[lat_col], errors='coerce')
    df_b[lon_col] = pd.to_numeric(df_b[lon_col], errors='coerce')
    df_b['_dt'] = pd.to_datetime(df_b[date_col], errors='coerce')
    df_b = df_b.dropna(subset=[lat_col, lon_col, '_dt'])
    df_b = df_b[(df_b[lat_col] != 0) | (df_b[lon_col] != 0)]
    df_b['_hour'] = df_b['_dt'].dt.hour

    result = {'home': None, 'work': None}

    for label, mask in [('home', df_b['_hour'].between(22, 23) | df_b['_hour'].between(0, 6)),
                        ('work', df_b['_hour'].between(8, 18))]:
        subset = df_b[mask]
        if subset.empty:
            continue
        # Cluster by rounded coords (city-level) — chave vetorizada; o
        # apply(axis=1) anterior fazia uma passada Python por linha.
        subset = subset.copy()
        subset['_loc'] = (subset[lat_col].round(2).astype(str) + ',' +
                          subset[lon_col].round(2).astype(str))
        top = subset['_loc'].value_counts()
        if top.empty:
            continue
        best_loc = top.index[0]
        best_rows = subset[subset['_loc'] == best_loc]
        result[label] = {
            'lat': best_rows[lat_col].mean(),
            'lon': best_rows[lon_col].mean(),
            'city': best_rows['Ip_Cidade'].mode().iloc[0] if 'Ip_Cidade' in best_rows.columns and not best_rows['Ip_Cidade'].mode().empty else '',
            'region': best_rows['Ip_Regiao'].mode().iloc[0] if 'Ip_Regiao' in best_rows.columns and not best_rows['Ip_Regiao'].mode().empty else '',
            'count': len(best_rows),
            'provider': best_rows['Ip_Dono'].mode().iloc[0] if 'Ip_Dono' in best_rows.columns and not best_rows['Ip_Dono'].mode().empty else '',
        }

    return result


# ============================================================
# 21. BEHAVIORAL PROFILE GENERATION
# ============================================================
def generate_behavioral_profile(df, alvo='', date_col='Data'):
    """
    Generate an automatic behavioral profile of the target as structured text.

    Returns dict with profile sections.
    """
    profile = {
        'alvo': alvo,
        'total_registros': len(df),
        'ips_unicos': df['Ip'].nunique() if 'Ip' in df.columns else 0,
        'periodo_inicio': '',
        'periodo_fim': '',
        'dias_monitorados': 0,
        'provedor_principal': '',
        'cidade_principal': '',
        'regiao_principal': '',
        'horario_pico': '',
        'padrao_atividade': '',
        'cidades_visitadas': [],
        'provedores': [],
        'resumo': '',
    }

    if df.empty:
        return profile

    # Date range
    df_p = df.copy()
    df_p['_dt'] = pd.to_datetime(df_p[date_col], errors='coerce')
    df_p = df_p.dropna(subset=['_dt'])

    if not df_p.empty:
        profile['periodo_inicio'] = df_p['_dt'].min().strftime('%Y-%m-%d')
        profile['periodo_fim'] = df_p['_dt'].max().strftime('%Y-%m-%d')
        profile['dias_monitorados'] = (df_p['_dt'].max() - df_p['_dt'].min()).days + 1

    # Provider
    if 'Ip_Dono' in df.columns:
        prov = df['Ip_Dono'].dropna().value_counts()
        if not prov.empty:
            profile['provedor_principal'] = prov.index[0]
            profile['provedores'] = [f"{p} ({c}x)" for p, c in prov.head(5).items()]

    # City / Region
    if 'Ip_Cidade' in df.columns:
        cidades = df['Ip_Cidade'].dropna().value_counts()
        if not cidades.empty:
            profile['cidade_principal'] = cidades.index[0]
            profile['cidades_visitadas'] = [f"{c} ({n}x)" for c, n in cidades.head(10).items()]
    if 'Ip_Regiao' in df.columns:
        regioes = df['Ip_Regiao'].dropna().value_counts()
        if not regioes.empty:
            profile['regiao_principal'] = regioes.index[0]

    # Activity pattern
    if not df_p.empty:
        hours = df_p['_dt'].dt.hour
        peak = hours.value_counts().head(3)
        profile['horario_pico'] = ', '.join([f"{h}h" for h in sorted(peak.index)])
        diurno = ((hours >= 6) & (hours < 18)).sum()
        noturno = len(hours) - diurno
        pct_diurno = diurno / len(hours) * 100 if len(hours) > 0 else 0
        if pct_diurno > 70:
            profile['padrao_atividade'] = 'Predominantemente diurno'
        elif pct_diurno < 30:
            profile['padrao_atividade'] = 'Predominantemente noturno'
        else:
            profile['padrao_atividade'] = 'Misto (diurno e noturno)'

    # Build summary text
    lines = []
    if profile['alvo']:
        lines.append(f"Alvo: {profile['alvo']}")
    lines.append(f"Período: {profile['periodo_inicio']} a {profile['periodo_fim']} ({profile['dias_monitorados']} dias)")
    lines.append(f"Registros: {profile['total_registros']} | IPs únicos: {profile['ips_unicos']}")
    if profile['provedor_principal']:
        lines.append(f"Provedor principal: {profile['provedor_principal']}")
    if profile['cidade_principal']:
        lines.append(f"Cidade principal: {profile['cidade_principal']}, {profile['regiao_principal']}")
    if profile['horario_pico']:
        lines.append(f"Horários de pico: {profile['horario_pico']}")
    if profile['padrao_atividade']:
        lines.append(f"Padrão: {profile['padrao_atividade']}")
    if len(profile['cidades_visitadas']) > 1:
        lines.append(f"Cidades: {', '.join(profile['cidades_visitadas'][:5])}")

    profile['resumo'] = '\n'.join(lines)
    return profile


# ============================================================
# 22. PERIOD COMPARISON (A vs B)
# ============================================================
def compare_split_periods(df, date_col='Data', split_date=None):
    """
    Compare two time periods of the same target, splitting automatically.

    Para comparar dois intervalos escolhidos pelo analista, use
    `helpers.period_compare.compare_periods` — assinatura diferente.

    If split_date is None, splits at the midpoint.

    Returns dict with comparison metrics.
    """
    df_c = df.copy()
    df_c['_dt'] = pd.to_datetime(df_c[date_col], errors='coerce')
    df_c = df_c.dropna(subset=['_dt'])

    if df_c.empty:
        return {}

    if split_date is None:
        mid = df_c['_dt'].min() + (df_c['_dt'].max() - df_c['_dt'].min()) / 2
    else:
        mid = pd.to_datetime(split_date)

    a = df_c[df_c['_dt'] < mid]
    b = df_c[df_c['_dt'] >= mid]

    def _stats(subset, label):
        s = {'label': label, 'registros': len(subset)}
        s['ips_unicos'] = subset['Ip'].nunique() if 'Ip' in subset.columns else 0
        if 'Ip_Dono' in subset.columns:
            prov = subset['Ip_Dono'].dropna().value_counts()
            s['provedor_top'] = prov.index[0] if not prov.empty else ''
        if 'Ip_Cidade' in subset.columns:
            cid = subset['Ip_Cidade'].dropna().value_counts()
            s['cidade_top'] = cid.index[0] if not cid.empty else ''
            s['cidades'] = cid.index.tolist()[:5]
        if 'Ip_Regiao' in subset.columns:
            reg = subset['Ip_Regiao'].dropna().value_counts()
            s['regiao_top'] = reg.index[0] if not reg.empty else ''
        if '_dt' in subset.columns and not subset.empty:
            s['inicio'] = subset['_dt'].min().strftime('%Y-%m-%d')
            s['fim'] = subset['_dt'].max().strftime('%Y-%m-%d')
        s['movel_pct'] = round(subset['Ip_Movel'].sum() / len(subset) * 100, 1) if 'Ip_Movel' in subset.columns and len(subset) > 0 else 0
        return s

    result = {
        'periodo_a': _stats(a, 'Período A'),
        'periodo_b': _stats(b, 'Período B'),
        'split_date': mid.strftime('%Y-%m-%d'),
    }

    # Changes
    changes = []
    pa, pb = result['periodo_a'], result['periodo_b']
    if pa.get('provedor_top') != pb.get('provedor_top') and pa.get('provedor_top') and pb.get('provedor_top'):
        changes.append(f"Provedor mudou: {pa['provedor_top']} → {pb['provedor_top']}")
    if pa.get('cidade_top') != pb.get('cidade_top') and pa.get('cidade_top') and pb.get('cidade_top'):
        changes.append(f"Cidade mudou: {pa['cidade_top']} → {pb['cidade_top']}")
    new_cities = set(pb.get('cidades', [])) - set(pa.get('cidades', []))
    if new_cities:
        changes.append(f"Novas cidades: {', '.join(list(new_cities)[:3])}")
    result['mudancas'] = changes

    return result


# ============================================================
# 23. CONVEX HULL / MOVEMENT RADIUS
# ============================================================
def calculate_movement_area(df, lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Calculate the convex hull area (km²) and bounding coordinates.

    Returns dict with area_km2, hull_coords, center, max_distance_km.
    """
    df_a = df.copy()
    df_a[lat_col] = pd.to_numeric(df_a[lat_col], errors='coerce')
    df_a[lon_col] = pd.to_numeric(df_a[lon_col], errors='coerce')
    df_a = df_a.dropna(subset=[lat_col, lon_col])
    df_a = df_a[(df_a[lat_col] != 0) | (df_a[lon_col] != 0)]

    unique_points = df_a[[lat_col, lon_col]].drop_duplicates()

    if len(unique_points) < 3:
        center_lat = unique_points[lat_col].mean() if not unique_points.empty else 0
        center_lon = unique_points[lon_col].mean() if not unique_points.empty else 0
        return {
            'area_km2': 0,
            'hull_coords': unique_points.values.tolist(),
            'center': [center_lat, center_lon],
            'max_distance_km': 0,
            'num_points': len(unique_points),
        }

    from scipy.spatial import ConvexHull
    points = unique_points.values
    try:
        hull = ConvexHull(points)
    except Exception as e:
        # QhullError em pontos colineares etc. — relatamos e devolvemos
        # fallback em vez de apresentar ausência de área como resultado.
        logger.warning("ConvexHull falhou (%d pontos): %s", len(points), e)
        return {
            'area_km2': 0, 'hull_coords': points.tolist(),
            'center': [points[:, 0].mean(), points[:, 1].mean()],
            'max_distance_km': 0, 'num_points': len(points),
        }

    hull_pts = points[hull.vertices].tolist()
    # Close the polygon
    hull_pts.append(hull_pts[0])

    # Approximate area in km² (lat/lon to km conversion)
    center_lat = points[:, 0].mean()
    center_lon = points[:, 1].mean()
    lat_km = 111.32  # km per degree latitude
    lon_km = 111.32 * np.cos(np.radians(center_lat))
    area_deg2 = hull.volume  # 2D: volume = area
    area_km2 = area_deg2 * lat_km * lon_km

    # Max distance from center
    R = 6371
    max_dist = 0
    for pt in points:
        dlat = np.radians(pt[0] - center_lat)
        dlon = np.radians(pt[1] - center_lon)
        a = np.sin(dlat/2)**2 + np.cos(np.radians(center_lat)) * \
            np.cos(np.radians(pt[0])) * np.sin(dlon/2)**2
        d = R * 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
        max_dist = max(max_dist, d)

    return {
        'area_km2': round(area_km2, 1),
        'hull_coords': hull_pts,
        'center': [center_lat, center_lon],
        'max_distance_km': round(max_dist, 1),
        'num_points': len(unique_points),
    }


