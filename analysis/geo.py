"""analysis.geo — split from analysis monolith."""
import pandas as pd
import numpy as np
import os
import json
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
from analysis._config import _analysis_config
from analysis.movement import detect_base_locations

def check_geofence(df, center_lat, center_lon, radius_km, lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Check which IPs are outside a geographic fence (circle).

    Args:
        df: DataFrame with lat/lon columns
        center_lat, center_lon: center of the fence
        radius_km: radius in kilometers

    Returns:
        Tuple of (df_inside, df_outside)
    """
    df_geo = df.copy()
    df_geo[lat_col] = pd.to_numeric(df_geo[lat_col], errors='coerce')
    df_geo[lon_col] = pd.to_numeric(df_geo[lon_col], errors='coerce')
    df_geo = df_geo.dropna(subset=[lat_col, lon_col])

    # Validar coordenadas do centro
    if not (-90 <= center_lat <= 90 and -180 <= center_lon <= 180):
        return pd.DataFrame(), pd.DataFrame()
    if center_lat == 0 and center_lon == 0:
        return pd.DataFrame(), pd.DataFrame()

    # Validar coordenadas: rejeitar (0,0) e fora dos limites
    df_geo = df_geo[
        (df_geo[lat_col].between(-90, 90)) &
        (df_geo[lon_col].between(-180, 180)) &
        ~((df_geo[lat_col] == 0) & (df_geo[lon_col] == 0))
    ]

    if df_geo.empty:
        return df_geo, pd.DataFrame()

    # Haversine distance
    R = 6371  # Earth radius in km
    lat1 = np.radians(center_lat)
    lat2 = np.radians(df_geo[lat_col].values)
    dlat = np.radians(df_geo[lat_col].values - center_lat)
    dlon = np.radians(df_geo[lon_col].values - center_lon)

    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
    c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1-a))
    distances = R * c

    df_geo['_distance_km'] = distances
    inside = df_geo[df_geo['_distance_km'] <= radius_km].drop(columns=['_distance_km'])
    outside = df_geo[df_geo['_distance_km'] > radius_km]

    return inside, outside


def detect_life_patterns(df, date_col='Data', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Detecta padrões de vida usando DBSCAN clustering geoespacial.
    Identifica automaticamente locais frequentados (casa, trabalho, lazer).

    Returns:
        dict com clusters, classificação e desvios de rotina.
    """
    _lp_config = _analysis_config.get('life_pattern', {})
    eps_km = _lp_config.get('dbscan_eps_km', 5.0)
    min_samples = _lp_config.get('dbscan_min_samples', 3)

    result = {
        'clusters': [],
        'routine_deviations': [],
        'has_data': False,
    }

    df_lp = df.copy()
    df_lp[lat_col] = pd.to_numeric(df_lp[lat_col], errors='coerce')
    df_lp[lon_col] = pd.to_numeric(df_lp[lon_col], errors='coerce')
    df_lp['_dt'] = pd.to_datetime(df_lp.get(date_col, pd.Series(dtype='object')), errors='coerce')
    df_lp = df_lp.dropna(subset=[lat_col, lon_col, '_dt'])
    df_lp = df_lp[(df_lp[lat_col] != 0) | (df_lp[lon_col] != 0)]

    if len(df_lp) < min_samples:
        return result

    result['has_data'] = True

    try:
        from sklearn.cluster import DBSCAN
    except ImportError:
        # Fallback: usar detect_base_locations simples
        logger.warning("scikit-learn não instalado — usando detecção de base simplificada")
        base = detect_base_locations(df, date_col, lat_col, lon_col)
        if base.get('home'):
            result['clusters'].append({
                'id': 0, 'label': 'Casa (estimado)', 'type': 'home',
                **base['home']
            })
        if base.get('work'):
            result['clusters'].append({
                'id': 1, 'label': 'Trabalho (estimado)', 'type': 'work',
                **base['work']
            })
        return result

    # Convert to radians for DBSCAN with haversine
    coords = np.radians(df_lp[[lat_col, lon_col]].values)
    eps_rad = eps_km / 6371.0  # Earth radius

    clustering = DBSCAN(eps=eps_rad, min_samples=min_samples, metric='haversine')
    df_lp['_cluster'] = clustering.fit_predict(coords)

    # Analyze each cluster
    for cluster_id in sorted(df_lp['_cluster'].unique()):
        if cluster_id == -1:
            continue  # noise

        cluster_data = df_lp[df_lp['_cluster'] == cluster_id]
        hours = cluster_data['_dt'].dt.hour

        # Classify by time pattern
        night_pct = ((hours >= 22) | (hours <= 6)).sum() / len(hours) * 100
        day_pct = hours.between(8, 18).sum() / len(hours) * 100

        if night_pct >= 50:
            cluster_type = 'home'
            cluster_label = 'Casa (provável)'
        elif day_pct >= 60:
            cluster_type = 'work'
            cluster_label = 'Trabalho (provável)'
        else:
            cluster_type = 'other'
            cluster_label = 'Local frequentado'

        # Get representative city
        city = ''
        if 'Ip_Cidade' in cluster_data.columns:
            cities = cluster_data['Ip_Cidade'].dropna().value_counts()
            if not cities.empty:
                city = cities.index[0]

        provider = ''
        if 'Ip_Dono' in cluster_data.columns:
            provs = cluster_data['Ip_Dono'].dropna().value_counts()
            if not provs.empty:
                provider = provs.index[0]

        result['clusters'].append({
            'id': int(cluster_id),
            'label': cluster_label,
            'type': cluster_type,
            'lat': float(cluster_data[lat_col].mean()),
            'lon': float(cluster_data[lon_col].mean()),
            'city': city,
            'region': cluster_data['Ip_Regiao'].mode().iloc[0] if 'Ip_Regiao' in cluster_data.columns and not cluster_data['Ip_Regiao'].mode().empty else '',
            'count': len(cluster_data),
            'provider': provider,
            'hours_distribution': {
                'night': round(night_pct, 1),
                'day': round(day_pct, 1),
                'other': round(100 - night_pct - day_pct, 1),
            },
            'first_seen': cluster_data['_dt'].min().strftime('%Y-%m-%d'),
            'last_seen': cluster_data['_dt'].max().strftime('%Y-%m-%d'),
        })

    # Detect routine deviations (noise points = out of pattern)
    noise = df_lp[df_lp['_cluster'] == -1]
    if len(noise) > 0 and len(result['clusters']) > 0:
        for _, row in noise.iterrows():
            result['routine_deviations'].append({
                'ip': row.get('Ip', row.get('Sender IP', '')),
                'date': row['_dt'].strftime('%Y-%m-%d %H:%M'),
                'city': row.get('Ip_Cidade', ''),
                'lat': float(row[lat_col]),
                'lon': float(row[lon_col]),
            })
        result['routine_deviations'] = result['routine_deviations'][:20]

    return result


# ============================================================
# 29. TRAVEL PATTERN DETECTION
# ============================================================
def detect_travel_pattern(df, date_col='Data', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Detect city-to-city travel sequences over time.
    Returns list of dicts with travel segments.
    """
    df_t = df.copy()
    df_t[lat_col] = pd.to_numeric(df_t[lat_col], errors='coerce')
    df_t[lon_col] = pd.to_numeric(df_t[lon_col], errors='coerce')
    df_t['_dt'] = pd.to_datetime(df_t[date_col], errors='coerce')
    df_t = df_t.dropna(subset=[lat_col, lon_col, '_dt'])
    df_t = df_t[(df_t[lat_col] != 0) | (df_t[lon_col] != 0)]
    df_t = df_t.sort_values('_dt')

    if len(df_t) < 2 or 'Ip_Cidade' not in df_t.columns:
        return []

    segments = []
    prev_city = None
    prev_dt = None
    prev_lat = prev_lon = 0.0

    for _, row in df_t.iterrows():
        city = row.get('Ip_Cidade', '')
        if not city or pd.isna(city):
            continue
        if prev_city and city != prev_city:
            R = 6371
            dlat = np.radians(row[lat_col] - prev_lat)
            dlon = np.radians(row[lon_col] - prev_lon)
            a = np.sin(dlat/2)**2 + np.cos(np.radians(prev_lat)) * \
                np.cos(np.radians(row[lat_col])) * np.sin(dlon/2)**2
            dist = R * 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
            delta_h = (row['_dt'] - prev_dt).total_seconds() / 3600 if prev_dt else 0

            segments.append({
                'De': prev_city,
                'Para': city,
                'Data_Saida': prev_dt.strftime('%Y-%m-%d %H:%M') if prev_dt else '',
                'Data_Chegada': row['_dt'].strftime('%Y-%m-%d %H:%M'),
                'Distancia_km': round(dist, 1),
                'Tempo_h': round(delta_h, 1),
            })

        prev_city = city
        prev_dt = row['_dt']
        prev_lat = float(row[lat_col])
        prev_lon = float(row[lon_col])

    return segments


def compute_geo_precision(row):
    """
    Calcula indicador de precisão da geolocalização para um IP.
    Retorna dict com precision_level e precision_label.
    """
    is_mobile = str(row.get('Ip_Movel', '')).lower() == 'true'
    is_proxy = str(row.get('Ip_Proxy', '')).lower() == 'true'
    is_hosting = str(row.get('Ip_Hospedagem', '')).lower() == 'true'
    ip = str(row.get('Ip', ''))
    is_v6 = ':' in ip

    if is_proxy:
        return {'precision': 'Baixa', 'icon': '🔴', 'reason': 'Proxy/VPN — localização mascarada'}
    if is_hosting:
        return {'precision': 'Baixa', 'icon': '🟠', 'reason': 'Datacenter — localização do servidor, não do usuário'}
    if is_mobile and not is_v6:
        return {'precision': 'Média', 'icon': '🟡', 'reason': 'Móvel IPv4 — pode apontar central da operadora (CGNAT)'}
    if is_mobile and is_v6:
        return {'precision': 'Alta', 'icon': '🟢', 'reason': 'Móvel IPv6 — boa precisão geográfica'}
    if is_v6:
        return {'precision': 'Alta', 'icon': '🟢', 'reason': 'IPv6 residencial — boa precisão'}
    return {'precision': 'Média', 'icon': '🟡', 'reason': 'IPv4 residencial — precisão ~80% a nível de cidade'}


