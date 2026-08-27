"""analysis.geo — split from analysis monolith."""
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)
from analysis._config import _analysis_config
from analysis.movement import detect_base_locations
from validators import as_bool

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


# Teto de coordenadas distintas enviadas ao DBSCAN. Acima disto as coordenadas
# são arredondadas (e o arredondamento é reportado no relatório, nunca silencioso).
MAX_UNIQUE_COORDS = 20000
# Máximo de desvios de rotina listados; o total real é sempre reportado à parte.
MAX_DEVIATIONS = 20


def detect_life_patterns(df, date_col='Data', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Detecta padrões de vida usando DBSCAN clustering geoespacial.
    Identifica automaticamente locais frequentados (casa, trabalho, lazer).

    O clustering é feito sobre as coordenadas DISTINTAS, com `sample_weight`
    igual ao número de registros em cada coordenada. Isso é matematicamente
    equivalente a clusterizar todos os registros: pontos duplicados estão a
    distância 0 entre si, portanto sempre dentro da vizinhança-eps um do outro,
    e o sklearn define núcleo por `soma(sample_weight[vizinhos]) >= min_samples`.
    Nenhum registro é descartado e `min_samples` não precisa de ajuste.

    A geolocalização por IP produz poucas coordenadas distintas (ordem de
    dezenas para milhares de IPs), enquanto o DBSCAN tem custo de memória
    O(n^2): sem esta agregação, um dataset de 200k linhas esgota a memória.

    Efeito colateral positivo: pontos de fronteira entre dois clusters deixam de
    ser atribuídos conforme a ordem de iteração, removendo uma não-determinação
    do DBSCAN clássico.

    Returns:
        dict com clusters, classificação e desvios de rotina.
    """
    _lp_config = _analysis_config.get('life_pattern', {})
    eps_km = _lp_config.get('dbscan_eps_km', 5.0)
    min_samples = _lp_config.get('dbscan_min_samples', 3)

    result = {
        'clusters': [],
        'routine_deviations': [],
        'routine_deviations_total': 0,
        'routine_deviations_truncated': False,
        'coord_precision_note': '',
        'has_data': False,
    }

    if df is None or len(df) == 0 or lat_col not in df.columns or lon_col not in df.columns:
        return result

    # Projeção estreita: copiar o DataFrame inteiro custa centenas de MB em
    # datasets grandes, e só estas colunas são usadas aqui.
    work = pd.DataFrame({
        'lat': pd.to_numeric(df[lat_col], errors='coerce').values,
        'lon': pd.to_numeric(df[lon_col], errors='coerce').values,
        '_dt': pd.to_datetime(df[date_col], errors='coerce').values
        if date_col in df.columns else pd.NaT,
    })
    for extra in ('Ip', 'Sender IP', 'Ip_Cidade', 'Ip_Dono', 'Ip_Regiao'):
        if extra in df.columns:
            work[extra] = df[extra].values

    work = work.dropna(subset=['lat', 'lon', '_dt'])
    work = work[(work['lat'] != 0) | (work['lon'] != 0)]

    if len(work) < min_samples:
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

    # -- Agrega para coordenadas distintas (sort=True garante determinismo) --
    uniq = work.groupby(['lat', 'lon'], sort=True).size().reset_index(name='_w')
    n_unique_original = len(uniq)
    result['n_rows'] = int(len(work))
    result['n_unique_coords'] = int(n_unique_original)

    # Segunda barreira: se ainda assim houver coordenadas distintas demais para
    # o custo O(n^2) do DBSCAN, arredonda -- e informa a precisão ao analista.
    if n_unique_original > MAX_UNIQUE_COORDS:
        for decimals, metros in ((4, '~11 m'), (3, '~110 m'), (2, '~1,1 km')):
            work['lat'] = work['lat'].round(decimals)
            work['lon'] = work['lon'].round(decimals)
            uniq = work.groupby(['lat', 'lon'], sort=True).size().reset_index(name='_w')
            result['coord_precision_note'] = (
                'Coordenadas arredondadas a {} casas decimais ({}) para viabilizar a '
                'clusterização de {} coordenadas distintas.'.format(
                    decimals, metros, '{:,}'.format(n_unique_original).replace(',', '.'))
            )
            if len(uniq) <= MAX_UNIQUE_COORDS:
                break
        logger.info("detect_life_patterns: %d coordenadas distintas reduzidas para %d",
                    n_unique_original, len(uniq))

    logger.info("detect_life_patterns: DBSCAN sobre %d coordenadas distintas (%d registros)",
                len(uniq), len(work))

    coords = np.radians(uniq[['lat', 'lon']].to_numpy())
    eps_rad = eps_km / 6371.0  # Earth radius

    clustering = DBSCAN(eps=eps_rad, min_samples=min_samples, metric='haversine')
    uniq['_cluster'] = clustering.fit_predict(coords, sample_weight=uniq['_w'].to_numpy())

    # Rótulos de volta às linhas: as estatísticas por cluster devem ser
    # ponderadas por ocorrência, não por coordenada.
    work = work.merge(uniq[['lat', 'lon', '_cluster']], on=['lat', 'lon'], how='left')

    # Analyze each cluster
    for cluster_id in sorted(work['_cluster'].dropna().unique()):
        if cluster_id == -1:
            continue  # noise

        cluster_data = work[work['_cluster'] == cluster_id]
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
            'lat': float(cluster_data['lat'].mean()),
            'lon': float(cluster_data['lon'].mean()),
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

    # Detect routine deviations (noise points = out of pattern).
    # O total real é reportado à parte: exibir apenas a lista truncada como se
    # fosse o total seria uma afirmação incorreta num documento pericial.
    noise = work[work['_cluster'] == -1]
    result['routine_deviations_total'] = int(len(noise))
    if len(noise) > 0 and len(result['clusters']) > 0:
        head = noise.sort_values('_dt').head(MAX_DEVIATIONS)
        ip_key = 'Ip' if 'Ip' in head.columns else ('Sender IP' if 'Sender IP' in head.columns else None)
        for _, row in head.iterrows():
            ip_val = row[ip_key] if ip_key else ''
            city_val = row['Ip_Cidade'] if 'Ip_Cidade' in head.columns else ''
            result['routine_deviations'].append({
                'ip': '' if pd.isna(ip_val) else str(ip_val),
                'date': row['_dt'].strftime('%Y-%m-%d %H:%M'),
                'city': '' if pd.isna(city_val) else str(city_val),
                'lat': float(row['lat']),
                'lon': float(row['lon']),
            })
        result['routine_deviations_truncated'] = len(noise) > MAX_DEVIATIONS

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
    is_mobile = as_bool(row.get('Ip_Movel'), field='Ip_Movel')
    is_proxy = as_bool(row.get('Ip_Proxy'), field='Ip_Proxy')
    is_hosting = as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem')
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


