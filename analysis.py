"""
Log Enrichment - Analysis Module
Advanced analysis functions: risk scoring, time patterns, geofencing,
cross-target correlation, disposable number detection, KML export, folder scanning.
"""

import pandas as pd
import numpy as np
import os
import json
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ============================================================
# LOAD EXTERNAL CONFIGURATION
# ============================================================

_CONFIG_DIR = os.path.dirname(__file__)

def _load_json_config(filename, default=None):
    """Carrega configuração JSON externa com fallback."""
    filepath = os.path.join(_CONFIG_DIR, filename)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Erro ao carregar {filename}: {e}")
    return default or {}

_providers_config = _load_json_config('infrastructure_providers.json')
_analysis_config = _load_json_config('analysis_config.json')


# ============================================================
# 24. INFRASTRUCTURE CLASSIFICATION (Datacenter/VPN vs Cloud vs Normal)
# ============================================================

# Carrega keywords de arquivo externo (editável sem alterar código)
DATACENTER_VPN_KEYWORDS = _providers_config.get('datacenter_vpn_keywords', [
    'datacamp', 'hostroyal', 'ovh', 'hetzner', 'leaseweb', 'digitalocean',
    'linode', 'vultr', 'choopa', 'm247', 'worldstream', 'contabo',
    'scaleway', 'servers.com', 'cherry servers', 'alexhost', 'hostdime',
    'iqweb', 'iq pl', 'gthost', 'hostzealot', 'cdn77',
    'mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
    'privadovpn', 'protonvpn', 'ipvanish', 'hidemyass', 'pia ',
    'private internet access', 'torguard', 'windscribe',
    'psychz', 'quadranet', 'colocrossing', 'buyvm', 'ramnode',
    'hostwinds', 'hostkey', 'blazingfast', 'sharktech', 'reliablesite',
    'nocix', 'combahton', 'flokinet', '1gservers', 'serverius',
    'xserver', 'vpn', 'proxy', 'tor exit', 'tor relay',
    'tzulo', 'frantech', 'privatelayer', 'incloudzone',
    'ponynet', 'emerald onion', 'calyx institute',
    'path.net', 'arelion', 'zayo', 'he.net', 'hurricane electric',
])

CLOUD_KEYWORDS = _providers_config.get('cloud_keywords', [
    'amazon', 'aws', 'ec2', 'cloudfront', 'amazonaws',
    'google cloud', 'google llc', 'gcp',
    'microsoft azure', 'microsoft corporation',
    'alibaba cloud', 'alicloud', 'aliyun',
    'oracle cloud', 'oracle corporation',
    'tencent cloud', 'tencent',
    'ibm cloud', 'softlayer',
    'rackspace', 'cloudflare', 'fastly', 'akamai',
    'heroku', 'vercel', 'netlify', 'railway',
    'huawei cloud',
])


def classify_infrastructure(row):
    """
    Classify an IP's infrastructure type based on ASN and provider name.

    Returns dict with:
        - category: 'datacenter_vpn' | 'cloud' | 'hosting' | 'proxy' | 'mobile' | 'normal'
        - label: Human-readable label
        - color: Hex color for map visualization
        - icon: Emoji icon
        - alert: Whether to show alert
    """
    is_proxy = str(row.get('Ip_Proxy', False)).lower() == 'true'
    is_hosting = str(row.get('Ip_Hospedagem', False)).lower() == 'true'
    is_mobile = str(row.get('Ip_Movel', False)).lower() == 'true'

    asn = str(row.get('Ip_AS', '')).lower()
    provider = str(row.get('Ip_Dono', '')).lower()
    combined = f"{asn} {provider}"

    # 1. Proxy/VPN flag from API takes priority
    if is_proxy:
        return {
            'category': 'proxy',
            'label': 'Proxy / VPN / Tor',
            'color': '#dc2626',
            'circle_color': '#ef4444',
            'icon': '🛡️',
            'alert': True,
        }

    # 2. Check datacenter/VPN keywords in ASN or provider
    for kw in DATACENTER_VPN_KEYWORDS:
        if kw in combined:
            return {
                'category': 'datacenter_vpn',
                'label': 'Datacenter / VPN',
                'color': '#b91c1c',
                'circle_color': '#f87171',
                'icon': '🏢',
                'alert': True,
            }

    # 3. Check cloud provider keywords
    for kw in CLOUD_KEYWORDS:
        if kw in combined:
            return {
                'category': 'cloud',
                'label': 'Cloud Pública',
                'color': '#d97706',
                'circle_color': '#f59e0b',
                'icon': '☁️',
                'alert': False,
            }

    # 4. Hosting flag from API (not matched above)
    if is_hosting:
        return {
            'category': 'hosting',
            'label': 'Hospedagem',
            'color': '#c2410c',
            'circle_color': '#f97316',
            'icon': '🖥️',
            'alert': False,
        }

    # 5. Mobile
    if is_mobile:
        return {
            'category': 'mobile',
            'label': 'Rede Móvel',
            'color': '#2563eb',
            'circle_color': '#3b82f6',
            'icon': '📱',
            'alert': False,
        }

    # 6. Residencial / Normal
    return {
        'category': 'normal',
        'label': 'Residencial',
        'color': '#16a34a',
        'circle_color': '#22c55e',
        'icon': '🏠',
        'alert': False,
    }


def format_reputacao(row):
    """Return a formatted infrastructure label for display and export."""
    classification = classify_infrastructure(row)
    return f"{classification['icon']} {classification['label']}"


def classify_dataframe(df):
    """
    Add infrastructure classification columns to a DataFrame.
    Adds: _infra_category, _infra_label, _infra_color, _infra_icon, _infra_alert
    """
    if df.empty:
        return df

    classifications = df.apply(classify_infrastructure, axis=1)
    df = df.copy()
    df['_infra_category'] = classifications.apply(lambda x: x['category'])
    df['_infra_label'] = classifications.apply(lambda x: x['label'])
    df['_infra_color'] = classifications.apply(lambda x: x['circle_color'])
    df['_infra_icon'] = classifications.apply(lambda x: x['icon'])
    df['_infra_alert'] = classifications.apply(lambda x: x['alert'])
    return df


# ============================================================
# 3. CACHE BACKUP
# ============================================================
def backup_cache(cache_file='ip_cache.json', backup_dir='cache_backups', max_backups=10):
    """Create a timestamped backup of the IP cache file."""
    if not os.path.exists(cache_file):
        return None

    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f'ip_cache_{timestamp}.json')
    shutil.copy2(cache_file, backup_path)

    # Rotate: keep only max_backups
    backups = sorted(glob.glob(os.path.join(backup_dir, 'ip_cache_*.json')))
    while len(backups) > max_backups:
        os.remove(backups.pop(0))

    return backup_path


# ============================================================
# 4. CROSS-TARGET CORRELATION
# ============================================================
def cross_target_correlation(dataframes_dict):
    """
    Find common IPs between multiple targets.

    Args:
        dataframes_dict: dict of {target_name: DataFrame} where DataFrame has 'Ip' or 'Sender IP' column

    Returns:
        DataFrame with common IPs and the targets they appear in
    """
    ip_targets = {}  # ip -> set of targets

    for target, df in dataframes_dict.items():
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
        if ip_col not in df.columns:
            continue
        for ip in df[ip_col].dropna().unique():
            if ip not in ip_targets:
                ip_targets[ip] = set()
            ip_targets[ip].add(target)

    # Filter to IPs appearing in 2+ targets
    common = {ip: targets for ip, targets in ip_targets.items() if len(targets) >= 2}

    if not common:
        return pd.DataFrame(columns=['IP', 'Alvos', 'Num_Alvos'])

    rows = []
    for ip, targets in sorted(common.items(), key=lambda x: len(x[1]), reverse=True):
        # Get provider info from first available df
        provider = ''
        city = ''
        for t in targets:
            df = dataframes_dict[t]
            ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
            match = df[df[ip_col] == ip]
            if not match.empty:
                provider = match.iloc[0].get('Ip_Dono', '') or ''
                city = match.iloc[0].get('Ip_Cidade', '') or ''
                break
        rows.append({
            'IP': ip,
            'Alvos': ', '.join(sorted(targets)),
            'Num_Alvos': len(targets),
            'Provedor': provider,
            'Cidade': city
        })

    return pd.DataFrame(rows)


# ============================================================
# 5. TIME PATTERN ANALYSIS
# ============================================================
def analyze_time_patterns(df, date_col='Data'):
    """
    Analyze temporal patterns: hourly distribution, most active hours,
    day-of-week patterns, and routine detection.

    Returns dict with analysis results.
    """
    result = {
        'hourly_counts': None,
        'weekday_counts': None,
        'most_active_hours': [],
        'most_active_days': [],
        'routine_score': 0,
        'activity_gaps': []
    }

    if date_col not in df.columns:
        return result

    df_t = df.copy()
    df_t['_dt'] = pd.to_datetime(df_t[date_col], errors='coerce')
    df_t = df_t.dropna(subset=['_dt'])

    if df_t.empty:
        return result

    df_t['_hour'] = df_t['_dt'].dt.hour
    df_t['_weekday'] = df_t['_dt'].dt.day_name()

    # Hourly distribution
    hourly = df_t['_hour'].value_counts().sort_index()
    result['hourly_counts'] = hourly

    # Most active hours (top 5)
    result['most_active_hours'] = hourly.nlargest(5).index.tolist()

    # Weekday distribution
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    weekday = df_t['_weekday'].value_counts()
    weekday = weekday.reindex(day_order).fillna(0)
    result['weekday_counts'] = weekday

    # Most active days
    result['most_active_days'] = weekday.nlargest(3).index.tolist()

    # Routine score (0-100): high if activity is concentrated in few hours
    if len(hourly) > 0:
        total = hourly.sum()
        top3_pct = hourly.nlargest(3).sum() / total if total > 0 else 0
        result['routine_score'] = round(top3_pct * 100, 1)

    # Activity gaps (days without activity)
    if len(df_t) > 1:
        days_active = df_t['_dt'].dt.date.unique()
        if len(days_active) > 1:
            all_days = pd.date_range(min(days_active), max(days_active)).date
            gaps = [d for d in all_days if d not in days_active]
            result['activity_gaps'] = [str(g) for g in gaps[:20]]

    return result


# ============================================================
# 6. GEOFENCING
# ============================================================
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


# ============================================================
# 8. IP RISK SCORE
# ============================================================
def calculate_risk_scores(df, ip_col='Ip'):
    """
    Calculate risk score (0-100) for each unique IP based on:
    - Proxy/VPN flag (+40)
    - Hosting flag (+25)
    - Unusual location (+20)
    - Low frequency (+10)
    - Mobile flag (-5, less risky)

    Returns DataFrame with IP, score, and breakdown.
    """
    if ip_col not in df.columns:
        return pd.DataFrame(columns=['IP', 'Score', 'Fatores'])

    # Get main city
    main_city = ''
    if 'Ip_Cidade' in df.columns:
        cities = df['Ip_Cidade'].value_counts()
        if len(cities) > 0:
            main_city = cities.index[0]

    ip_data = []
    for ip in df[ip_col].dropna().unique():
        mask = df[ip_col] == ip
        rows = df[mask]
        row = rows.iloc[0]

        score = 0
        factors = []

        is_proxy = row.get('Ip_Proxy', False)
        is_hosting = row.get('Ip_Hospedagem', False)
        is_mobile = row.get('Ip_Movel', False)
        city = row.get('Ip_Cidade', '')

        if is_proxy:
            score += 40
            factors.append('Proxy/VPN (+40)')
        if is_hosting:
            score += 25
            factors.append('Hosting (+25)')
        if main_city and pd.notna(city) and city != main_city:
            score += 20
            factors.append(f'Local incomum (+20)')
        if len(rows) <= 2:
            score += 10
            factors.append('Baixa frequência (+10)')
        if is_mobile:
            score -= 5
            factors.append('Móvel (-5)')

        score = max(0, min(100, score))

        ip_data.append({
            'IP': ip,
            'Score': score,
            'Fatores': '; '.join(factors) if factors else 'Residencial',
            'Provedor': row.get('Ip_Dono', ''),
            'Cidade': row.get('Ip_Cidade', ''),
            'Ocorrencias': len(rows)
        })

    result = pd.DataFrame(ip_data)
    if not result.empty:
        result = result.sort_values('Score', ascending=False)
    return result


# ============================================================
# 12. DISPOSABLE NUMBER DETECTION
# ============================================================
def detect_disposable_numbers(df, from_col='FROM', date_col='Data', min_appearances=1, max_appearances=3):
    """
    Detect contacts that appear very few times (potentially disposable numbers).

    Returns DataFrame with suspicious numbers.
    """
    if from_col not in df.columns:
        return pd.DataFrame(columns=['Numero', 'Aparicoes', 'Primeiro_Contato', 'Ultimo_Contato', 'Duracao_Dias'])

    counts = df[from_col].value_counts()
    suspicious = counts[(counts >= min_appearances) & (counts <= max_appearances)]

    if suspicious.empty:
        return pd.DataFrame(columns=['Numero', 'Aparicoes', 'Primeiro_Contato', 'Ultimo_Contato', 'Duracao_Dias'])

    rows = []
    for number, count in suspicious.items():
        if not number or str(number).strip() == '':
            continue
        subset = df[df[from_col] == number]

        first = ''
        last = ''
        duration = 0
        if date_col in subset.columns:
            dates = pd.to_datetime(subset[date_col], errors='coerce').dropna()
            if not dates.empty:
                first = dates.min().strftime('%Y-%m-%d %H:%M')
                last = dates.max().strftime('%Y-%m-%d %H:%M')
                duration = (dates.max() - dates.min()).days

        types = ', '.join(subset['type'].unique().tolist()) if 'type' in subset.columns else ''

        rows.append({
            'Numero': number,
            'Aparicoes': count,
            'Primeiro_Contato': first,
            'Ultimo_Contato': last,
            'Duracao_Dias': duration,
            'Tipos': types
        })

    return pd.DataFrame(rows).sort_values('Aparicoes')


# ============================================================
# 15. KML EXPORT
# ============================================================
def export_kml_animated(df, ip_col='Ip', lat_col='Ip_Lat', lon_col='Ip_Lon', date_col='Data'):
    """
    4.3 — Export KML com timestamps para animação temporal no Google Earth Pro.
    Inclui rota temporal (LineString) conectando pontos em ordem cronológica.
    """
    import simplekml

    kml = simplekml.Kml(name='Log Enrichment - Rota Temporal')

    df_kml = df.copy()
    df_kml[lat_col] = pd.to_numeric(df_kml[lat_col], errors='coerce')
    df_kml[lon_col] = pd.to_numeric(df_kml[lon_col], errors='coerce')
    df_kml['_dt'] = pd.to_datetime(df_kml.get(date_col, pd.Series(dtype='object')),
                                    format='mixed', errors='coerce')
    df_kml = df_kml.dropna(subset=[lat_col, lon_col, '_dt'])
    df_kml = df_kml[(df_kml[lat_col] != 0) | (df_kml[lon_col] != 0)]
    df_kml = df_kml.sort_values('_dt')

    if df_kml.empty:
        return kml.kml()

    # Folder: Pontos com timestamp
    folder = kml.newfolder(name='IPs Geolocalizados')
    coords_for_line = []

    for _, row in df_kml.iterrows():
        ip = str(row.get(ip_col, 'N/A'))
        lat, lon = row[lat_col], row[lon_col]
        dt = row['_dt']

        pnt = folder.newpoint(name=ip)
        pnt.coords = [(lon, lat)]
        pnt.timestamp.when = dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        desc_parts = [f"IP: {ip}"]
        if pd.notna(row.get('Ip_Dono')):
            desc_parts.append(f"Provedor: {row['Ip_Dono']}")
        if pd.notna(row.get('Ip_Cidade')):
            desc_parts.append(f"Cidade: {row['Ip_Cidade']}")
        desc_parts.append(f"Data: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        pnt.description = '\n'.join(desc_parts)

        is_proxy = str(row.get('Ip_Proxy', '')).lower() == 'true'
        is_hosting = str(row.get('Ip_Hospedagem', '')).lower() == 'true'
        if is_proxy:
            pnt.style.iconstyle.color = simplekml.Color.red
        elif is_hosting:
            pnt.style.iconstyle.color = simplekml.Color.orange
        else:
            pnt.style.iconstyle.color = simplekml.Color.green

        coords_for_line.append((lon, lat, 0))

    # Rota temporal (LineString)
    if len(coords_for_line) >= 2:
        route = kml.newlinestring(name='Rota Temporal')
        route.coords = coords_for_line
        route.style.linestyle.color = simplekml.Color.changealphaint(180, simplekml.Color.cyan)
        route.style.linestyle.width = 3

    return kml.kml()


def export_kml(df, ip_col='Ip', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Export IP locations as KML for Google Earth.

    Returns KML content as string.
    """
    import simplekml

    kml = simplekml.Kml(name='Log Enrichment - IP Locations')

    df_kml = df.copy()
    df_kml[lat_col] = pd.to_numeric(df_kml[lat_col], errors='coerce')
    df_kml[lon_col] = pd.to_numeric(df_kml[lon_col], errors='coerce')
    df_kml = df_kml.dropna(subset=[lat_col, lon_col])
    df_kml = df_kml[(df_kml[lat_col] != 0) | (df_kml[lon_col] != 0)]

    for _, row in df_kml.iterrows():
        ip = row.get(ip_col, 'N/A')
        pnt = kml.newpoint(name=str(ip))
        pnt.coords = [(row[lon_col], row[lat_col])]

        desc_parts = []
        if 'Ip_Dono' in row and pd.notna(row.get('Ip_Dono')):
            desc_parts.append(f"Provedor: {row['Ip_Dono']}")
        if 'Ip_Cidade' in row and pd.notna(row.get('Ip_Cidade')):
            desc_parts.append(f"Cidade: {row['Ip_Cidade']}")
        if 'Data' in row and pd.notna(row.get('Data')):
            desc_parts.append(f"Data: {row['Data']}")

        pnt.description = '\n'.join(desc_parts)

        # Color by type
        is_proxy = row.get('Ip_Proxy', False)
        is_hosting = row.get('Ip_Hospedagem', False)
        is_mobile = row.get('Ip_Movel', False)

        if is_proxy:
            pnt.style.iconstyle.color = simplekml.Color.red
        elif is_hosting:
            pnt.style.iconstyle.color = simplekml.Color.orange
        elif is_mobile:
            pnt.style.iconstyle.color = simplekml.Color.blue
        else:
            pnt.style.iconstyle.color = simplekml.Color.green

    return kml.kml()


# ============================================================
# 18. FOLDER SCANNING
# ============================================================
def scan_folder_for_logs(folder_path, extensions=None):
    """
    Scan a folder for log files to process.

    Returns list of file paths found.
    """
    if not folder_path or not os.path.isdir(folder_path):
        return []

    if extensions is None:
        extensions = ['.txt', '.csv', '.xlsx', '.xls', '.html', '.zip']

    files = []
    for f in os.listdir(folder_path):
        full_path = os.path.join(folder_path, f)
        if os.path.isfile(full_path):
            ext = os.path.splitext(f)[1].lower()
            if ext in extensions:
                files.append(full_path)

    return sorted(files)


# ============================================================
# 19. IMPOSSIBLE JUMP DETECTION (speed anomaly)
# ============================================================
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
        # Cluster by rounded coords (city-level)
        subset = subset.copy()
        subset['_loc'] = subset.apply(
            lambda r: f"{round(r[lat_col], 2)},{round(r[lon_col], 2)}", axis=1)
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
def compare_periods(df, date_col='Data', split_date=None):
    """
    Compare two time periods of the same target.
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
    except Exception:
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


# ============================================================
# 25. ADVANCED VPN/PROXY DETECTION (Heuristic-based)
# ============================================================

_vpn_config = _analysis_config.get('vpn_detection', {})

def detect_vpn_heuristics(df, date_col='Data'):
    """
    Detecção avançada de VPN/proxy usando heurísticas comportamentais.
    Detecta padrões que APIs de geolocalização não identificam.

    Returns:
        dict com indicadores e score de confiança (0-100) de uso de VPN.
    """
    result = {
        'score': 0,
        'indicators': {},
        'suspicious_ips': [],
    }

    if df.empty:
        return result

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    if ip_col not in df.columns:
        return result

    df_work = df.copy()
    df_work['_dt'] = pd.to_datetime(df_work.get(date_col, pd.Series(dtype='object')), errors='coerce')
    df_work = df_work.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_work) < 2:
        return result

    score = 0

    # 1. IP Rotation Detection — IPs that change at regular intervals
    rotation_interval_min = _vpn_config.get('rotation_interval_minutes', 30)
    min_rotation_count = _vpn_config.get('min_rotation_count', 3)
    ip_changes = []
    prev_ip = None
    for _, row in df_work.iterrows():
        cur_ip = row[ip_col]
        if prev_ip and cur_ip != prev_ip:
            ip_changes.append(row['_dt'])
        prev_ip = cur_ip

    if len(ip_changes) >= min_rotation_count:
        # Check if intervals are suspiciously regular
        intervals = [(ip_changes[i+1] - ip_changes[i]).total_seconds() / 60
                      for i in range(len(ip_changes) - 1)]
        if intervals:
            avg_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            # Low std relative to mean = regular rotation (VPN)
            if avg_interval > 0 and std_interval / avg_interval < 0.3:
                score += 25
                result['indicators']['Rotação regular'] = (
                    f"⚠️ IPs mudam a cada ~{avg_interval:.0f}min (desvio: {std_interval:.0f}min)"
                )

    # 2. ASN Diversity — too many different ASNs for one user
    max_asn_diversity = _vpn_config.get('max_asn_diversity', 5)
    if 'Ip_AS' in df_work.columns:
        asns = df_work['Ip_AS'].dropna().nunique()
        if asns > max_asn_diversity:
            score += 20
            result['indicators']['Diversidade ASN'] = (
                f"⚠️ {asns} ASNs distintos (limite normal: {max_asn_diversity})"
            )
        elif asns > 3:
            score += 10
            result['indicators']['Diversidade ASN'] = f"⚠️ {asns} ASNs distintos"

    # 3. Residential IP jump — same user, different residential IPs in different countries within short time
    residential_jump_hours = _vpn_config.get('residential_jump_hours', 1)
    if 'Ip_Pais' in df_work.columns and 'Ip_Proxy' in df_work.columns:
        # Filter to non-proxy, non-hosting IPs (residential)
        residential = df_work[
            ~df_work['Ip_Proxy'].apply(lambda x: str(x).lower() == 'true') &
            ~df_work.get('Ip_Hospedagem', pd.Series(False, index=df_work.index)).apply(lambda x: str(x).lower() == 'true')
        ]
        if len(residential) >= 2:
            prev_row = None
            for _, row in residential.iterrows():
                if prev_row is not None:
                    time_diff_h = abs((row['_dt'] - prev_row['_dt']).total_seconds()) / 3600
                    if (time_diff_h <= residential_jump_hours and
                            row.get('Ip_Pais') != prev_row.get('Ip_Pais') and
                            pd.notna(row.get('Ip_Pais')) and pd.notna(prev_row.get('Ip_Pais'))):
                        score += 30
                        result['indicators']['Salto residencial'] = (
                            f"🔴 IPs residenciais em {prev_row.get('Ip_Pais')} → "
                            f"{row.get('Ip_Pais')} em {time_diff_h:.1f}h"
                        )
                        result['suspicious_ips'].extend([
                            str(prev_row.get(ip_col, '')),
                            str(row.get(ip_col, ''))
                        ])
                        break
                prev_row = row

    # 4. Provider mix — residential + datacenter from same "user"
    if 'Ip_Hospedagem' in df_work.columns:
        hosting_count = df_work['Ip_Hospedagem'].apply(lambda x: str(x).lower() == 'true').sum()
        total = len(df_work)
        if total > 0:
            hosting_pct = hosting_count / total * 100
            if 10 < hosting_pct < 80:
                score += 15
                result['indicators']['Mix infraestrutura'] = (
                    f"⚠️ {hosting_pct:.0f}% hosting + {100-hosting_pct:.0f}% residencial"
                )

    result['score'] = max(0, min(100, score))
    result['suspicious_ips'] = list(set(result['suspicious_ips']))
    return result


def compute_ip_confidence(df, date_col='Data'):
    """
    Calcula score de confiança para cada IP: 'IP real' vs 'IP mascarado'.
    IPs com alta recorrência, em horários consistentes, de provedores residenciais
    recebem score alto (mais provável de ser IP real do usuário).

    Returns:
        DataFrame com IP, confidence_score (0-100), classification.
    """
    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    if ip_col not in df.columns or df.empty:
        return pd.DataFrame(columns=['IP', 'Confidence', 'Classification', 'Motivo'])

    rows = []
    for ip in df[ip_col].dropna().unique():
        mask = df[ip_col] == ip
        ip_data = df[mask]
        score = 50  # base

        motivos = []

        # Recurrence: more appearances = more likely real
        count = len(ip_data)
        if count >= 10:
            score += 20
            motivos.append(f'{count}x ocorrências')
        elif count >= 5:
            score += 10
            motivos.append(f'{count}x ocorrências')
        elif count == 1:
            score -= 15
            motivos.append('Ocorrência única')

        # Proxy/hosting flags
        is_proxy = ip_data.iloc[0].get('Ip_Proxy', False)
        is_hosting = ip_data.iloc[0].get('Ip_Hospedagem', False)
        is_mobile = ip_data.iloc[0].get('Ip_Movel', False)

        if is_proxy:
            score -= 30
            motivos.append('Flag proxy/VPN')
        if is_hosting:
            score -= 20
            motivos.append('Flag hosting')
        if is_mobile:
            score += 10
            motivos.append('Rede móvel')

        # Temporal consistency
        if date_col in ip_data.columns:
            dates = pd.to_datetime(ip_data[date_col], format='mixed', errors='coerce').dropna()
            if len(dates) >= 3:
                hours = dates.dt.hour
                hour_std = hours.std()
                if hour_std < 4:
                    score += 10
                    motivos.append('Horários consistentes')

                # Multi-day usage
                days = dates.dt.date.nunique()
                if days >= 3:
                    score += 10
                    motivos.append(f'{days} dias diferentes')

        score = max(0, min(100, score))
        classification = 'IP Real' if score >= 60 else 'Incerto' if score >= 35 else 'IP Mascarado'

        rows.append({
            'IP': ip,
            'Confidence': score,
            'Classification': classification,
            'Motivo': '; '.join(motivos),
            'Provedor': ip_data.iloc[0].get('Ip_Dono', ''),
            'Ocorrencias': count,
        })

    result = pd.DataFrame(rows)
    if not result.empty:
        result = result.sort_values('Confidence', ascending=False)
    return result


# ============================================================
# 26. LIFE PATTERN ANALYSIS (DBSCAN clustering)
# ============================================================

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


# ============================================================
# 36. SUBNET PATTERN ANALYSIS
# ============================================================

def analyze_subnet_patterns(df, ipv4_mask=24, ipv6_mask=48, ip_col=None):
    """
    Group IPs by subnet and analyze distribution patterns.
    Returns dict with subnet statistics and dominant subnets.
    """
    from ipaddress import ip_address as ipa, ip_network

    if ip_col is None:
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    if df.empty or ip_col not in df.columns:
        return {'subnets': [], 'dominant_subnets': [], 'total_subnets': 0}

    subnet_data = {}
    date_col = 'Data' if 'Data' in df.columns else None

    for _, row in df.iterrows():
        ip_str = str(row.get(ip_col, '')).strip()
        if not ip_str:
            continue
        try:
            addr = ipa(ip_str)
            mask = ipv6_mask if addr.version == 6 else ipv4_mask
            net = ip_network(f"{ip_str}/{mask}", strict=False)
            subnet_key = str(net)
        except Exception:
            continue

        if subnet_key not in subnet_data:
            subnet_data[subnet_key] = {
                'subnet': subnet_key,
                'ips': set(),
                'count': 0,
                'providers': set(),
                'cities': set(),
                'dates': [],
                'version': addr.version,
            }

        subnet_data[subnet_key]['ips'].add(ip_str)
        subnet_data[subnet_key]['count'] += 1

        prov = row.get('Ip_Dono', '')
        if prov and not pd.isna(prov):
            subnet_data[subnet_key]['providers'].add(str(prov))
        city = row.get('Ip_Cidade', '')
        if city and not pd.isna(city):
            subnet_data[subnet_key]['cities'].add(str(city))
        if date_col and date_col in row.index:
            d = row[date_col]
            if d and not pd.isna(d):
                subnet_data[subnet_key]['dates'].append(str(d))

    subnets = []
    for s in sorted(subnet_data.values(), key=lambda x: x['count'], reverse=True):
        dates = s['dates']
        date_range = None
        if dates:
            try:
                parsed = pd.to_datetime(dates, format='mixed', errors='coerce').dropna()
                if len(parsed) > 0:
                    date_range = (parsed.min().strftime('%Y-%m-%d'), parsed.max().strftime('%Y-%m-%d'))
            except Exception:
                pass

        subnets.append({
            'subnet': s['subnet'],
            'ip_count': len(s['ips']),
            'record_count': s['count'],
            'providers': sorted(s['providers']),
            'cities': sorted(s['cities']),
            'date_range': date_range,
            'version': s['version'],
        })

    dominant = subnets[:5] if subnets else []

    return {
        'subnets': subnets,
        'dominant_subnets': dominant,
        'total_subnets': len(subnets),
    }


def correlate_subnets_cross_target(dataframes_dict, ipv4_mask=24, ipv6_mask=48):
    """
    Find subnets shared between multiple targets.
    Stronger signal than exact IP match.
    """
    from ipaddress import ip_address as ipa, ip_network

    if not dataframes_dict or len(dataframes_dict) < 2:
        return []

    # Build subnet→targets mapping
    subnet_targets = {}
    for target_name, df in dataframes_dict.items():
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
        if ip_col not in df.columns:
            continue
        for ip_str in df[ip_col].dropna().unique():
            try:
                addr = ipa(str(ip_str).strip())
                mask = ipv6_mask if addr.version == 6 else ipv4_mask
                net = str(ip_network(f"{ip_str}/{mask}", strict=False))
            except Exception:
                continue
            if net not in subnet_targets:
                subnet_targets[net] = {}
            if target_name not in subnet_targets[net]:
                subnet_targets[net][target_name] = set()
            subnet_targets[net][target_name].add(str(ip_str))

    shared = []
    for subnet, targets in subnet_targets.items():
        if len(targets) >= 2:
            shared.append({
                'subnet': subnet,
                'targets': sorted(targets.keys()),
                'num_targets': len(targets),
                'ips_per_target': {t: sorted(ips) for t, ips in targets.items()},
                'total_ips': sum(len(ips) for ips in targets.values()),
            })

    return sorted(shared, key=lambda x: x['num_targets'], reverse=True)


def compute_subnet_consistency(df, ipv4_mask=24, ipv6_mask=48, ip_col=None, date_col='Data'):
    """
    Score 0-100: how consistently an IP user stays within the same subnets.
    High = stable residential. Low = VPN rotation/mobile roaming.
    """
    from ipaddress import ip_address as ipa, ip_network

    if ip_col is None:
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    if df.empty or ip_col not in df.columns:
        return {'consistency_score': 0, 'primary_subnet': '', 'subnet_changes': 0, 'total_subnets': 0}

    df_work = df.copy()
    if date_col in df_work.columns:
        df_work['_dt'] = pd.to_datetime(df_work[date_col], format='mixed', errors='coerce')
        df_work = df_work.dropna(subset=['_dt']).sort_values('_dt')

    subnets_seen = []
    for _, row in df_work.iterrows():
        ip_str = str(row.get(ip_col, '')).strip()
        if not ip_str:
            continue
        try:
            addr = ipa(ip_str)
            mask = ipv6_mask if addr.version == 6 else ipv4_mask
            net = str(ip_network(f"{ip_str}/{mask}", strict=False))
            subnets_seen.append(net)
        except Exception:
            continue

    if not subnets_seen:
        return {'consistency_score': 0, 'primary_subnet': '', 'subnet_changes': 0, 'total_subnets': 0}

    from collections import Counter
    subnet_counts = Counter(subnets_seen)
    primary_subnet = subnet_counts.most_common(1)[0][0]
    primary_pct = subnet_counts[primary_subnet] / len(subnets_seen) * 100

    # Count transitions between different subnets
    changes = sum(1 for i in range(1, len(subnets_seen)) if subnets_seen[i] != subnets_seen[i-1])
    change_rate = changes / max(len(subnets_seen) - 1, 1)

    # Score: high primary % + low change rate = high consistency
    consistency = min(100, primary_pct * 0.6 + (1 - change_rate) * 40)

    return {
        'consistency_score': round(consistency, 1),
        'primary_subnet': primary_subnet,
        'primary_pct': round(primary_pct, 1),
        'subnet_changes': changes,
        'total_subnets': len(subnet_counts),
        'top_subnets': dict(subnet_counts.most_common(5)),
    }


# ============================================================
# 37. PROVIDER TIMING FINGERPRINT
# ============================================================

def analyze_provider_timing(df, date_col='Data', min_records=5):
    """
    Per-provider temporal analysis: hourly distribution, session duration,
    usage type (always_on / scheduled / sporadic).
    Detects VPN-only hours vs residential-only hours.
    """
    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    if df.empty or date_col not in df.columns or 'Ip_Dono' not in df.columns:
        return {'providers': {}, 'transitions': [], 'vpn_schedule': {'detected': False}}

    df_work = df.copy()
    df_work['_dt'] = pd.to_datetime(df_work[date_col], format='mixed', errors='coerce')
    df_work = df_work.dropna(subset=['_dt']).sort_values('_dt')

    if df_work.empty:
        return {'providers': {}, 'transitions': [], 'vpn_schedule': {'detected': False}}

    providers = {}
    for prov, group in df_work.groupby('Ip_Dono'):
        if len(group) < min_records:
            continue

        hourly = [0] * 24
        for h in group['_dt'].dt.hour:
            hourly[h] += 1

        total = sum(hourly)
        peak_hours = sorted(range(24), key=lambda h: hourly[h], reverse=True)[:3]

        # Estimate average session duration
        times = group['_dt'].sort_values().tolist()
        session_gaps = []
        for i in range(1, len(times)):
            gap = (times[i] - times[i-1]).total_seconds() / 60
            if gap < 120:  # Same session if < 2h gap
                session_gaps.append(gap)
        avg_session = np.mean(session_gaps) if session_gaps else 0

        # Classify usage type
        active_hours = sum(1 for h in hourly if h > 0)
        if active_hours >= 16:
            usage_type = 'always_on'
        elif active_hours >= 6:
            usage_type = 'scheduled'
        else:
            usage_type = 'sporadic'

        providers[str(prov)] = {
            'hourly_dist': hourly,
            'peak_hours': peak_hours,
            'total_records': total,
            'avg_session_minutes': round(avg_session, 1),
            'active_hours': active_hours,
            'usage_type': usage_type,
        }

    # Detect VPN schedule by looking for infrastructure-classified providers
    vpn_schedule = {'detected': False}
    vpn_providers = set()
    residential_providers = set()
    for prov in providers:
        prov_rows = df_work[df_work['Ip_Dono'] == prov]
        if prov_rows.empty:
            continue
        proxy_pct = prov_rows['Ip_Proxy'].apply(lambda x: str(x).lower() == 'true').mean() if 'Ip_Proxy' in prov_rows.columns else 0
        hosting_pct = prov_rows['Ip_Hospedagem'].apply(lambda x: str(x).lower() == 'true').mean() if 'Ip_Hospedagem' in prov_rows.columns else 0
        if proxy_pct > 0.5 or hosting_pct > 0.5:
            vpn_providers.add(prov)
        else:
            residential_providers.add(prov)

    if vpn_providers and residential_providers:
        vpn_hours = set()
        res_hours = set()
        for vp in vpn_providers:
            if vp in providers:
                for h, count in enumerate(providers[vp]['hourly_dist']):
                    if count > 0:
                        vpn_hours.add(h)
        for rp in residential_providers:
            if rp in providers:
                for h, count in enumerate(providers[rp]['hourly_dist']):
                    if count > 0:
                        res_hours.add(h)
        exclusive_vpn = vpn_hours - res_hours
        if exclusive_vpn:
            vpn_schedule = {
                'detected': True,
                'vpn_hours': sorted(vpn_hours),
                'residential_hours': sorted(res_hours),
                'exclusive_vpn_hours': sorted(exclusive_vpn),
                'vpn_providers': sorted(vpn_providers),
                'residential_providers': sorted(residential_providers),
            }

    return {
        'providers': providers,
        'transitions': [],  # Populated by detect_provider_transitions
        'vpn_schedule': vpn_schedule,
    }


def detect_provider_transitions(df, date_col='Data', window_minutes=30):
    """
    Find systematic provider switches. Detect sandwich pattern A→B→A (VPN session).
    Returns dict with transition matrix and patterns.
    """
    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    if df.empty or date_col not in df.columns or 'Ip_Dono' not in df.columns:
        return {'transitions': [], 'sandwich_patterns': [], 'matrix': {}}

    df_work = df.copy()
    df_work['_dt'] = pd.to_datetime(df_work[date_col], format='mixed', errors='coerce')
    df_work = df_work.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_work) < 3:
        return {'transitions': [], 'sandwich_patterns': [], 'matrix': {}}

    providers_seq = df_work['Ip_Dono'].tolist()
    times_seq = df_work['_dt'].tolist()

    # Build transition counts
    from collections import Counter
    transitions = Counter()
    transition_hours = {}

    for i in range(1, len(providers_seq)):
        p_from = str(providers_seq[i-1])
        p_to = str(providers_seq[i])
        if p_from == p_to:
            continue
        gap_min = (times_seq[i] - times_seq[i-1]).total_seconds() / 60
        if gap_min > window_minutes * 10:  # Skip very large gaps
            continue
        key = (p_from, p_to)
        transitions[key] += 1
        if key not in transition_hours:
            transition_hours[key] = []
        transition_hours[key].append(times_seq[i].hour)

    transition_list = []
    for (p_from, p_to), count in transitions.most_common(20):
        hours = transition_hours.get((p_from, p_to), [])
        typical_hour = Counter(hours).most_common(1)[0][0] if hours else -1
        transition_list.append({
            'from': p_from,
            'to': p_to,
            'count': count,
            'typical_hour': typical_hour,
        })

    # Detect sandwich patterns: A→B→A
    sandwiches = Counter()
    for i in range(2, len(providers_seq)):
        a = str(providers_seq[i-2])
        b = str(providers_seq[i-1])
        c = str(providers_seq[i])
        if a == c and a != b:
            gap1 = (times_seq[i-1] - times_seq[i-2]).total_seconds() / 60
            gap2 = (times_seq[i] - times_seq[i-1]).total_seconds() / 60
            if gap1 < window_minutes * 10 and gap2 < window_minutes * 10:
                sandwiches[(a, b)] += 1

    sandwich_list = []
    for (base, middle), count in sandwiches.most_common(10):
        sandwich_list.append({
            'base_provider': base,
            'middle_provider': middle,
            'pattern': f"{base} → {middle} → {base}",
            'count': count,
        })

    # Build matrix
    matrix = {}
    for (p_from, p_to), count in transitions.items():
        if p_from not in matrix:
            matrix[p_from] = {}
        matrix[p_from][p_to] = count

    return {
        'transitions': transition_list,
        'sandwich_patterns': sandwich_list,
        'matrix': matrix,
    }


# ============================================================
# RE-EXPORT: advanced_analysis functions (3.1 consolidation)
# ============================================================
from advanced_analysis import (
    batch_check_abuseipdb, batch_check_virustotal,
    compute_multi_source_threat_score, compute_data_health,
    detect_relay_chains, fingerprint_device_by_ip_pattern,
    detect_shared_wifi, detect_digital_silence,
    validate_timezone_consistency,
    batch_check_shodan, compute_shodan_risk_indicators,
    detect_geo_changes,
    get_tor_exit_nodes, check_tor_exit_nodes,
)


# ============================================================
# 31. UNIFIED REPUTATION SCORE (3.2)
# ============================================================

def compute_unified_reputation(df, ip_col='Ip'):
    """
    Score de reputação unificado (0-100) combinando:
    - Risk score (proxy/hosting/location)
    - IP confidence (recorrência, consistência)
    - VPN heuristics (rotação, ASN diversity)
    Retorna DataFrame com colunas: Ip, ReputationScore, ReputationLevel, Breakdown.
    """
    if df.empty or ip_col not in df.columns:
        return pd.DataFrame(columns=[ip_col, 'ReputationScore', 'ReputationLevel', 'Breakdown'])

    # Componente 1: Risk scores (calculate_risk_scores may return 'IP' or ip_col)
    risk_df = calculate_risk_scores(df, ip_col=ip_col)
    risk_map = {}
    if not risk_df.empty and 'Score' in risk_df.columns:
        risk_key = ip_col if ip_col in risk_df.columns else ('IP' if 'IP' in risk_df.columns else None)
        if risk_key:
            risk_map = dict(zip(risk_df[risk_key], risk_df['Score']))

    # Componente 2: IP Confidence (compute_ip_confidence returns 'IP' column)
    conf_df = compute_ip_confidence(df)
    conf_map = {}
    if not conf_df.empty and 'Confidence' in conf_df.columns:
        conf_key = 'IP' if 'IP' in conf_df.columns else ip_col
        conf_map = dict(zip(conf_df[conf_key], conf_df['Confidence']))

    # Componente 3: VPN heuristics (global score, applied to all suspicious IPs)
    vpn_result = detect_vpn_heuristics(df)
    vpn_score = vpn_result.get('score', 0)
    vpn_suspicious = set(vpn_result.get('suspicious_ips', []))

    rows = []
    for ip in df[ip_col].unique():
        risk = risk_map.get(ip, 0)
        conf = conf_map.get(ip, 50)
        # Inverter confidence: alta confiança = baixo risco
        conf_risk = max(0, 100 - conf)

        # VPN bonus para IPs suspeitos
        vpn_bonus = vpn_score * 0.3 if ip in vpn_suspicious else 0

        # Score unificado: média ponderada
        unified = (risk * 0.45) + (conf_risk * 0.30) + (vpn_bonus * 0.25)
        unified = max(0, min(100, unified))

        if unified >= 75:
            level = '🔴 Crítico'
        elif unified >= 50:
            level = '🟠 Alto'
        elif unified >= 25:
            level = '🟡 Médio'
        else:
            level = '🟢 Baixo'

        rows.append({
            ip_col: ip,
            'ReputationScore': round(unified, 1),
            'ReputationLevel': level,
            'Breakdown': f"Risk:{risk:.0f} | Conf:{conf:.0f} | VPN:{vpn_bonus:.0f}",
        })

    return pd.DataFrame(rows).sort_values('ReputationScore', ascending=False)


# ============================================================
# 32. VPN TIMING ANALYSIS (3.3)
# ============================================================

def detect_vpn_timing(df, date_col='Data', max_gap_seconds=5):
    """
    Analisa timing entre IPs consecutivos para detectar VPN.
    Se um IP de datacenter é seguido por um residencial em <max_gap_seconds,
    o datacenter é provável nó VPN (mesmo pacote, roteado).
    """
    if df.empty or date_col not in df.columns:
        return {'detected': False, 'pairs': []}

    df_w = df.copy()
    df_w['_dt'] = pd.to_datetime(df_w[date_col], format='mixed', errors='coerce')
    df_w = df_w.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_w) < 2:
        return {'detected': False, 'pairs': []}

    ip_col = 'Sender IP' if 'Sender IP' in df_w.columns else 'Ip'
    pairs = []

    prev = None
    for _, row in df_w.iterrows():
        if prev is not None:
            gap_sec = abs((row['_dt'] - prev['_dt']).total_seconds())
            if gap_sec <= max_gap_seconds:
                prev_hosting = str(prev.get('Ip_Hospedagem', False)).lower() == 'true' or str(prev.get('Ip_Proxy', False)).lower() == 'true'
                curr_residential = str(row.get('Ip_Hospedagem', False)).lower() != 'true' and str(row.get('Ip_Proxy', False)).lower() != 'true'

                if prev_hosting and curr_residential and prev.get(ip_col) != row.get(ip_col):
                    pairs.append({
                        'vpn_ip': prev.get(ip_col, ''),
                        'real_ip': row.get(ip_col, ''),
                        'gap_seconds': round(gap_sec, 2),
                        'vpn_provider': prev.get('Ip_Dono', ''),
                        'real_provider': row.get('Ip_Dono', ''),
                        'timestamp': row['_dt'].strftime('%Y-%m-%d %H:%M:%S'),
                    })
        prev = row

    return {
        'detected': len(pairs) > 0,
        'pairs': pairs[:30],
        'total_pairs': len(pairs),
    }


# ============================================================
# 33. CROSS-CORRELATION WITH TEMPORAL OVERLAP (3.4)
# ============================================================

def cross_correlation_temporal(dataframes_dict, date_col='Data', window_hours=24):
    """
    Correlação cruzada entre alvos considerando sobreposição temporal.
    IPs compartilhados no mesmo dia são mais significativos que em meses diferentes.
    """
    if len(dataframes_dict) < 2:
        return pd.DataFrame()

    from collections import defaultdict
    ip_target_dates = defaultdict(lambda: defaultdict(set))

    for target, df in dataframes_dict.items():
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
        if ip_col not in df.columns or date_col not in df.columns:
            continue
        df_t = df.copy()
        df_t['_dt'] = pd.to_datetime(df_t[date_col], format='mixed', errors='coerce')
        df_t = df_t.dropna(subset=['_dt'])

        for _, row in df_t.iterrows():
            ip = row.get(ip_col)
            if pd.notna(ip):
                date_key = row['_dt'].strftime('%Y-%m-%d')
                ip_target_dates[ip][target].add(date_key)

    rows = []
    for ip, targets in ip_target_dates.items():
        if len(targets) < 2:
            continue
        target_names = sorted(targets.keys())
        # Verificar sobreposição temporal
        for i in range(len(target_names)):
            for j in range(i + 1, len(target_names)):
                t1, t2 = target_names[i], target_names[j]
                dates_1 = targets[t1]
                dates_2 = targets[t2]
                common_dates = dates_1 & dates_2
                strength = 'Forte' if len(common_dates) >= 3 else 'Média' if common_dates else 'Fraca'

                rows.append({
                    'IP': ip,
                    'Alvo_1': t1,
                    'Alvo_2': t2,
                    'Dias_Alvo1': len(dates_1),
                    'Dias_Alvo2': len(dates_2),
                    'Dias_Coincidentes': len(common_dates),
                    'Datas_Comuns': ', '.join(sorted(common_dates)[:5]),
                    'Força': strength,
                })

    result = pd.DataFrame(rows)
    if not result.empty:
        result = result.sort_values('Dias_Coincidentes', ascending=False)
    return result


# ============================================================
# 34. RESIDENTIAL VS CORPORATE DETECTION (2.3)
# ============================================================

def detect_usage_profile(df, date_col='Data'):
    """
    Detecta se o padrão de uso sugere acesso residencial ou corporativo.
    Baseado em: horários de atividade, quantidade de provedores, tipo de IP,
    consistência geográfica.

    Retorna dict com:
        - profile: 'residencial', 'corporativo', 'misto'
        - confidence: 0-100
        - indicators: lista de evidências
    """
    if df.empty:
        return {'profile': 'indeterminado', 'confidence': 0, 'indicators': []}

    df_w = df.copy()
    df_w['_dt'] = pd.to_datetime(df_w.get(date_col, pd.Series(dtype='object')),
                                  format='mixed', errors='coerce')
    df_w = df_w.dropna(subset=['_dt'])

    indicators = []
    res_score = 0  # Pontos para residencial
    corp_score = 0  # Pontos para corporativo

    # 1. Horário de atividade
    if not df_w.empty:
        hours = df_w['_dt'].dt.hour
        night_pct = ((hours < 6) | (hours >= 22)).sum() / len(hours) * 100
        business_pct = ((hours >= 8) & (hours < 18)).sum() / len(hours) * 100

        if night_pct > 30:
            res_score += 25
            indicators.append(f"📍 {night_pct:.0f}% de acessos em horário noturno (residencial)")
        if business_pct > 70:
            corp_score += 25
            indicators.append(f"🏢 {business_pct:.0f}% de acessos em horário comercial (corporativo)")

    # 2. Diversidade de provedores
    if 'Ip_Dono' in df_w.columns:
        n_providers = df_w['Ip_Dono'].nunique()
        if n_providers <= 2:
            res_score += 20
            indicators.append(f"📍 Apenas {n_providers} provedor(es) — típico residencial")
        elif n_providers >= 5:
            corp_score += 15
            indicators.append(f"🏢 {n_providers} provedores distintos — possível corporativo/viagem")

    # 3. IPv6 /64 consistência (mesmo roteador = residencial)
    ip_col = 'Sender IP' if 'Sender IP' in df_w.columns else 'Ip'
    if ip_col in df_w.columns:
        v6_mask = df_w[ip_col].apply(lambda x: ':' in str(x))
        if v6_mask.sum() > 0:
            v6_ips = df_w.loc[v6_mask, ip_col]
            prefixes = set()
            for ip in v6_ips.unique():
                parts = str(ip).split(':')
                if len(parts) >= 4:
                    prefixes.add(':'.join(parts[:4]))
            if len(prefixes) <= 2 and len(v6_ips) >= 5:
                res_score += 20
                indicators.append(f"📍 IPv6 concentrado em {len(prefixes)} prefixo(s) /64 — mesmo roteador")

    # 4. Tipo de conexão
    if 'Ip_Movel' in df_w.columns:
        mobile_pct = df_w['Ip_Movel'].apply(lambda x: str(x).lower() == 'true').sum() / max(len(df_w), 1) * 100
        if mobile_pct > 50:
            res_score += 15
            indicators.append(f"📱 {mobile_pct:.0f}% conexões móveis — uso pessoal")

    # 5. IP fixo (mesmo IP em múltiplos dias)
    if ip_col in df_w.columns and '_dt' in df_w.columns:
        ip_days = df_w.groupby(ip_col)['_dt'].apply(lambda x: x.dt.date.nunique())
        if ip_days.max() >= 5:
            corp_score += 20
            top_ip = ip_days.idxmax()
            indicators.append(f"🏢 IP {top_ip} usado em {ip_days.max()} dias — possível IP fixo corporativo")

    # Classificação final
    total = res_score + corp_score
    if total == 0:
        return {'profile': 'indeterminado', 'confidence': 0, 'indicators': indicators}

    if res_score > corp_score * 1.5:
        profile = 'residencial'
        confidence = min(95, res_score)
    elif corp_score > res_score * 1.5:
        profile = 'corporativo'
        confidence = min(95, corp_score)
    else:
        profile = 'misto'
        confidence = min(80, max(res_score, corp_score))

    return {
        'profile': profile,
        'confidence': confidence,
        'indicators': indicators,
        'scores': {'residencial': res_score, 'corporativo': corp_score},
    }


# ============================================================
# 35. GEOLOCATION PRECISION INDICATOR (4.1)
# ============================================================

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


