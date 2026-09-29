"""analysis.heuristics — heurísticas sobre o DataFrame: saúde dos dados,
cadeias de relay, fingerprint de dispositivo, Wi-Fi compartilhado, silêncio
digital, consistência de fuso e mudanças geográficas no cache.

Veio de `advanced_analysis` (que segue como fachada). Nada aqui sai para a
rede; as integrações externas estão em `intel/`.
"""

import logging
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd

from validators import as_bool, bool_series, parse_data

logger = logging.getLogger(__name__)


# ============================================================
# 9. DATA HEALTH DASHBOARD
# ============================================================

def compute_data_health(df):
    """
    Compute data quality metrics for the dashboard.
    Returns dict with health scores and stats.
    """
    total = len(df)
    if total == 0:
        return {'total': 0, 'overall_score': 0}

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    metrics = {'total': total}

    # IP coverage
    if ip_col in df.columns:
        valid_ips = df[ip_col].notna().sum()
        metrics['ip_coverage'] = round(valid_ips / total * 100, 1)
    else:
        metrics['ip_coverage'] = 0

    # Provider coverage
    if 'Ip_Dono' in df.columns:
        known = df['Ip_Dono'].notna() & (df['Ip_Dono'] != '') & (~df['Ip_Dono'].str.startswith('Erro', na=True))
        metrics['provider_coverage'] = round(known.sum() / total * 100, 1)
    else:
        metrics['provider_coverage'] = 0

    # Geolocation coverage
    if 'Ip_Lat' in df.columns:
        has_geo = pd.to_numeric(df['Ip_Lat'], errors='coerce').notna().sum()
        metrics['geo_coverage'] = round(has_geo / total * 100, 1)
    else:
        metrics['geo_coverage'] = 0

    # Date coverage
    if 'Data' in df.columns:
        has_date = parse_data(df['Data']).notna().sum()
        metrics['date_coverage'] = round(has_date / total * 100, 1)
    else:
        metrics['date_coverage'] = 0

    # IPv6 ratio
    if ip_col in df.columns:
        v6 = df[ip_col].apply(lambda x: ':' in str(x)).sum()
        metrics['ipv6_ratio'] = round(v6 / total * 100, 1)
        metrics['ipv4_ratio'] = round(100 - metrics['ipv6_ratio'], 1)
    else:
        metrics['ipv6_ratio'] = 0
        metrics['ipv4_ratio'] = 0

    # Proxy/Hosting ratio
    if 'Ip_Proxy' in df.columns:
        metrics['proxy_ratio'] = round(bool_series(df, 'Ip_Proxy').sum() / total * 100, 1)
    else:
        metrics['proxy_ratio'] = 0

    # Overall score (weighted average)
    metrics['overall_score'] = round(
        metrics['ip_coverage'] * 0.2 +
        metrics['provider_coverage'] * 0.25 +
        metrics['geo_coverage'] * 0.25 +
        metrics['date_coverage'] * 0.2 +
        (100 - metrics['proxy_ratio']) * 0.1, 1
    )

    return metrics


# ============================================================
# 17. RELAY CHAIN / MULTI-HOP VPN DETECTION (2.2)
# ============================================================

def detect_relay_chains(df, date_col='Data', max_gap_minutes=10):
    """
    Detect relay chain patterns: datacenter → datacenter → residential IP transitions.
    When a datacenter IP is followed by a residential IP within max_gap_minutes,
    the datacenter IPs are likely intermediate VPN/proxy relay nodes.

    Returns dict with chains found, suspicious patterns, relay_score (0-100).
    """
    df_r = df.copy()
    df_r['_dt'] = parse_data(df_r[date_col])
    df_r = df_r.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_r) < 3:
        return {'detected': False, 'chains': [], 'relay_score': 0}

    # Classificação vetorizada por coluna e varredura sobre arrays: o
    # `apply(axis=1)` + `list(df.iterrows())` anterior criava uma Series por
    # linha do frame inteiro. Mesma prioridade (proxy > datacenter > móvel >
    # residencial) e mesma varredura.
    infra = np.select(
        [bool_series(df_r, 'Ip_Proxy').to_numpy(),
         bool_series(df_r, 'Ip_Hospedagem').to_numpy(),
         bool_series(df_r, 'Ip_Movel').to_numpy()],
        ['proxy', 'datacenter', 'mobile'], default='residential')
    dts = list(df_r['_dt'])
    ips = df_r['Ip'].tolist() if 'Ip' in df_r.columns else [''] * len(df_r)
    donos = df_r['Ip_Dono'].tolist() if 'Ip_Dono' in df_r.columns else [''] * len(df_r)
    chains = []
    dc_types = {'proxy', 'datacenter'}

    def _hop(k):
        return {'ip': ips[k], 'type': str(infra[k]),
                'time': dts[k].strftime('%Y-%m-%d %H:%M'), 'provider': donos[k]}

    n = len(dts)
    i = 0
    while i < n - 1:
        if infra[i] in dc_types:
            chain = [_hop(i)]
            j = i + 1
            while j < n:
                gap = abs((dts[j] - dts[j - 1]).total_seconds()) / 60
                if gap > max_gap_minutes:
                    break
                chain.append(_hop(j))
                if infra[j] not in dc_types:
                    # Found transition: DC chain → residential
                    chains.append({
                        'hops': chain,
                        'num_hops': len(chain),
                        'total_time_min': round(abs((dts[j] - dts[i]).total_seconds()) / 60, 1),
                        'exit_ip': ips[j],
                        'exit_type': str(infra[j]),
                    })
                    break
                j += 1
            i = j
        else:
            i += 1
    dc_count = int(np.isin(infra, list(dc_types)).sum())
    total = n
    relay_score = min(100, int((dc_count / max(total, 1)) * 100 + len(chains) * 15))

    return {
        'detected': len(chains) > 0,
        'chains': chains[:20],
        'total_chains': len(chains),
        'datacenter_ratio': round(dc_count / max(total, 1) * 100, 1),
        'relay_score': relay_score,
    }


# ============================================================
# 18. DEVICE FINGERPRINTING BY IP PATTERN (2.3)
# ============================================================

def fingerprint_device_by_ip_pattern(dataframes_dict, date_col='Data', window_minutes=15):
    """
    Group sessions by IP switching pattern. If two targets switch IPs at the same
    times and to the same providers, they likely share a device or network.

    Args:
        dataframes_dict: {target_name: DataFrame}

    Returns:
        list of dicts with target pairs and similarity scores.
    """
    if len(dataframes_dict) < 2:
        return []

    # Build fingerprint per target: list of (timestamp_bucket, provider, infra_type)
    def _build_fingerprint(df):
        df_f = df.copy()
        df_f['_dt'] = parse_data(df_f[date_col])
        df_f = df_f.dropna(subset=['_dt']).sort_values('_dt')
        fingerprints = []
        for _, row in df_f.iterrows():
            bucket = row['_dt'].floor(f'{window_minutes}min')
            provider = str(row.get('Ip_Dono', '')).lower()[:20]
            infra = 'dc' if as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem') else 'res'
            fingerprints.append((bucket, provider, infra))
        return set(fingerprints)

    fps = {name: _build_fingerprint(df) for name, df in dataframes_dict.items()}
    targets = list(fps.keys())
    matches = []

    for i in range(len(targets)):
        for j in range(i + 1, len(targets)):
            t1, t2 = targets[i], targets[j]
            fp1, fp2 = fps[t1], fps[t2]
            if not fp1 or not fp2:
                continue
            common = fp1 & fp2
            union = fp1 | fp2
            jaccard = len(common) / len(union) if union else 0
            if jaccard > 0.05:
                matches.append({
                    'alvo_1': t1,
                    'alvo_2': t2,
                    'common_patterns': len(common),
                    'total_patterns': len(union),
                    'similarity_pct': round(jaccard * 100, 1),
                    'assessment': (
                        'Mesmo dispositivo provável' if jaccard > 0.5
                        else 'Mesma rede provável' if jaccard > 0.2
                        else 'Padrão similar detectado'
                    ),
                })

    return sorted(matches, key=lambda x: x['similarity_pct'], reverse=True)


# ============================================================
# 19. SHARED WI-FI DETECTION - EXACT TIMESTAMP (2.5)
# ============================================================

def detect_shared_wifi(dataframes_dict, date_col='Data', tolerance_seconds=60):
    """
    Detect when multiple targets use the exact same IP at the exact same timestamp.
    This indicates shared Wi-Fi (same home, workplace, or public location).

    Different from find_shared_ips() which doesn't consider exact simultaneity.
    """
    if len(dataframes_dict) < 2:
        return []

    # Collect (ip, timestamp_bucket) pairs per target
    target_events = {}
    for target, df in dataframes_dict.items():
        df_w = df.copy()
        ip_col = 'Sender IP' if 'Sender IP' in df_w.columns else 'Ip'
        if ip_col not in df_w.columns or date_col not in df_w.columns:
            continue
        df_w['_dt'] = parse_data(df_w[date_col])
        df_w = df_w.dropna(subset=['_dt'])
        events = set()
        for _, row in df_w.iterrows():
            ip = row.get(ip_col)
            if pd.notna(ip):
                bucket = row['_dt'].floor(f'{tolerance_seconds}s')
                events.add((str(ip), bucket))
        target_events[target] = events

    targets = list(target_events.keys())
    shared = []

    for i in range(len(targets)):
        for j in range(i + 1, len(targets)):
            t1, t2 = targets[i], targets[j]
            common = target_events[t1] & target_events[t2]
            if common:
                # Group by IP
                ip_times = defaultdict(list)
                for ip, ts in common:
                    ip_times[ip].append(ts.strftime('%Y-%m-%d %H:%M:%S'))
                for ip, times in ip_times.items():
                    shared.append({
                        'alvo_1': t1,
                        'alvo_2': t2,
                        'ip': ip,
                        'simultaneous_count': len(times),
                        'timestamps': times[:10],
                        'assessment': (
                            'Wi-Fi compartilhado (mesma localização física)' if len(times) >= 3
                            else 'Possível Wi-Fi compartilhado'
                        ),
                    })

    return sorted(shared, key=lambda x: x['simultaneous_count'], reverse=True)


# ============================================================
# 20. DIGITAL SILENCE ANALYSIS (2.6)
# ============================================================

def detect_digital_silence(df, date_col='Data', min_gap_hours=24):
    """
    Detect periods of complete service inactivity (gaps > min_gap_hours).
    Correlates with: travel, country changes, possible device/number swaps.
    Goes beyond detect_sleep_pattern() by analyzing extended absences.

    Returns dict with silence_periods, correlations, risk indicators.
    """
    df_s = df.copy()
    df_s['_dt'] = parse_data(df_s[date_col])
    df_s = df_s.dropna(subset=['_dt']).sort_values('_dt')

    if len(df_s) < 2:
        return {'detected': False, 'periods': []}

    periods = []
    prev_dt = None
    prev_row = None

    for _, row in df_s.iterrows():
        if prev_dt is not None:
            gap_hours = abs((row['_dt'] - prev_dt).total_seconds()) / 3600
            if gap_hours >= min_gap_hours:
                # Check for country change
                country_before = prev_row.get('Ip_Pais', '') if prev_row is not None else ''
                country_after = row.get('Ip_Pais', '')
                country_changed = (country_before and country_after and
                                   country_before != country_after and
                                   pd.notna(country_before) and pd.notna(country_after))

                # Check for provider change
                prov_before = prev_row.get('Ip_Dono', '') if prev_row is not None else ''
                prov_after = row.get('Ip_Dono', '')
                provider_changed = (prov_before and prov_after and
                                    prov_before != prov_after and
                                    pd.notna(prov_before) and pd.notna(prov_after))

                # Check for city change
                city_before = prev_row.get('Ip_Cidade', '') if prev_row is not None else ''
                city_after = row.get('Ip_Cidade', '')
                city_changed = (city_before and city_after and
                                city_before != city_after and
                                pd.notna(city_before) and pd.notna(city_after))

                indicators = []
                if country_changed:
                    indicators.append(f'Mudança de país: {country_before} → {country_after}')
                if city_changed and not country_changed:
                    indicators.append(f'Mudança de cidade: {city_before} → {city_after}')
                if provider_changed:
                    indicators.append(f'Mudança de provedor: {prov_before} → {prov_after}')
                if gap_hours > 72:
                    indicators.append('Silêncio prolongado (>72h)')

                periods.append({
                    'start': prev_dt.strftime('%Y-%m-%d %H:%M'),
                    'end': row['_dt'].strftime('%Y-%m-%d %H:%M'),
                    'gap_hours': round(gap_hours, 1),
                    'gap_days': round(gap_hours / 24, 1),
                    'country_changed': country_changed,
                    'city_changed': city_changed,
                    'provider_changed': provider_changed,
                    'ip_before': prev_row.get('Ip', '') if prev_row is not None else '',
                    'ip_after': row.get('Ip', ''),
                    'indicators': indicators,
                    'risk_level': (
                        'Alto' if country_changed or gap_hours > 72
                        else 'Médio' if city_changed or provider_changed
                        else 'Baixo'
                    ),
                })
        prev_dt = row['_dt']
        prev_row = row

    # Summary
    total_silence_hours = sum(p['gap_hours'] for p in periods)
    if df_s['_dt'].iloc[-1] != df_s['_dt'].iloc[0]:
        total_span_hours = (df_s['_dt'].iloc[-1] - df_s['_dt'].iloc[0]).total_seconds() / 3600
    else:
        total_span_hours = 1

    return {
        'detected': len(periods) > 0,
        'periods': periods[:50],
        'total_silences': len(periods),
        'total_silence_hours': round(total_silence_hours, 1),
        'silence_ratio': round(total_silence_hours / max(total_span_hours, 1) * 100, 1),
        'longest_gap_hours': round(max((p['gap_hours'] for p in periods), default=0), 1),
        'country_changes': sum(1 for p in periods if p['country_changed']),
        'high_risk_periods': sum(1 for p in periods if p['risk_level'] == 'Alto'),
    }


# ============================================================
# 21. TIMEZONE CROSS-VALIDATION (3.3)
# ============================================================

def validate_timezone_consistency(df, date_col='Data', sleep_pattern=None):
    """
    Cross-validate IP geolocation timezone with log timestamp timezone.
    Flags inconsistencies where IP is in one timezone but activity pattern
    suggests a different one.

    Args:
        df: DataFrame with geolocation data
        sleep_pattern: dict from detect_sleep_pattern() (optional)

    Returns dict with inconsistencies found.
    """
    # Timezone offsets by country code (simplified)
    TZ_MAP = {
        'BR': -3, 'AR': -3, 'UY': -3, 'CL': -4, 'PY': -4, 'BO': -4,
        'CO': -5, 'PE': -5, 'EC': -5, 'VE': -4,
        'US': -5, 'CA': -5, 'MX': -6,
        'GB': 0, 'PT': 0, 'ES': 1, 'FR': 1, 'DE': 1, 'IT': 1,
        'NL': 1, 'BE': 1, 'AT': 1, 'CH': 1,
        'JP': 9, 'CN': 8, 'KR': 9, 'IN': 5, 'AU': 10, 'NZ': 12,
        'RU': 3, 'ZA': 2, 'EG': 2, 'NG': 1, 'KE': 3,
        'IL': 2, 'AE': 4, 'SA': 3, 'TR': 3,
    }

    df_t = df.copy()
    df_t['_dt'] = parse_data(df_t[date_col])
    df_t = df_t.dropna(subset=['_dt'])

    if df_t.empty or 'Ip_Pais_Codigo' not in df_t.columns:
        return {'analyzed': False, 'inconsistencies': []}

    inconsistencies = []

    # Inline simple sleep detection if not provided
    if sleep_pattern is None:
        sleep_pattern = {'detected': False}
        if len(df_t) >= 10:
            hours = df_t['_dt'].dt.hour
            hourly = hours.value_counts().reindex(range(24), fill_value=0)
            threshold = hourly.mean() * 0.3
            inactive = (hourly <= threshold).astype(int)
            doubled = list(inactive.values) * 2
            max_gap, max_start, cur_gap, cur_start = 0, 0, 0, 0
            for i, v in enumerate(doubled):
                if v == 1:
                    if cur_gap == 0:
                        cur_start = i
                    cur_gap += 1
                    if cur_gap > max_gap:
                        max_gap = cur_gap
                        max_start = cur_start
                else:
                    cur_gap = 0
            if max_gap >= 3:
                sleep_pattern = {
                    'detected': True,
                    'sleep_start': f"{max_start % 24:02d}:00",
                    'duration_hours': max_gap,
                }

    sleep_start = None
    if sleep_pattern.get('detected'):
        sleep_start = int(sleep_pattern['sleep_start'].split(':')[0])

    # Analyze per-record timezone vs activity
    for _, row in df_t.iterrows():
        cc = row.get('Ip_Pais_Codigo', '')
        if not cc or pd.isna(cc) or cc not in TZ_MAP:
            continue

        ip_tz_offset = TZ_MAP[cc]
        local_hour_at_ip = (row['_dt'].hour + ip_tz_offset + 3) % 24  # +3 to convert from BRT

        # Flag if activity at IP location would be in unusual sleep hours
        if sleep_start is not None:
            sleep_end = (sleep_start + sleep_pattern.get('duration_hours', 6)) % 24
            is_sleep_hour = False
            if sleep_start < sleep_end:
                is_sleep_hour = sleep_start <= local_hour_at_ip < sleep_end
            else:
                is_sleep_hour = local_hour_at_ip >= sleep_start or local_hour_at_ip < sleep_end

            if is_sleep_hour and cc != 'BR':
                inconsistencies.append({
                    'timestamp': row['_dt'].strftime('%Y-%m-%d %H:%M'),
                    'ip': row.get('Ip', ''),
                    'ip_country': cc,
                    'ip_timezone': f'UTC{ip_tz_offset:+d}',
                    'local_hour_at_ip': f'{local_hour_at_ip:02d}:00',
                    'issue': f'Atividade às {row["_dt"].strftime("%H:%M")} BRT seria '
                             f'{local_hour_at_ip:02d}:00 em {cc} — horário de sono detectado',
                    'severity': 'Alta' if abs(ip_tz_offset + 3) > 5 else 'Média',
                })

    # Group by country
    country_hours = defaultdict(list)
    for _, row in df_t.iterrows():
        cc = row.get('Ip_Pais_Codigo', '')
        if cc and pd.notna(cc):
            country_hours[cc].append(row['_dt'].hour)

    return {
        'analyzed': True,
        'total_records': len(df_t),
        'inconsistencies': inconsistencies[:50],
        'total_inconsistencies': len(inconsistencies),
        'countries_seen': list(country_hours.keys()),
        'sleep_pattern_used': sleep_pattern.get('detected', False),
    }


# ============================================================
# 13. GEOLOCATION HISTORY / IP REASSIGNMENT DETECTION
# ============================================================

def detect_geo_changes(df, cache):
    """
    Compare current enrichment results against _geo_history in cache.
    Returns dict with IPs that changed geolocation over time.
    """
    from helpers.geo import haversine_km

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    changes = []

    if df.empty or not cache:
        return {'changed_ips': [], 'total_changes': 0, 'isp_changes': 0, 'city_changes': 0, 'country_changes': 0}

    for ip in df[ip_col].dropna().unique():
        ip_str = str(ip)
        entry = cache.get(ip_str, {})
        if not isinstance(entry, dict):
            continue

        history = entry.get('_geo_history', [])
        if not history:
            continue

        current_city = str(entry.get('Ip_Cidade', ''))
        current_isp = str(entry.get('Ip_Dono', ''))
        current_country = str(entry.get('Ip_Pais', ''))
        current_lat = entry.get('Ip_Lat')
        current_lon = entry.get('Ip_Lon')

        for h in history:
            old_city = h.get('city', '')
            old_isp = h.get('isp', '')
            old_country = h.get('country', '')
            old_lat = h.get('lat')
            old_lon = h.get('lon')
            old_ts = h.get('ts', 0)

            city_changed = old_city != current_city
            isp_changed = old_isp != current_isp
            country_changed = old_country != current_country

            distance_km = 0.0
            if old_lat and old_lon and current_lat and current_lon:
                try:
                    distance_km = haversine_km(old_lat, old_lon, current_lat, current_lon)
                except (TypeError, ValueError) as e:
                    logger.debug("haversine falhou para %s: %s", ip_str, e)

            days_since = 0
            if old_ts:
                try:
                    days_since = int((datetime.now().timestamp() - old_ts) / 86400)
                except (TypeError, OverflowError) as e:
                    logger.debug("days_since falhou para %s (ts=%r): %s", ip_str, old_ts, e)

            if city_changed or isp_changed or country_changed:
                severity = 'Crítico' if country_changed else ('Alto' if isp_changed else 'Médio')
                changes.append({
                    'ip': ip_str,
                    'old_city': old_city,
                    'new_city': current_city,
                    'old_isp': old_isp,
                    'new_isp': current_isp,
                    'old_country': old_country,
                    'new_country': current_country,
                    'distance_km': round(distance_km, 1),
                    'days_since': days_since,
                    'old_lat': old_lat,
                    'old_lon': old_lon,
                    'new_lat': current_lat,
                    'new_lon': current_lon,
                    'severity': severity,
                    'change_date': datetime.fromtimestamp(old_ts).strftime('%Y-%m-%d') if old_ts else '',
                })

    isp_changes = sum(1 for c in changes if c['old_isp'] != c['new_isp'])
    city_changes = sum(1 for c in changes if c['old_city'] != c['new_city'])
    country_changes = sum(1 for c in changes if c['old_country'] != c['new_country'])

    return {
        'changed_ips': sorted(changes, key=lambda x: {'Crítico': 2, 'Alto': 1, 'Médio': 0}.get(x['severity'], 0), reverse=True),
        'total_changes': len(changes),
        'isp_changes': isp_changes,
        'city_changes': city_changes,
        'country_changes': country_changes,
    }
