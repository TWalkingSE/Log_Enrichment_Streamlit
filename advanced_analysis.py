"""
Log Enrichment - Advanced Analysis Module v4.1
VirusTotal + AbuseIPDB multi-source threat scoring, relay chain detection,
device fingerprinting, shared Wi-Fi detection, digital silence analysis,
timezone cross-validation, data health.
"""

import pandas as pd
import logging
import aiohttp
import asyncio
import os
import json
import ipaddress
from datetime import datetime
from collections import defaultdict
from validators import as_bool, bool_series, parse_data

logger = logging.getLogger(__name__)


# ============================================================
# 1. ABUSEIPDB INTEGRATION
# ============================================================

async def check_abuseipdb(session, ip, api_key):
    """Query AbuseIPDB for a single IP. Returns dict with abuse data."""
    if not api_key:
        return {'ip': ip, 'abuse_score': None, 'error': 'No API key'}
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.get(url, headers=headers, params=params, timeout=timeout) as resp:
            if resp.status == 200:
                data = await resp.json()
                d = data.get('data', {})
                return {
                    'ip': ip,
                    'abuse_score': d.get('abuseConfidenceScore', 0),
                    'total_reports': d.get('totalReports', 0),
                    'country': d.get('countryCode', ''),
                    'isp': d.get('isp', ''),
                    'usage_type': d.get('usageType', ''),
                    'is_tor': d.get('isTor', False),
                    'last_reported': d.get('lastReportedAt', ''),
                }
            elif resp.status == 429:
                return {'ip': ip, 'abuse_score': None, 'error': 'Rate limited'}
            else:
                return {'ip': ip, 'abuse_score': None, 'error': f'HTTP {resp.status}'}
    except Exception as e:
        return {'ip': ip, 'abuse_score': None, 'error': str(e)}


async def batch_check_abuseipdb(ips, api_key, max_concurrent=5):
    """Check multiple IPs against AbuseIPDB. Returns list of dicts."""
    results = []
    sem = asyncio.Semaphore(max_concurrent)

    async def _check(session, ip):
        async with sem:
            return await check_abuseipdb(session, ip, api_key)

    async with aiohttp.ClientSession() as session:
        tasks = [_check(session, ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = []
    for r in results:
        if isinstance(r, Exception):
            clean.append({'ip': '', 'abuse_score': None, 'error': str(r)})
        else:
            clean.append(r)
    return clean


# ============================================================
# 1B. VIRUSTOTAL INTEGRATION
# ============================================================

async def check_virustotal(session, ip, api_key):
    """Query VirusTotal for a single IP. Returns dict with threat data."""
    if not api_key:
        return {'ip': ip, 'vt_malicious': None, 'error': 'No API key'}
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {'x-apikey': api_key, 'Accept': 'application/json'}
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status == 200:
                data = await resp.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'ip': ip,
                    'vt_malicious': stats.get('malicious', 0),
                    'vt_suspicious': stats.get('suspicious', 0),
                    'vt_harmless': stats.get('harmless', 0),
                    'vt_undetected': stats.get('undetected', 0),
                    'vt_total_engines': sum(stats.values()) if stats else 0,
                    'vt_country': attrs.get('country', ''),
                    'vt_as_owner': attrs.get('as_owner', ''),
                    'vt_asn': attrs.get('asn', ''),
                    'vt_reputation': attrs.get('reputation', 0),
                    'vt_ssl_count': len(attrs.get('last_https_certificate', {}).get('extensions', {}).get('subject_alternative_name', [])),
                    'vt_domains': len(attrs.get('last_dns_records', [])),
                }
            elif resp.status == 429:
                return {'ip': ip, 'vt_malicious': None, 'error': 'Rate limited'}
            elif resp.status == 404:
                return {'ip': ip, 'vt_malicious': 0, 'vt_suspicious': 0, 'vt_harmless': 0,
                        'vt_undetected': 0, 'vt_total_engines': 0, 'vt_country': '',
                        'vt_as_owner': '', 'vt_asn': '', 'vt_reputation': 0,
                        'vt_ssl_count': 0, 'vt_domains': 0}
            else:
                return {'ip': ip, 'vt_malicious': None, 'error': f'HTTP {resp.status}'}
    except Exception as e:
        return {'ip': ip, 'vt_malicious': None, 'error': str(e)}


async def batch_check_virustotal(ips, api_key, max_concurrent=4):
    """Check multiple IPs against VirusTotal (free: 4 req/min)."""
    results = []
    sem = asyncio.Semaphore(max_concurrent)

    async def _check(session, ip):
        async with sem:
            result = await check_virustotal(session, ip, api_key)
            await asyncio.sleep(15.5)  # Free tier: 4 req/min
            return result

    async with aiohttp.ClientSession() as session:
        tasks = [_check(session, ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = []
    for r in results:
        if isinstance(r, Exception):
            clean.append({'ip': '', 'vt_malicious': None, 'error': str(r)})
        else:
            clean.append(r)
    return clean


def compute_multi_source_threat_score(abuse_results, vt_results):
    """
    Compute unified threat score (0-100) from AbuseIPDB + VirusTotal data.
    Returns list of dicts with ip, threat_score, threat_level, sources.
    """
    abuse_map = {r['ip']: r for r in abuse_results if r.get('ip')}
    vt_map = {r['ip']: r for r in vt_results if r.get('ip')}

    all_ips = set(abuse_map.keys()) | set(vt_map.keys())
    scores = []

    for ip in all_ips:
        abuse = abuse_map.get(ip, {})
        vt = vt_map.get(ip, {})

        # AbuseIPDB component (0-50 pts)
        abuse_score = abuse.get('abuse_score') or 0
        abuse_component = min(50, abuse_score * 0.5)

        # VirusTotal component (0-50 pts)
        vt_malicious = vt.get('vt_malicious') or 0
        vt_suspicious = vt.get('vt_suspicious') or 0
        vt_total = vt.get('vt_total_engines') or 1
        vt_ratio = (vt_malicious * 2 + vt_suspicious) / max(vt_total, 1)
        vt_component = min(50, vt_ratio * 100)

        # Bonus for Tor exit
        tor_bonus = 15 if abuse.get('is_tor') else 0

        total = min(100, abuse_component + vt_component + tor_bonus)

        if total >= 75:
            level = 'Crítico'
        elif total >= 50:
            level = 'Alto'
        elif total >= 25:
            level = 'Médio'
        else:
            level = 'Baixo'

        scores.append({
            'ip': ip,
            'threat_score': round(total, 1),
            'threat_level': level,
            'abuse_score': abuse_score,
            'abuse_reports': abuse.get('total_reports', 0),
            'is_tor': abuse.get('is_tor', False),
            'vt_malicious': vt_malicious,
            'vt_suspicious': vt_suspicious,
            'vt_reputation': vt.get('vt_reputation', 0),
            'vt_domains': vt.get('vt_domains', 0),
            'sources': ', '.join(filter(None, [
                'AbuseIPDB' if abuse.get('abuse_score') is not None else None,
                'VirusTotal' if vt.get('vt_malicious') is not None else None,
            ])),
        })

    return sorted(scores, key=lambda x: x['threat_score'], reverse=True)




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

    # Classify each record
    def _classify(row):
        if as_bool(row.get('Ip_Proxy'), field='Ip_Proxy'):
            return 'proxy'
        if as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem'):
            return 'datacenter'
        if as_bool(row.get('Ip_Movel'), field='Ip_Movel'):
            return 'mobile'
        return 'residential'

    df_r['_infra'] = df_r.apply(_classify, axis=1)
    rows = list(df_r.iterrows())
    chains = []
    dc_types = {'proxy', 'datacenter'}

    i = 0
    while i < len(rows) - 1:
        _, r1 = rows[i]
        if r1['_infra'] in dc_types:
            chain = [{'ip': r1.get('Ip', ''), 'type': r1['_infra'],
                       'time': r1['_dt'].strftime('%Y-%m-%d %H:%M'),
                       'provider': r1.get('Ip_Dono', '')}]
            j = i + 1
            while j < len(rows):
                _, r2 = rows[j]
                gap = abs((r2['_dt'] - rows[j-1][1]['_dt']).total_seconds()) / 60
                if gap > max_gap_minutes:
                    break
                chain.append({'ip': r2.get('Ip', ''), 'type': r2['_infra'],
                              'time': r2['_dt'].strftime('%Y-%m-%d %H:%M'),
                              'provider': r2.get('Ip_Dono', '')})
                if r2['_infra'] not in dc_types:
                    # Found transition: DC chain → residential
                    chains.append({
                        'hops': chain,
                        'num_hops': len(chain),
                        'total_time_min': round(abs((r2['_dt'] - r1['_dt']).total_seconds()) / 60, 1),
                        'exit_ip': r2.get('Ip', ''),
                        'exit_type': r2['_infra'],
                    })
                    break
                j += 1
            i = j
        else:
            i += 1

    dc_count = sum(1 for _, r in rows if r['_infra'] in dc_types)
    total = len(rows)
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
# 12. SHODAN INTEGRATION
# ============================================================

async def check_shodan(session, ip, api_key):
    """Query Shodan for a single IP. Returns dict with service/port data."""
    if not api_key:
        return {'ip': ip, 'ports': [], 'error': 'No API key'}
    try:
        url = f'https://api.shodan.io/shodan/host/{ip}'
        params = {'key': api_key}
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.get(url, params=params, timeout=timeout) as resp:
            if resp.status == 200:
                data = await resp.json()
                ports = data.get('ports', [])
                services = []
                for item in data.get('data', []):
                    services.append({
                        'port': item.get('port'),
                        'transport': item.get('transport', 'tcp'),
                        'product': item.get('product', ''),
                        'version': item.get('version', ''),
                        'banner': (item.get('data', '') or '')[:200],
                    })
                vulns = []
                for item in data.get('data', []):
                    for v in item.get('vulns', []):
                        if v not in vulns:
                            vulns.append(v)
                return {
                    'ip': ip,
                    'ports': ports,
                    'services': services,
                    'os': data.get('os', ''),
                    'vulns': vulns,
                    'hostnames': data.get('hostnames', []),
                    'org': data.get('org', ''),
                    'last_update': data.get('last_update', ''),
                }
            elif resp.status == 404:
                return {'ip': ip, 'ports': [], 'services': [], 'os': '',
                        'vulns': [], 'hostnames': [], 'org': '', 'last_update': ''}
            elif resp.status == 429:
                return {'ip': ip, 'ports': [], 'error': 'Rate limited'}
            elif resp.status == 401:
                return {'ip': ip, 'ports': [], 'error': 'Invalid API key'}
            else:
                return {'ip': ip, 'ports': [], 'error': f'HTTP {resp.status}'}
    except Exception as e:
        return {'ip': ip, 'ports': [], 'error': str(e)}


async def batch_check_shodan(ips, api_key, max_concurrent=1):
    """Check multiple IPs against Shodan (free: ~1 req/sec)."""
    results = []
    sem = asyncio.Semaphore(max_concurrent)

    async def _check(session, ip):
        async with sem:
            result = await check_shodan(session, ip, api_key)
            await asyncio.sleep(1.1)  # Free tier: ~1 req/sec
            return result

    async with aiohttp.ClientSession() as session:
        tasks = [_check(session, ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    clean = []
    for r in results:
        if isinstance(r, Exception):
            clean.append({'ip': '', 'ports': [], 'error': str(r)})
        else:
            clean.append(r)
    return clean


def compute_shodan_risk_indicators(shodan_results, df=None):
    """
    Analyze Shodan results and flag risky IPs.
    Returns list of dicts with risk indicators per IP.
    """
    DANGEROUS_PORTS = {22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 27017}
    indicators = []

    # Build infra map from df if available
    infra_map = {}
    if df is not None and not df.empty:
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
        if ip_col in df.columns:
            for _, row in df.drop_duplicates(subset=[ip_col]).iterrows():
                is_hosting = as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem')
                is_proxy = as_bool(row.get('Ip_Proxy'), field='Ip_Proxy')
                infra_map[str(row[ip_col])] = 'hosting' if (is_hosting or is_proxy) else 'residential'

    for r in shodan_results:
        ip = r.get('ip', '')
        if not ip or r.get('error'):
            continue

        ports = set(r.get('ports', []))
        dangerous_open = ports & DANGEROUS_PORTS
        vulns = r.get('vulns', [])
        infra_type = infra_map.get(ip, 'unknown')

        # Flag residential IPs with server-like ports
        unexpected_services = False
        if infra_type == 'residential' and ports & {80, 443, 25, 8080, 8443}:
            unexpected_services = True

        risk_level = 'Baixo'
        risk_reasons = []

        if dangerous_open:
            risk_level = 'Alto'
            risk_reasons.append(f"Portas perigosas: {', '.join(str(p) for p in sorted(dangerous_open))}")
        if vulns:
            risk_level = 'Crítico' if len(vulns) >= 3 else 'Alto'
            risk_reasons.append(f"{len(vulns)} vulnerabilidade(s): {', '.join(vulns[:5])}")
        if unexpected_services:
            if risk_level == 'Baixo':
                risk_level = 'Médio'
            risk_reasons.append("Serviços inesperados para IP residencial")

        # Org mismatch check
        shodan_org = (r.get('org', '') or '').lower()
        if df is not None and not df.empty:
            ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
            match = df[df[ip_col] == ip]
            if not match.empty:
                api_org = str(match.iloc[0].get('Ip_Dono', '')).lower()
                if shodan_org and api_org and shodan_org != api_org:
                    if not (shodan_org in api_org or api_org in shodan_org):
                        risk_reasons.append(f"Org mismatch: IP-API='{api_org}' vs Shodan='{shodan_org}'")

        indicators.append({
            'ip': ip,
            'ports_open': len(ports),
            'ports_list': sorted(ports),
            'dangerous_ports': sorted(dangerous_open),
            'vulns_count': len(vulns),
            'vulns': vulns[:10],
            'os': r.get('os', ''),
            'hostnames': r.get('hostnames', []),
            'services_count': len(r.get('services', [])),
            'unexpected_services': unexpected_services,
            'risk_level': risk_level,
            'risk_reasons': risk_reasons,
        })

    return sorted(indicators, key=lambda x: {'Crítico': 3, 'Alto': 2, 'Médio': 1, 'Baixo': 0}.get(x['risk_level'], 0), reverse=True)


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
                except Exception:
                    pass

            days_since = 0
            if old_ts:
                try:
                    days_since = int((datetime.now().timestamp() - old_ts) / 86400)
                except Exception:
                    pass

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


# ============================================================
# 14. TOR EXIT NODE DATABASE
# ============================================================

TOR_BULK_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist'
TOR_ONIONOO_DETAILS_URL = (
    'https://onionoo.torproject.org/details?running=true&flag=Exit'
    '&fields=running,flags,exit_addresses'
)
TOR_CACHE_TTL_HOURS = 6


def _normalize_tor_exit_ip(value):
    """Normalize and validate a public IP candidate from Tor sources."""
    candidate = str(value or '').strip()
    if not candidate:
        return None
    if candidate.startswith('[') and candidate.endswith(']'):
        candidate = candidate[1:-1]
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if not ip_obj.is_global:
        return None
    return str(ip_obj)


def fetch_tor_exit_nodes(list_url=TOR_BULK_EXIT_LIST_URL, return_error=False):
    """Download Tor exit nodes from torbulkexitlist."""
    import urllib.request

    try:
        req = urllib.request.Request(list_url, headers={'User-Agent': 'LogEnrichment/5.2'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode('utf-8', errors='ignore')

        nodes = set()
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if not parts:
                continue

            candidate = parts[1] if parts[0].lower() == 'exitaddress' and len(parts) > 1 else parts[0]
            normalized = _normalize_tor_exit_ip(candidate)
            if normalized:
                nodes.add(normalized)

        logger.info("Tor exit nodes downloaded from torbulkexitlist: %d IPs", len(nodes))
        if return_error:
            return nodes, None
        return nodes
    except (OSError, ValueError) as e:
        logger.error("Failed to fetch Tor exit nodes from torbulkexitlist: %s", e)
        if return_error:
            return set(), str(e)
        return set()


def fetch_tor_exit_nodes_from_onionoo(api_url=TOR_ONIONOO_DETAILS_URL, return_error=False):
    """Download Tor exit nodes from Onionoo details documents."""
    import urllib.request

    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'LogEnrichment/5.2'})
        with urllib.request.urlopen(req, timeout=25) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='ignore'))

        nodes = set()
        for relay in payload.get('relays', []):
            if relay.get('running') is False:
                continue
            flags = {str(flag).lower() for flag in relay.get('flags', [])}
            if flags and 'exit' not in flags:
                continue
            for candidate in relay.get('exit_addresses', []) or []:
                normalized = _normalize_tor_exit_ip(candidate)
                if normalized:
                    nodes.add(normalized)

        logger.info("Tor exit nodes downloaded from Onionoo: %d IPs", len(nodes))
        if return_error:
            return nodes, None
        return nodes
    except (OSError, ValueError, TypeError) as e:
        logger.error("Failed to fetch Tor exit nodes from Onionoo: %s", e)
        if return_error:
            return set(), str(e)
        return set()


def load_tor_exit_nodes(cache_file='tor_exit_nodes.json', ttl_hours=TOR_CACHE_TTL_HOURS,
                        allow_stale=False, return_metadata=False):
    """Load Tor exit nodes from local cache, optionally accepting stale data."""
    import time as _time

    metadata = {
        'available': False,
        'cached_at': None,
        'cached_at_iso': None,
        'age_hours': None,
        'is_stale': True,
        'nodes': set(),
        'node_count': 0,
    }

    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cached_at = float(data.get('cached_at', 0) or 0)
            nodes = {
                normalized
                for normalized in (_normalize_tor_exit_ip(node) for node in data.get('nodes', []))
                if normalized
            }
            age_seconds = max(_time.time() - cached_at, 0) if cached_at else None
            is_stale = age_seconds is None or age_seconds >= (ttl_hours * 3600)

            metadata.update({
                'available': True,
                'cached_at': cached_at or None,
                'cached_at_iso': datetime.fromtimestamp(cached_at).isoformat(timespec='seconds') if cached_at else None,
                'age_hours': round(age_seconds / 3600, 2) if age_seconds is not None else None,
                'is_stale': is_stale,
                'nodes': nodes,
                'node_count': len(nodes),
            })

            if nodes and (allow_stale or not is_stale):
                logger.info("Tor exit nodes loaded from cache: %d", len(nodes))
                return metadata if return_metadata else nodes
    except (OSError, ValueError, TypeError) as e:
        logger.warning("Error loading Tor cache: %s", e)

    return metadata if return_metadata else None


def get_tor_exit_cache_status(cache_file='tor_exit_nodes.json', ttl_hours=TOR_CACHE_TTL_HOURS):
    """Return Tor cache metadata for UI/status display."""
    return load_tor_exit_nodes(cache_file, ttl_hours, allow_stale=True, return_metadata=True)


def save_tor_exit_nodes(nodes, cache_file='tor_exit_nodes.json'):
    """Persist Tor exit nodes to local cache."""
    import time as _time

    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'cached_at': _time.time(), 'nodes': sorted(nodes)}, f, ensure_ascii=False, indent=2)
        logger.info("Tor exit nodes saved to cache: %d", len(nodes))
    except OSError as e:
        logger.error("Error saving Tor cache: %s", e)


def update_tor_exit_nodes_cache(cache_file='tor_exit_nodes.json',
                                list_url=TOR_BULK_EXIT_LIST_URL,
                                onionoo_url=TOR_ONIONOO_DETAILS_URL):
    """Refresh the Tor cache using torbulkexitlist plus Onionoo."""
    bulk_nodes, bulk_error = fetch_tor_exit_nodes(list_url, return_error=True)
    onionoo_nodes, onionoo_error = fetch_tor_exit_nodes_from_onionoo(onionoo_url, return_error=True)

    combined_nodes = set(bulk_nodes) | set(onionoo_nodes)
    source_counts = {
        'torbulkexitlist': len(bulk_nodes),
        'onionoo': len(onionoo_nodes),
    }
    source_errors = {}
    if bulk_error:
        source_errors['torbulkexitlist'] = bulk_error
    if onionoo_error:
        source_errors['onionoo'] = onionoo_error

    if combined_nodes:
        save_tor_exit_nodes(combined_nodes, cache_file)
        return {
            'success': True,
            'nodes': combined_nodes,
            'node_count': len(combined_nodes),
            'source_counts': source_counts,
            'source_errors': source_errors,
        }

    error_message = 'Falha ao atualizar lista Tor a partir das fontes oficiais.'
    logger.warning("%s", error_message)
    return {
        'success': False,
        'nodes': set(),
        'node_count': 0,
        'source_counts': source_counts,
        'source_errors': source_errors,
        'error': error_message,
    }


def get_tor_exit_nodes(cache_file='tor_exit_nodes.json', ttl_hours=TOR_CACHE_TTL_HOURS,
                       list_url=TOR_BULK_EXIT_LIST_URL,
                       onionoo_url=TOR_ONIONOO_DETAILS_URL):
    """Get Tor exit nodes from cache or refresh from the two official Tor sources."""
    nodes = load_tor_exit_nodes(cache_file, ttl_hours)
    if nodes is not None:
        return nodes

    update_result = update_tor_exit_nodes_cache(cache_file, list_url, onionoo_url)
    if update_result['success']:
        return update_result['nodes']

    stale_nodes = load_tor_exit_nodes(cache_file, ttl_hours, allow_stale=True)
    if stale_nodes:
        logger.warning("Using stale Tor cache after refresh failure.")
        return stale_nodes
    return set()


def check_tor_exit_nodes(df, tor_nodes_set=None, ip_col=None):
    """
    Cross-reference DataFrame IPs against Tor exit node set.
    Returns dict with tor IPs, percentage, and timeline.
    """
    if ip_col is None:
        ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'

    if df.empty or ip_col not in df.columns:
        return {'tor_ips': [], 'total_tor': 0, 'pct_tor': 0.0, 'tor_timeline': []}

    if tor_nodes_set is None:
        tor_nodes_set = get_tor_exit_nodes()

    if not tor_nodes_set:
        return {'tor_ips': [], 'total_tor': 0, 'pct_tor': 0.0, 'tor_timeline': []}

    all_ips = df[ip_col].dropna().unique()
    tor_ips = [ip for ip in all_ips if str(ip).strip() in tor_nodes_set]

    # Build timeline
    tor_timeline = []
    if tor_ips and 'Data' in df.columns:
        df_tor = df[df[ip_col].isin(tor_ips)].copy()
        df_tor['_dt'] = parse_data(df_tor['Data'])
        df_tor = df_tor.dropna(subset=['_dt']).sort_values('_dt')
        for ip in tor_ips:
            ip_dates = df_tor[df_tor[ip_col] == ip]['_dt'].tolist()
            tor_timeline.append({
                'ip': ip,
                'first_seen': ip_dates[0].strftime('%Y-%m-%d %H:%M') if ip_dates else '',
                'last_seen': ip_dates[-1].strftime('%Y-%m-%d %H:%M') if ip_dates else '',
                'count': len(ip_dates),
            })

    total_unique = len(all_ips)
    return {
        'tor_ips': tor_ips,
        'total_tor': len(tor_ips),
        'pct_tor': round(len(tor_ips) / max(total_unique, 1) * 100, 1),
        'tor_timeline': tor_timeline,
    }
