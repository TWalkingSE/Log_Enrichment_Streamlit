"""Reputação de IP em fontes externas: AbuseIPDB, VirusTotal e Shodan."""

import asyncio
import logging

import aiohttp

from helpers.runtime_flags import ensure_network_allowed
from validators import as_bool

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
    ensure_network_allowed('AbuseIPDB')
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
    ensure_network_allowed('VirusTotal')
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
    ensure_network_allowed('Shodan')
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
