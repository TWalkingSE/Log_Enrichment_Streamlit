"""Lista de Tor exit nodes: download (torbulkexitlist + Onionoo), cache local e cruzamento."""

import ipaddress
import json
import logging
import os
from datetime import datetime


from helpers.runtime_flags import AirGappedError, ensure_network_allowed
from validators import parse_data

logger = logging.getLogger(__name__)

# Caminho absoluto: com o nome relativo, o cache Tor lido/gravado dependia do
# diretório de onde o app (ou o `tor_updater`) foi iniciado.
TOR_CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'tor_exit_nodes.json')

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
        ensure_network_allowed('torbulkexitlist')
    except AirGappedError as e:
        return (set(), str(e)) if return_error else set()

    try:
        req = urllib.request.Request(list_url, headers={'User-Agent': 'LogEnrichment/5.4'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode('utf-8', errors='replace')

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
        ensure_network_allowed('Onionoo')
    except AirGappedError as e:
        return (set(), str(e)) if return_error else set()

    try:
        req = urllib.request.Request(api_url, headers={'User-Agent': 'LogEnrichment/5.4'})
        with urllib.request.urlopen(req, timeout=25) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='replace'))

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


def load_tor_exit_nodes(cache_file=TOR_CACHE_FILE, ttl_hours=TOR_CACHE_TTL_HOURS,
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


def get_tor_exit_cache_status(cache_file=TOR_CACHE_FILE, ttl_hours=TOR_CACHE_TTL_HOURS):
    """Return Tor cache metadata for UI/status display."""
    return load_tor_exit_nodes(cache_file, ttl_hours, allow_stale=True, return_metadata=True)


def save_tor_exit_nodes(nodes, cache_file=TOR_CACHE_FILE):
    """Persist Tor exit nodes to local cache."""
    import time as _time

    from helpers.atomic_io import atomic_write_json
    try:
        atomic_write_json(cache_file, {'cached_at': _time.time(), 'nodes': sorted(nodes)},
                          ensure_ascii=False, indent=2)
        logger.info("Tor exit nodes saved to cache: %d", len(nodes))
    except OSError as e:
        logger.error("Error saving Tor cache: %s", e)


def update_tor_exit_nodes_cache(cache_file=TOR_CACHE_FILE,
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


def get_tor_exit_nodes(cache_file=TOR_CACHE_FILE, ttl_hours=TOR_CACHE_TTL_HOURS,
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
