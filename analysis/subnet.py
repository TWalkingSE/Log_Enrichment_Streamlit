"""analysis.subnet — split from analysis monolith."""
import logging
from validators import parse_data

logger = logging.getLogger(__name__)

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

    # Subrede calculada uma vez por IP distinto — cardinalidade baixa — e
    # o restante agregado por groupby, em vez de iterrows() sobre o frame.
    cols = [c for c in (ip_col, 'Ip_Dono', 'Ip_Cidade', 'Data') if c in df.columns]
    work = df[cols].copy()
    work['_ip'] = work[ip_col].astype(str).str.strip()
    work = work[work['_ip'] != '']

    subnet_map = {}
    for ip_str in work['_ip'].unique():
        try:
            addr = ipa(ip_str)
            mask = ipv6_mask if addr.version == 6 else ipv4_mask
            subnet_map[ip_str] = (str(ip_network(f"{ip_str}/{mask}", strict=False)), addr.version)
        except ValueError:
            continue
    n_invalid = int((~work['_ip'].isin(subnet_map)).sum())
    if n_invalid:
        logger.warning("analyze_subnet_patterns: %d registros com IP inválido ignorados", n_invalid)

    work['_subnet'] = work['_ip'].map(lambda i: subnet_map.get(i, (None,))[0])
    work = work[work['_subnet'].notna()]
    if work.empty:
        return {'subnets': [], 'dominant_subnets': [], 'total_subnets': 0}

    subnet_data = {}
    for subnet_key, grp in work.groupby('_subnet', sort=False):
        provs = set(grp['Ip_Dono'].dropna().astype(str)) if 'Ip_Dono' in grp.columns else set()
        cities = set(grp['Ip_Cidade'].dropna().astype(str)) if 'Ip_Cidade' in grp.columns else set()
        dates = grp['Data'].dropna().astype(str).tolist() if 'Data' in grp.columns else []
        provs.discard('')
        cities.discard('')
        subnet_data[subnet_key] = {
            'subnet': subnet_key,
            'ips': set(grp['_ip']),
            'count': len(grp),
            'providers': provs,
            'cities': cities,
            'dates': dates,
            'version': subnet_map[grp['_ip'].iloc[0]][1],
        }

    subnets = []
    for s in sorted(subnet_data.values(), key=lambda x: x['count'], reverse=True):
        dates = s['dates']
        date_range = None
        if dates:
            try:
                parsed = parse_data(dates).dropna()
                if len(parsed) > 0:
                    date_range = (parsed.min().strftime('%Y-%m-%d'), parsed.max().strftime('%Y-%m-%d'))
            except Exception as e:
                logger.debug("Intervalo de datas da subrede %s não calculado: %s", s['subnet'], e)

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
            except ValueError:
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
        df_work['_dt'] = parse_data(df_work[date_col])
        df_work = df_work.dropna(subset=['_dt']).sort_values('_dt')

    # Subrede por IP distinto; a ordem temporal das linhas é preservada
    # pelo map, então a sequência de transições sai igual à varredura.
    ip_series = df_work[ip_col].astype(str).str.strip()
    subnet_map = {}
    for ip_str in ip_series.unique():
        if not ip_str:
            continue
        try:
            addr = ipa(ip_str)
            mask = ipv6_mask if addr.version == 6 else ipv4_mask
            subnet_map[ip_str] = str(ip_network(f"{ip_str}/{mask}", strict=False))
        except ValueError:
            continue
    subnets_seen = ip_series.map(subnet_map).dropna().tolist()

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


