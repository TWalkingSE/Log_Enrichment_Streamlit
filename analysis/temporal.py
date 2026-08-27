"""analysis.temporal — split from analysis monolith."""
import pandas as pd
import numpy as np
import logging
from validators import bool_series, parse_data

logger = logging.getLogger(__name__)

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
    df_work['_dt'] = parse_data(df_work[date_col])
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
        proxy_pct = bool_series(prov_rows, 'Ip_Proxy').mean() if 'Ip_Proxy' in prov_rows.columns else 0
        hosting_pct = bool_series(prov_rows, 'Ip_Hospedagem').mean() if 'Ip_Hospedagem' in prov_rows.columns else 0
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
    df_work['_dt'] = parse_data(df_work[date_col])
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


