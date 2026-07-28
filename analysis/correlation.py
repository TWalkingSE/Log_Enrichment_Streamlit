"""analysis.correlation — split from analysis monolith."""
import pandas as pd
import numpy as np
import os
import json
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

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


