"""analysis.profile — split from analysis monolith."""
import pandas as pd
import logging
from validators import as_bool, bool_series, parse_data

logger = logging.getLogger(__name__)

def detect_vpn_timing(df, date_col='Data', max_gap_seconds=5):
    """
    Analisa timing entre IPs consecutivos para detectar VPN.
    Se um IP de datacenter é seguido por um residencial em <max_gap_seconds,
    o datacenter é provável nó VPN (mesmo pacote, roteado).
    """
    if df.empty or date_col not in df.columns:
        return {'detected': False, 'pairs': []}

    df_w = df.copy()
    df_w['_dt'] = parse_data(df_w[date_col])
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
                prev_hosting = as_bool(prev.get('Ip_Hospedagem'), field='Ip_Hospedagem') or as_bool(prev.get('Ip_Proxy'), field='Ip_Proxy')
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
    df_w['_dt'] = parse_data(df_w.get(date_col, pd.Series(dtype='object')))
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
        mobile_pct = bool_series(df_w, 'Ip_Movel').sum() / max(len(df_w), 1) * 100
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


