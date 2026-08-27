"""analysis.risk — split from analysis monolith."""
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)
from analysis._config import _vpn_config
from validators import bool_series, parse_data

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
        breakdown = []

        is_proxy = row.get('Ip_Proxy', False)
        is_hosting = row.get('Ip_Hospedagem', False)
        is_mobile = row.get('Ip_Movel', False)
        city = row.get('Ip_Cidade', '')

        if is_proxy:
            score += 40
            factors.append('Proxy/VPN (+40)')
            breakdown.append({'label': 'Proxy/VPN detectado', 'weight': 40,
                              'detail': 'IP marcado como proxy/VPN pela base de geolocalização.'})
        if is_hosting:
            score += 25
            factors.append('Hosting (+25)')
            breakdown.append({'label': 'Infraestrutura de hosting', 'weight': 25,
                              'detail': 'IP pertence a datacenter/hospedagem (improvável uso residencial).'})
        if main_city and pd.notna(city) and city != main_city:
            score += 20
            factors.append(f'Local incomum (+20)')
            breakdown.append({'label': 'Local incomum', 'weight': 20,
                              'detail': f'Cidade "{city}" diverge da cidade dominante "{main_city}".'})
        if len(rows) <= 2:
            score += 10
            factors.append('Baixa frequência (+10)')
            breakdown.append({'label': 'Baixa frequência', 'weight': 10,
                              'detail': f'IP apareceu apenas {len(rows)}x — pode ser conexão pontual/anômala.'})
        if is_mobile:
            score -= 5
            factors.append('Móvel (-5)')
            breakdown.append({'label': 'Conexão móvel', 'weight': -5,
                              'detail': 'IPs móveis são naturalmente dinâmicos; reduz suspeita.'})

        score = max(0, min(100, score))

        ip_data.append({
            'IP': ip,
            'Score': score,
            'Fatores': '; '.join(factors) if factors else 'Residencial',
            'Breakdown': breakdown,
            'Provedor': row.get('Ip_Dono', ''),
            'Cidade': row.get('Ip_Cidade', ''),
            'Ocorrencias': len(rows)
        })

    result = pd.DataFrame(ip_data)
    if not result.empty:
        result = result.sort_values('Score', ascending=False)
    return result


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
            ~bool_series(df_work, 'Ip_Proxy') &
            ~bool_series(df_work, 'Ip_Hospedagem')
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
        hosting_count = bool_series(df_work, 'Ip_Hospedagem').sum()
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
            dates = parse_data(ip_data[date_col]).dropna()
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


