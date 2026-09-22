"""analysis.risk — split from analysis monolith."""
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)
from analysis._config import _vpn_config
from validators import as_bool, bool_series, parse_data

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

    # Um grupo por IP: a versão anterior fazia uma varredura completa do
    # frame por IP único (O(n_ips × n_linhas) — ~4,3k × 202k num caso real).
    # Flags/cidade/provedor vêm do primeiro registro do grupo, como antes.
    agg_spec = {'Ocorrencias': (ip_col, 'size')}
    for c in ('Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_Cidade', 'Ip_Dono'):
        if c in df.columns:
            agg_spec[c] = (c, 'first')
    grp = df.groupby(ip_col, sort=False).agg(**agg_spec).reset_index()
    # 'Sender IP' tem espaço — itertuples sanitizaria o nome do campo.
    grp = grp.rename(columns={ip_col: 'IP'})

    ip_data = []
    for row in grp.itertuples(index=False):
        ip = row.IP
        n_rows = row.Ocorrencias

        score = 0
        factors = []
        breakdown = []

        is_proxy = as_bool(getattr(row, 'Ip_Proxy', None), field='Ip_Proxy')
        is_hosting = as_bool(getattr(row, 'Ip_Hospedagem', None), field='Ip_Hospedagem')
        is_mobile = as_bool(getattr(row, 'Ip_Movel', None), field='Ip_Movel')
        city = getattr(row, 'Ip_Cidade', '')

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
            factors.append('Local incomum (+20)')
            breakdown.append({'label': 'Local incomum', 'weight': 20,
                              'detail': f'Cidade "{city}" diverge da cidade dominante "{main_city}".'})
        if n_rows <= 2:
            score += 10
            factors.append('Baixa frequência (+10)')
            breakdown.append({'label': 'Baixa frequência', 'weight': 10,
                              'detail': f'IP apareceu apenas {n_rows}x — pode ser conexão pontual/anômala.'})
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
            'Provedor': getattr(row, 'Ip_Dono', ''),
            'Cidade': city,
            'Ocorrencias': n_rows
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
    # Mesma semântica do loop anterior (prev_ip truthy && cur != prev): a
    # primeira linha nunca conta; NaN != qualquer coisa conta como mudança.
    mudou = df_work[ip_col].ne(df_work[ip_col].shift())
    mudou.iloc[0] = False
    ip_changes = df_work.loc[mudou, '_dt'].tolist()

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
            pais = residential['Ip_Pais']
            delta_h = residential['_dt'].diff().dt.total_seconds() / 3600
            jump_mask = (pais.ne(pais.shift()) & pais.notna() & pais.shift().notna()
                         & delta_h.abs().le(residential_jump_hours))
            if jump_mask.any():
                cur = residential.loc[jump_mask.idxmax()]
                pos = residential.index.get_loc(jump_mask.idxmax())
                prev_row = residential.iloc[pos - 1]
                time_diff_h = abs((cur['_dt'] - prev_row['_dt']).total_seconds()) / 3600
                score += 30
                result['indicators']['Salto residencial'] = (
                    f"🔴 IPs residenciais em {prev_row.get('Ip_Pais')} → "
                    f"{cur.get('Ip_Pais')} em {time_diff_h:.1f}h"
                )
                result['suspicious_ips'].extend([
                    str(prev_row.get(ip_col, '')),
                    str(cur.get(ip_col, ''))
                ])

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

    # Uma agregação por IP em vez de uma varredura completa do frame por IP
    # (O(n_ips × n_linhas) na versão anterior).
    agg_spec = {'Ocorrencias': (ip_col, 'size')}
    for c in ('Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_Dono'):
        if c in df.columns:
            agg_spec[c] = (c, 'first')

    work = df
    if date_col in df.columns:
        work = pd.DataFrame({ip_col: df[ip_col]})
        for c in ('Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_Dono'):
            if c in df.columns:
                work[c] = df[c]
        datas = parse_data(df[date_col])
        work['_hour'] = datas.dt.hour
        work['_day'] = datas.dt.date
        work['_tem_data'] = datas.notna()
        agg_spec.update({
            '_datas_ok': ('_tem_data', 'sum'),
            '_hour_std': ('_hour', 'std'),
            '_dias': ('_day', 'nunique'),
        })

    grp = work.groupby(ip_col, sort=False).agg(**agg_spec).reset_index()
    grp = grp.rename(columns={ip_col: 'IP'})

    rows = []
    for row in grp.itertuples(index=False):
        ip = row.IP
        score = 50  # base

        motivos = []

        # Recurrence: more appearances = more likely real
        count = row.Ocorrencias
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
        is_proxy = as_bool(getattr(row, 'Ip_Proxy', None), field='Ip_Proxy')
        is_hosting = as_bool(getattr(row, 'Ip_Hospedagem', None), field='Ip_Hospedagem')
        is_mobile = as_bool(getattr(row, 'Ip_Movel', None), field='Ip_Movel')

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
        if getattr(row, '_datas_ok', 0) >= 3:
            hour_std = row._hour_std
            if pd.notna(hour_std) and hour_std < 4:
                score += 10
                motivos.append('Horários consistentes')

            # Multi-day usage
            days = row._dias
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
            'Provedor': getattr(row, 'Ip_Dono', ''),
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


