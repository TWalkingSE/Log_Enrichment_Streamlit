"""
Log Enrichment - Módulo de Análise Investigativa de IPs v2.1
Análise investigativa para uso policial: scoring com prioridade IPv6,
âncoras temporais, diversificação de horário, detecção de usuário único,
seleção inteligente de provedores e sugestão de IPs para investigação
com geração de resumo narrativo.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from api_client import is_cgnat_ip
from data_processor import periodo_matches as _periodo_matches
from styles.theme import COLORS


# ============================================================
# HELPERS
# ============================================================

def _parse_bool(val):
    """Converte valor heterogêneo em bool (delega a validators.as_bool)."""
    from validators import as_bool
    return as_bool(val)


def _safe_datetime(dt_series):
    """Converte série para datetime, removendo timezone se presente."""
    dt = pd.to_datetime(dt_series, errors='coerce')
    if hasattr(dt, 'dt') and dt.dt.tz is not None:
        dt = dt.dt.tz_localize(None)
    return dt


def _is_ipv6(ip_str):
    """Verifica se o IP é IPv6."""
    if not isinstance(ip_str, str):
        return False
    return ':' in ip_str


def _strip_tz(dt_fato):
    """Remove timezone de um datetime se presente."""
    if hasattr(dt_fato, 'tzinfo') and dt_fato.tzinfo is not None:
        return dt_fato.replace(tzinfo=None)
    return dt_fato


def _get_ipv6_prefix64(ip_str):
    """Extrai o prefixo /64 de um endereço IPv6 (identifica o roteador/rede)."""
    if not isinstance(ip_str, str) or ':' not in ip_str:
        return None
    try:
        from ipaddress import ip_address as ipa
        addr = ipa(ip_str.strip())
        if addr.version != 6:
            return None
        # /64 = primeiros 64 bits = primeiros 4 grupos de 16 bits
        full = addr.exploded  # ex: 2001:0db8:10b9:9855:0920:db70:2b33:5c08
        parts = full.split(':')
        return ':'.join(parts[:4]) + '::/64'
    except Exception:
        return None


def agrupar_ipv6_por_prefixo(df):
    """
    Agrupa IPs IPv6 por prefixo /64 para identificar IPs do mesmo roteador.
    Retorna DataFrame com prefixo, contagem e lista de IPs.
    """
    if df.empty or 'Ip' not in df.columns:
        return pd.DataFrame()

    df_v6 = df[df['Ip'].apply(lambda x: _is_ipv6(str(x)))].copy()
    if df_v6.empty:
        return pd.DataFrame()

    df_v6['Prefixo_64'] = df_v6['Ip'].apply(_get_ipv6_prefix64)
    df_v6 = df_v6.dropna(subset=['Prefixo_64'])

    if df_v6.empty:
        return pd.DataFrame()

    grouped = df_v6.groupby('Prefixo_64').agg(
        Qtd_IPs=('Ip', 'nunique'),
        Qtd_Registros=('Ip', 'count'),
        IPs=('Ip', lambda x: ', '.join(x.unique()[:5])),
        Provedor=('Ip_Dono', 'first') if 'Ip_Dono' in df_v6.columns else ('Ip', 'first'),
        Cidade=('Ip_Cidade', 'first') if 'Ip_Cidade' in df_v6.columns else ('Ip', 'first'),
    ).sort_values('Qtd_Registros', ascending=False).reset_index()

    return grouped


# ============================================================
# 1. SELECIONAR PROVEDORES E DETECTAR CGNAT
# ============================================================

def selecionar_provedores(df):
    """
    Identifica os 3 provedores mais relevantes no DataFrame.
    Aplica regra dos 80%: verifica se os top 3 cobrem >80% dos registros válidos.

    Retorna:
        (lista_de_provedores, contagem_por_provedor, pct_cobertura)
    """
    if df.empty or 'Ip_Dono' not in df.columns:
        return [], {}, 0.0

    # Filtrar linhas com provedor válido
    df_f = df[df['Ip_Dono'].notna() & (df['Ip_Dono'] != '')].copy()
    if df_f.empty:
        return [], {}, 0.0

    # Excluir proxy/hosting (não identificam usuário final).
    # bool_series já trata coluna ausente e loga tokens desconhecidos —
    # o apply(_parse_bool) anterior fazia uma chamada Python por linha.
    from validators import bool_series
    mask_clean = ~(bool_series(df_f, 'Ip_Proxy') | bool_series(df_f, 'Ip_Hospedagem'))
    df_clean = df_f[mask_clean]

    # Fallback: se o filtro removeu tudo, usar todos os registros válidos
    if df_clean.empty:
        df_clean = df_f

    contagem = df_clean['Ip_Dono'].value_counts()
    total_validos = len(df_clean)

    top3 = contagem.head(3)
    pct_cobertura = (top3.sum() / total_validos * 100) if total_validos > 0 else 0.0
    provedores_sel = list(top3.index)

    return provedores_sel, contagem.to_dict(), round(pct_cobertura, 1)


def detectar_cgnat(df):
    """
    Detecta IPs na faixa CGNAT (100.64.0.0/10).

    Retorna:
        dict com 'count', 'ips' e 'warning'
    """
    if df.empty or 'Ip' not in df.columns:
        return {'count': 0, 'ips': [], 'warning': ''}

    ips = df['Ip'].dropna().astype(str).str.strip()
    cgnat_ips = sorted({ip for ip in ips if is_cgnat_ip(ip)})
    count = len(cgnat_ips)

    warning = ''
    if count > 0:
        warning = (
            f"⚠️ {count} IP(s) em faixa CGNAT detectado(s). "
            "Esses endereços podem ser compartilhados por múltiplos usuários."
        )

    return {'count': count, 'ips': cgnat_ips, 'warning': warning}


# ============================================================
# 2. CALCULAR SCORE INVESTIGATIVO
# ============================================================

def calcular_score(df, dt_fato, periodo_fato, contagem_provedores, janela_horas_max=72.0):
    """
    Atribui pontuação investigativa (0-100) a cada registro IP.

    Critérios (total base = 95 pts, penalidade de até -10):
    - Proximidade temporal: 40 pts
    - Recorrência do provedor: 20 pts
    - Compatibilidade de período: 15 pts
    - Continuidade temporal: 15 pts
    - Bônus IPv6: +5 pts (mais rastreável que IPv4)
    - Penalidade proxy/hosting: -10 pts
    """
    df_scored = df.copy()
    df_scored['Score'] = 0.0
    dt_fato = _strip_tz(dt_fato)

    # Adicionar coluna Tipo_IP (v4/v6)
    if 'Ip' in df_scored.columns:
        df_scored['Tipo_IP'] = df_scored['Ip'].apply(lambda x: 'IPv6' if _is_ipv6(str(x)) else 'IPv4')
    else:
        df_scored['Tipo_IP'] = 'IPv4'

    # Converter coluna Data para datetime
    df_scored['_dt'] = _safe_datetime(df_scored.get('Data', pd.Series(dtype='object')))
    if df_scored['_dt'].dt.tz is not None:
        df_scored['_dt'] = df_scored['_dt'].dt.tz_localize(None)

    max_count = max(contagem_provedores.values()) if contagem_provedores else 1
    if max_count == 0:
        max_count = 1

    for idx in df_scored.index:
        try:
            row = df_scored.loc[idx]
            score = 0.0
            dt_reg = row.get('_dt')

            # 1. Proximidade temporal (40 pts)
            if pd.notna(dt_reg):
                diff_hours = abs((dt_reg - dt_fato).total_seconds()) / 3600
                if diff_hours <= janela_horas_max and janela_horas_max > 0:
                    score += 40 * (1 - diff_hours / janela_horas_max)

            # 2. Recorrência do provedor (20 pts)
            provedor = row.get('Ip_Dono', '')
            if provedor and provedor in contagem_provedores:
                score += 20 * (contagem_provedores[provedor] / max_count)

            # 3. Compatibilidade de período (15 pts) - comparação emoji-safe
            periodo_reg = row.get('Periodo', '')
            if _periodo_matches(periodo_reg, periodo_fato):
                score += 15

            # 4. Continuidade temporal (15 pts)
            if provedor and pd.notna(dt_reg):
                prov_mask = df_scored['Ip_Dono'] == provedor
                prov_dates = df_scored.loc[prov_mask, '_dt'].dropna()
                has_before = (prov_dates < dt_fato).any()
                has_after = (prov_dates > dt_fato).any()
                if has_before and has_after:
                    score += 15
                elif has_before or has_after:
                    score += 7

            # 5. Bônus IPv6 (+5 pts)
            if _is_ipv6(str(row.get('Ip', ''))):
                score += 5

            # 6. Penalidade proxy/hosting (-10 pts)
            is_proxy = _parse_bool(row.get('Ip_Proxy', False))
            is_hosting = _parse_bool(row.get('Ip_Hospedagem', False))
            if is_proxy or is_hosting:
                score -= 10

            df_scored.at[idx, 'Score'] = score

        except Exception:
            df_scored.at[idx, 'Score'] = 0

    df_scored['Score'] = df_scored['Score'].clip(0, 100).fillna(0).round(1)
    df_scored = df_scored.drop(columns=['_dt'], errors='ignore')
    return df_scored


# ============================================================
# 3. DETECTAR USUÁRIO ÚNICO
# ============================================================

def detectar_usuario_unico(df, dt_fato):
    """
    Estima probabilidade de que todos os registros pertençam ao mesmo usuário.

    Retorna:
        dict com 'score' (0-100) e 'indicadores' (dict)
    """
    score = 0
    indicadores = {}

    if df.empty:
        return {'score': 0, 'indicadores': {'Dados': '❌ DataFrame vazio'}}

    # Preparar dt_fato
    if hasattr(dt_fato, 'tzinfo') and dt_fato.tzinfo is not None:
        dt_fato = dt_fato.replace(tzinfo=None)

    # 1. Quantidade de provedores
    provedores = df['Ip_Dono'].dropna().unique() if 'Ip_Dono' in df.columns else []
    n_prov = len(provedores)
    if n_prov == 1:
        score += 30
        indicadores['Provedor'] = f"✅ Provedor único: {provedores[0]}"
    elif n_prov <= 3:
        score += 15
        indicadores['Provedor'] = f"⚠️ {n_prov} provedores: {', '.join(provedores[:3])}"
    else:
        indicadores['Provedor'] = f"❌ {n_prov} provedores distintos"

    # 2. Continuidade temporal
    df_dt = _safe_datetime(df.get('Data', pd.Series(dtype='object'))).dropna()
    if hasattr(df_dt, 'dt') and df_dt.dt.tz is not None:
        df_dt = df_dt.dt.tz_localize(None)

    if not df_dt.empty:
        has_before = (df_dt < dt_fato).any()
        has_after = (df_dt > dt_fato).any()
        if has_before and has_after:
            score += 25
            indicadores['Continuidade'] = "✅ Registros antes E depois do fato"
        elif has_before or has_after:
            score += 10
            lado = "antes" if has_before else "depois"
            indicadores['Continuidade'] = f"⚠️ Registros apenas {lado} do fato"
        else:
            indicadores['Continuidade'] = "❌ Sem registros temporais válidos"
    else:
        indicadores['Continuidade'] = "❌ Sem dados de data válidos"

    # 3. Padrão de horário
    if 'Periodo' in df.columns:
        periodos = df['Periodo'].value_counts()
        if not periodos.empty:
            pct_top = periodos.iloc[0] / len(df) * 100
            top_per = periodos.index[0]
            if pct_top >= 80:
                score += 20
                indicadores['Horário'] = f"✅ {pct_top:.0f}% dos acessos no período {top_per}"
            else:
                indicadores['Horário'] = f"⚠️ Distribuição mista: {top_per} ({pct_top:.0f}%)"
    else:
        indicadores['Horário'] = "⚠️ Coluna Periodo não disponível"

    # 4. IPs repetidos
    if 'Ip' in df.columns:
        ip_counts = df['Ip'].value_counts()
        ips_repetidos = (ip_counts > 1).sum()
        if ips_repetidos > 0:
            score += 15
            indicadores['IPs repetidos'] = f"✅ {ips_repetidos} IP(s) aparecem mais de uma vez"
        else:
            indicadores['IPs repetidos'] = "⚠️ Nenhum IP repetido"

    # 5. Proxy
    if 'Ip_Proxy' in df.columns:
        n_proxy = df['Ip_Proxy'].apply(_parse_bool).sum()
        if n_proxy == 0:
            score += 10
            indicadores['Proxy'] = "✅ Nenhum registro com proxy"
        else:
            score -= 10
            indicadores['Proxy'] = f"❌ {int(n_proxy)} registro(s) com proxy/VPN"
    else:
        indicadores['Proxy'] = "⚠️ Coluna Ip_Proxy não disponível"

    score = max(0, min(100, score))
    return {'score': score, 'indicadores': indicadores}


# ============================================================
# 4. SUGERIR IPs PARA INVESTIGAÇÃO
# ============================================================

def sugerir_ips_investigativos(df, dt_fato, provedores_sel, contagem_prov, ips_por_provedor=5):
    """
    Seleciona registros mais estratégicos para investigação.

    Técnica de seleção em 3 fases temporais:
            1. ANTES do fato - demonstra uso anterior da conexão
            2. DIA do fato - nexo causal (se houver registros)
            3. APÓS o fato - demonstra continuidade

    Para cada fase, prioriza IPv6 e seleciona o primeiro e o último
    registro IPv6 como âncoras obrigatórias. Diversifica horário
    garantindo registros diurnos e noturnos.

    Args:
        ips_por_provedor: 3 a 10 IPs por provedor (configurável na interface)

    Retorna DataFrame com registros selecionados + colunas auxiliares.
    """
    if df.empty or 'Score' not in df.columns or not provedores_sel:
        return pd.DataFrame()

    dt_fato = _strip_tz(dt_fato)
    df_work = df.copy()
    df_work['_dt'] = _safe_datetime(df_work.get('Data', pd.Series(dtype='object')))
    if df_work['_dt'].dt.tz is not None:
        df_work['_dt'] = df_work['_dt'].dt.tz_localize(None)
    df_work['_is_v6'] = df_work['Ip'].apply(lambda x: _is_ipv6(str(x))) if 'Ip' in df_work.columns else False

    resultados = []
    fato_date = dt_fato.date() if hasattr(dt_fato, 'date') else dt_fato

    for provedor in provedores_sel:
        prov_df = df_work[df_work['Ip_Dono'] == provedor].copy()
        if prov_df.empty:
            continue

        # Priorizar IPv6: usar apenas IPv6 se disponível
        prov_v6 = prov_df[prov_df['_is_v6']]
        pool = prov_v6 if not prov_v6.empty else prov_df
        has_v6 = not prov_v6.empty

        selecionados_idx = []
        max_n = min(ips_por_provedor, len(pool))

        com_dt = pool[pool['_dt'].notna()].copy()
        if com_dt.empty:
            # Sem datas, usar Score
            for idx_r in pool.sort_values('Score', ascending=False).head(max_n).index:
                selecionados_idx.append(idx_r)
        else:
            com_dt_sorted = com_dt.sort_values('_dt')
            com_dt['_diff_abs'] = (com_dt['_dt'] - dt_fato).abs()
            com_dt['_hour'] = com_dt['_dt'].dt.hour

            # ÂNCORA IPv6: primeiro e último IPv6 cronológico (se existirem)
            if has_v6:
                v6_sorted = com_dt_sorted[com_dt_sorted.index.isin(prov_v6.index)]
                if not v6_sorted.empty:
                    first_v6 = v6_sorted.iloc[0]
                    selecionados_idx.append(first_v6.name)
                    if len(v6_sorted) > 1:
                        last_v6 = v6_sorted.iloc[-1]
                        if last_v6.name not in selecionados_idx:
                            selecionados_idx.append(last_v6.name)
            else:
                # Sem IPv6: âncoras com primeiro e último do pool geral
                primeiro = com_dt_sorted.iloc[0]
                selecionados_idx.append(primeiro.name)
                if len(com_dt_sorted) > 1:
                    ultimo = com_dt_sorted.iloc[-1]
                    if ultimo.name not in selecionados_idx:
                        selecionados_idx.append(ultimo.name)

            # FASE 1: ANTES do fato (proximidade temporal + Score)
            antes = com_dt[(com_dt['_dt'] < dt_fato) & (~com_dt.index.isin(selecionados_idx))]
            antes = antes.sort_values(['_diff_abs', 'Score'], ascending=[True, False])
            slots_antes = max(1, (max_n - len(selecionados_idx)) // 3)
            for idx_r in antes.index:
                if len(selecionados_idx) >= max_n or slots_antes <= 0:
                    break
                selecionados_idx.append(idx_r)
                slots_antes -= 1

            # FASE 2: DIA do fato (nexo causal)
            dia_fato_df = com_dt[
                (com_dt['_dt'].dt.date == fato_date) &
                (~com_dt.index.isin(selecionados_idx))
            ]
            slots_fato = max(1, (max_n - len(selecionados_idx)) // 2)
            for idx_r in dia_fato_df.sort_values('Score', ascending=False).index:
                if len(selecionados_idx) >= max_n or slots_fato <= 0:
                    break
                selecionados_idx.append(idx_r)
                slots_fato -= 1

            # FASE 3: APÓS o fato (continuidade)
            depois = com_dt[(com_dt['_dt'] > dt_fato) & (~com_dt.index.isin(selecionados_idx))]
            depois = depois.sort_values(['_diff_abs', 'Score'], ascending=[True, False])
            for idx_r in depois.index:
                if len(selecionados_idx) >= max_n:
                    break
                selecionados_idx.append(idx_r)

            # DIVERSIFICAÇÃO: garantir 1 registro noturno (22-06h) e 1 diurno (06-18h)
            has_noturno = any(com_dt.loc[i, '_hour'] in range(0, 7) or com_dt.loc[i, '_hour'] >= 22
                              for i in selecionados_idx if i in com_dt.index)
            has_diurno = any(6 <= com_dt.loc[i, '_hour'] < 18
                             for i in selecionados_idx if i in com_dt.index)

            if not has_noturno and len(selecionados_idx) < max_n:
                noturno_pool = com_dt[
                    (com_dt['_hour'].isin(range(0, 7)) | (com_dt['_hour'] >= 22)) &
                    (~com_dt.index.isin(selecionados_idx))
                ].sort_values('Score', ascending=False)
                if not noturno_pool.empty:
                    # Substituir o item com menor Score (exceto âncoras IPv6)
                    if len(selecionados_idx) >= max_n and len(selecionados_idx) > 2:
                        scores = [(i, com_dt.loc[i, 'Score']) for i in selecionados_idx[2:]
                                  if i in com_dt.index]
                        if scores:
                            worst_idx = min(scores, key=lambda x: x[1])[0]
                            selecionados_idx.remove(worst_idx)
                    selecionados_idx.append(noturno_pool.index[0])

            if not has_diurno and len(selecionados_idx) < max_n:
                diurno_pool = com_dt[
                    (com_dt['_hour'].between(6, 17)) &
                    (~com_dt.index.isin(selecionados_idx))
                ].sort_values('Score', ascending=False)
                if not diurno_pool.empty:
                    if len(selecionados_idx) >= max_n and len(selecionados_idx) > 2:
                        scores = [(i, com_dt.loc[i, 'Score']) for i in selecionados_idx[2:]
                                  if i in com_dt.index]
                        if scores:
                            worst_idx = min(scores, key=lambda x: x[1])[0]
                            selecionados_idx.remove(worst_idx)
                    selecionados_idx.append(diurno_pool.index[0])

            # PREENCHER vagas restantes com maior Score
            restantes = com_dt[~com_dt.index.isin(selecionados_idx)].sort_values(
                'Score', ascending=False)
            for idx_r in restantes.index:
                if len(selecionados_idx) >= max_n:
                    break
                selecionados_idx.append(idx_r)

        # Montar resultado
        for idx_s in selecionados_idx:
            row = df_work.loc[idx_s].copy()
            row['Provedor_Selecionado'] = provedor
            resultados.append(row)

    if not resultados:
        return pd.DataFrame()

    df_result = pd.DataFrame(resultados)
    df_result = df_result.drop(columns=['_dt', '_diff_abs', '_hour', '_is_v6', '_dt_date'], errors='ignore')
    df_result = df_result.sort_values(['Provedor_Selecionado', 'Score'], ascending=[True, False])
    return df_result


# ============================================================
# 4b. IPs DE ATENÇÃO (outliers)
# ============================================================

def detectar_ips_atencao(df, dt_fato, provedores_sel):
    """
    Detecta IPs que merecem atenção especial mas não estão nos provedores top 3.
    Inclui: IPs do dia do fato fora dos top 3, IPs com score alto fora da seleção,
    IPs de datacenter/VPN.
    """
    if df.empty or 'Score' not in df.columns:
        return pd.DataFrame()

    dt_fato = _strip_tz(dt_fato)
    df_work = df.copy()
    df_work['_dt'] = _safe_datetime(df_work.get('Data', pd.Series(dtype='object')))
    if df_work['_dt'].dt.tz is not None:
        df_work['_dt'] = df_work['_dt'].dt.tz_localize(None)

    fato_date = dt_fato.date() if hasattr(dt_fato, 'date') else dt_fato
    atencao = []

    # IPs FORA dos top 3 provedores, mas no dia do fato
    fora_top3 = df_work[~df_work['Ip_Dono'].isin(provedores_sel)]
    if not fora_top3.empty and fora_top3['_dt'].notna().any():
        dia_fato_fora = fora_top3[fora_top3['_dt'].dt.date == fato_date]
        for _, row in dia_fato_fora.iterrows():
            atencao.append({
                'Ip': row.get('Ip', ''),
                'Data': row.get('Data', ''),
                'Provedor': row.get('Ip_Dono', ''),
                'Cidade': row.get('Ip_Cidade', ''),
                'Score': row.get('Score', 0),
                'Motivo': '📅 IP no dia do fato (provedor fora do top 3)',
            })

    # IPs com Score alto (>60) fora dos top 3
    high_score_fora = fora_top3[fora_top3['Score'] > 60]
    for _, row in high_score_fora.head(5).iterrows():
        ip = row.get('Ip', '')
        if not any(a['Ip'] == ip for a in atencao):
            atencao.append({
                'Ip': ip,
                'Data': row.get('Data', ''),
                'Provedor': row.get('Ip_Dono', ''),
                'Cidade': row.get('Ip_Cidade', ''),
                'Score': row.get('Score', 0),
                'Motivo': '⭐ Score alto (provedor fora do top 3)',
            })

    # IPs de proxy/hosting/datacenter
    proxy_mask = df_work.get('Ip_Proxy', pd.Series(False, index=df_work.index)).apply(_parse_bool)
    hosting_mask = df_work.get('Ip_Hospedagem', pd.Series(False, index=df_work.index)).apply(_parse_bool)
    suspicious = df_work[proxy_mask | hosting_mask]
    for _, row in suspicious.drop_duplicates(subset=['Ip']).head(5).iterrows():
        ip = row.get('Ip', '')
        if not any(a['Ip'] == ip for a in atencao):
            atencao.append({
                'Ip': ip,
                'Data': row.get('Data', ''),
                'Provedor': row.get('Ip_Dono', ''),
                'Cidade': row.get('Ip_Cidade', ''),
                'Score': row.get('Score', 0),
                'Motivo': '🛡️ Proxy/VPN/Datacenter',
            })

    return pd.DataFrame(atencao) if atencao else pd.DataFrame()


# ============================================================
# 4c. RESUMO NARRATIVO
# ============================================================

def gerar_resumo_narrativo(df, df_selecionados, provedores_sel, contagem_prov, dt_fato, alvo=''):
    """
    Gera texto descritivo automático para uso investigativo.
    """
    dt_fato = _strip_tz(dt_fato)
    lines = []

    if alvo:
        lines.append(f"ANÁLISE DE ENDEREÇOS IP - ALVO: {alvo}")
    lines.append(f"Data do fato investigado: {dt_fato.strftime('%d/%m/%Y')}")
    lines.append("")

    if df.empty:
        return "Sem dados para análise."

    # Estatísticas gerais
    total = len(df)
    unicos = df['Ip'].nunique() if 'Ip' in df.columns else 0
    n_v6 = df['Ip'].apply(lambda x: _is_ipv6(str(x))).sum() if 'Ip' in df.columns else 0
    n_v4 = unicos - n_v6

    dt_col = _safe_datetime(df.get('Data', pd.Series(dtype='object'))).dropna()
    periodo_str = ""
    if not dt_col.empty:
        periodo_str = f"no período de {dt_col.min().strftime('%d/%m/%Y')} a {dt_col.max().strftime('%d/%m/%Y')}"

    lines.append(f"Foram analisados {total} registros de acesso contendo {unicos} endereços IP "
                 f"únicos ({n_v6} IPv6, {n_v4} IPv4) {periodo_str}.")
    lines.append("")

    # Por provedor
    for prov in provedores_sel:
        qtd = contagem_prov.get(prov, 0)
        prov_df = df[df['Ip_Dono'] == prov] if 'Ip_Dono' in df.columns else pd.DataFrame()
        if prov_df.empty:
            continue

        prov_v6 = prov_df['Ip'].apply(lambda x: _is_ipv6(str(x))).sum() if 'Ip' in prov_df.columns else 0
        cidades = prov_df['Ip_Cidade'].dropna().unique() if 'Ip_Cidade' in prov_df.columns else []
        cidade_str = ', '.join(str(c) for c in cidades[:3])

        # Período predominante
        if 'Periodo' in prov_df.columns:
            per = prov_df['Periodo'].value_counts()
            per_pct = (per.iloc[0] / len(prov_df) * 100) if not per.empty else 0
            per_nome = per.index[0] if not per.empty else 'Misto'
        else:
            per_pct = 0
            per_nome = 'N/A'

        # IPs selecionados para este provedor
        of_prov = df_selecionados[df_selecionados['Provedor_Selecionado'] == prov] if not df_selecionados.empty and 'Provedor_Selecionado' in df_selecionados.columns else pd.DataFrame()
        n_sel = len(of_prov)

        as_info = prov_df['Ip_AS'].dropna().iloc[0] if 'Ip_AS' in prov_df.columns and not prov_df['Ip_AS'].dropna().empty else ''

        lines.append(f"PROVEDOR: {prov}" + (f" ({as_info})" if as_info else ""))
        lines.append(f"  - {qtd} registros, {prov_v6} IPv6")
        lines.append(f"  - Cidade(s): {cidade_str}")
        lines.append(f"  - Padrão: {per_pct:.0f}% {per_nome}")
        lines.append(f"  - {n_sel} endereços IP selecionados para investigação")
        lines.append("")

    # Conclusão
    lines.append("CONCLUSÃO:")
    lines.append(f"Os registros indicam utilização concentrada nos provedores "
                 f"{', '.join(provedores_sel)}, com predominância de endereços IPv6, "
                 f"sugerindo continuidade de uso pelo mesmo usuário. "
                 f"Os endereços selecionados demonstram atividade antes, durante e após "
                 f"a data do fato ({dt_fato.strftime('%d/%m/%Y')}), "
                 f"em diferentes horários do dia, reforçando a hipótese de utilização "
                 f"residencial/pessoal da conexão.")

    return '\n'.join(lines)


# ============================================================
# 5. INTERFACE STREAMLIT
# ============================================================

def render_analise_investigativa(df):
    """
    Renderiza a interface completa de análise investigativa v2.0.
    Chamada pela aplicação principal com o DataFrame já carregado.
    """
    st.markdown(f"""<div style="background:linear-gradient(135deg,{COLORS['surface']},{COLORS['surface_elevated']});
        border:1px solid {COLORS['border']};border-radius:12px;padding:24px;margin-bottom:24px;
        position:relative;overflow:hidden;">
        <div style="position:absolute;top:-30%;right:-10%;width:200px;height:200px;border-radius:50%;
            background:radial-gradient(circle,{COLORS['danger']}14 0%,transparent 70%);"></div>
        <h2 style="margin:0;background:linear-gradient(135deg,{COLORS['danger']},{COLORS['warning']});
            -webkit-background-clip:text;-webkit-text-fill-color:transparent;position:relative;">
            🔍 Análise Investigativa de IPs v2.0</h2>
        <p style="color:{COLORS['text_muted']};margin:4px 0 0 0;position:relative;">
            Prioridade IPv6 · Âncoras temporais · Diversificação de horário · Resumo narrativo</p>
    </div>""", unsafe_allow_html=True)

    if df is None or df.empty:
        st.warning("⚠️ Nenhum dado disponível. Processe dados na aba **Entrada** primeiro.")
        return

    # ---- PAINEL DE CONFIGURAÇÃO ----
    with st.expander("⚙️ Configuração da Análise", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            data_fato = st.date_input("📅 Data do Fato *", value=datetime.now().date(),
                                       key="inv_data_fato")
            hora_fato = st.time_input("🕐 Horário do Fato (opcional)",
                                       value=None, key="inv_hora_fato")

        with c2:
            periodo_fato = st.selectbox("🌗 Período do Fato",
                                         ["Diurno", "Noturno"], key="inv_periodo")
            janela_horas = st.slider("⏱️ Janela temporal (horas)",
                                      min_value=6, max_value=168, value=72,
                                      key="inv_janela")

        with c3:
            ips_por_prov = st.slider("🔢 IPs por provedor",
                                      min_value=3, max_value=10, value=5,
                                      key="inv_ips_prov")
            st.caption("IPv6 tem prioridade sobre IPv4")

    # ---- BOTÃO DE EXECUÇÃO ----
    if st.button("🚀 Executar Análise Investigativa", type="primary",
                  key="inv_executar"):

        if hora_fato is not None:
            dt_fato = datetime.combine(data_fato, hora_fato)
        else:
            dt_fato = datetime.combine(data_fato, datetime.min.time())

        with st.spinner("Executando análise investigativa..."):
            provedores_sel, contagem_prov, pct_cobertura = selecionar_provedores(df)

            df_scored = calcular_score(
                df, dt_fato, periodo_fato, contagem_prov,
                janela_horas_max=float(janela_horas))

            resultado_unicidade = detectar_usuario_unico(df_scored, dt_fato)

            df_selecionados = sugerir_ips_investigativos(
                df_scored, dt_fato, provedores_sel, contagem_prov,
                ips_por_provedor=ips_por_prov)

            df_atencao = detectar_ips_atencao(df_scored, dt_fato, provedores_sel)

            alvo = st.session_state.get('alvo', '')
            resumo_narrativo = gerar_resumo_narrativo(
                df_scored, df_selecionados, provedores_sel, contagem_prov, dt_fato, alvo)

        st.session_state['inv_result'] = {
            'df_scored': df_scored,
            'provedores_sel': provedores_sel,
            'contagem_prov': contagem_prov,
            'resultado_unicidade': resultado_unicidade,
            'df_selecionados': df_selecionados,
            'df_atencao': df_atencao,
            'resumo_narrativo': resumo_narrativo,
            'dt_fato': dt_fato,
            'pct_cobertura': pct_cobertura,
        }

    # ---- EXIBIR RESULTADOS ----
    if 'inv_result' not in st.session_state:
        st.info("📌 Configure os parâmetros acima e clique em **Executar Análise Investigativa**.")
        return

    res = st.session_state['inv_result']
    df_scored = res['df_scored']
    provedores_sel = res['provedores_sel']
    contagem_prov = res['contagem_prov']
    resultado_unicidade = res['resultado_unicidade']
    df_selecionados = res['df_selecionados']
    df_atencao = res.get('df_atencao', pd.DataFrame())
    resumo_narrativo = res.get('resumo_narrativo', '')
    pct_cobertura = res.get('pct_cobertura', 0)
    dt_fato = res.get('dt_fato', datetime.now())

    # Aviso de cobertura (80% threshold)
    if pct_cobertura < 80 and provedores_sel:
        st.warning(
            f"⚠️ Os 3 provedores selecionados representam **{pct_cobertura}%** dos registros. "
            "A lista pode conter acessos distribuídos entre muitos provedores, "
            "o que pode indicar múltiplos usuários ou uso de infraestrutura intermediária."
        )
    elif provedores_sel:
        st.success(f"✅ Os {len(provedores_sel)} provedores selecionados cobrem **{pct_cobertura}%** dos registros.")

    # ---- MÉTRICAS RÁPIDAS ----
    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
    with mc1:
        st.metric("📋 Registros", len(df_scored))
    with mc2:
        st.metric("🏢 Provedores", len(provedores_sel))
    with mc3:
        st.metric("📨 Selecionados", len(df_selecionados))
    with mc4:
        avg_score = df_selecionados['Score'].mean() if not df_selecionados.empty else 0
        st.metric("⭐ Score Médio", f"{avg_score:.1f}")
    with mc5:
        n_v6 = df_scored['Tipo_IP'].eq('IPv6').sum() if 'Tipo_IP' in df_scored.columns else 0
        st.metric("🌐 IPv6", n_v6)

    # ---- ABAS DE RESULTADO ----
    tab_prov, tab_score, tab_unico, tab_selecionados, tab_atencao, tab_v6, tab_resumo = st.tabs([
        "📋 Provedores",
        "🏆 Score",
        "👤 Usuário Único",
        "📨 IPs Selecionados",
        "⚠️ Atenção",
        "🌐 IPv6/CGNAT",
        "📝 Resumo"
    ])

    # ---- ABA 1: Provedores ----
    with tab_prov:
        st.subheader("📋 Provedores Selecionados (Top 3)")
        if provedores_sel:
            total_validos = sum(contagem_prov.values()) or 1
            prov_data = []
            for p in provedores_sel:
                qtd = contagem_prov.get(p, 0)
                prov_df = df_scored[df_scored['Ip_Dono'] == p] if 'Ip_Dono' in df_scored.columns else pd.DataFrame()
                n_v6_p = prov_df['Tipo_IP'].eq('IPv6').sum() if 'Tipo_IP' in prov_df.columns else 0
                prov_data.append({
                    'Provedor': p,
                    'Registros': qtd,
                    'IPv6': n_v6_p,
                    'IPv4': qtd - n_v6_p,
                    '% Total': f"{qtd / total_validos * 100:.1f}%",
                })
            df_prov = pd.DataFrame(prov_data).sort_values('Registros', ascending=False)
            st.dataframe(df_prov, use_container_width=True, hide_index=True)
            st.caption(f"Cobertura: **{pct_cobertura}%** de {total_validos} registros válidos")
        else:
            st.warning("Nenhum provedor selecionado")

    # ---- ABA 2: Score Investigativo ----
    with tab_score:
        st.subheader("🏆 Score Investigativo")
        score_cols = ['Ip', 'Tipo_IP', 'Data', 'Ip_Dono', 'Ip_Regiao', 'Ip_Cidade',
                      'Ip_Proxy', 'Ip_Hospedagem', 'Periodo', 'Score']
        available_cols = [c for c in score_cols if c in df_scored.columns]
        df_show = df_scored[available_cols].sort_values('Score', ascending=False).copy()
        df_show['Score'] = df_show['Score'].fillna(0)

        st.dataframe(
            df_show.style.background_gradient(subset=['Score'], cmap='RdYlGn', vmin=0, vmax=100),
            use_container_width=True, height=500, hide_index=True
        )

        csv_score = df_show.to_csv(index=False, sep=';', encoding='utf-8-sig')
        st.download_button("📥 Baixar Score CSV", csv_score.encode('utf-8'),
                           "score_investigativo.csv", "text/csv", key="inv_dl_score")

    # ---- ABA 3: Usuário Único ----
    with tab_unico:
        st.subheader("👤 Detecção de Usuário Único")
        score_unico = resultado_unicidade['score']
        indicadores = resultado_unicidade['indicadores']

        if score_unico >= 70:
            emoji, cor = "🟢", COLORS['success']
            interpretacao = "Alta probabilidade de ser um único usuário"
        elif score_unico >= 40:
            emoji, cor = "🟡", COLORS['warning']
            interpretacao = "Probabilidade moderada - pode haver mais de um usuário"
        else:
            emoji, cor = "🔴", COLORS['danger']
            interpretacao = "Baixa probabilidade - possível compartilhamento ou múltiplos dispositivos"

        st.markdown(f"""
        <div style="background:linear-gradient(135deg,{COLORS['surface']},{COLORS['surface_elevated']});border:1px solid {COLORS['border']};
            border-radius:12px;padding:24px;text-align:center;margin-bottom:16px;">
            <span style="font-size:3em;">{emoji}</span>
            <h2 style="margin:8px 0;color:{cor};">{score_unico}/100</h2>
            <p style="color:{COLORS['text_muted']};margin:0;">{interpretacao}</p>
        </div>""", unsafe_allow_html=True)

        for nome, texto in indicadores.items():
            st.markdown(f"- **{nome}:** {texto}")

    # ---- ABA 4: IPs Selecionados ----
    with tab_selecionados:
        st.subheader("📨 IPs Selecionados para Investigação")

        if df_selecionados.empty:
            st.warning("Nenhum IP sugerido.")
        else:
            sel_cols = ['Provedor_Selecionado', 'Ip', 'Tipo_IP', 'Data', 'Ip_Dono',
                           'Ip_Regiao', 'Ip_Cidade', 'Periodo', 'Score']
            available_of = [c for c in sel_cols if c in df_selecionados.columns]
            df_of_show = df_selecionados[available_of].copy().reset_index(drop=True)
            df_of_show['Score'] = df_of_show['Score'].fillna(0)

            st.markdown(f"**{len(df_of_show)} IPs sugeridos** (IPv6 prioritário) - Selecione até **10** para exportação:")

            options = []
            for i, row in df_of_show.iterrows():
                tipo = row.get('Tipo_IP', '')
                label = f"[{tipo}] {row.get('Ip', '')} | {row.get('Ip_Dono', '')} | {str(row.get('Data', ''))[:16]} | Score: {row.get('Score', 0)}"
                options.append(label)

            selected = st.multiselect(
                "Selecione os IPs para exportação",
                options=options,
                default=options[:min(10, len(options))],
                max_selections=10,
                key="inv_select_ips"
            )

            n_sel = len(selected)
            st.caption(f"{'✅' if n_sel > 0 else '⚠️'} **{n_sel} de 10** selecionados")

            st.dataframe(
                df_of_show.style.background_gradient(subset=['Score'], cmap='RdYlGn', vmin=0, vmax=100),
                use_container_width=True, height=400, hide_index=True
            )

            st.divider()
            if selected:
                sel_indices = [options.index(s) for s in selected if s in options]
                df_selected = df_of_show.iloc[sel_indices]
                csv_selecionados = df_selected.to_csv(index=False, sep=';', encoding='utf-8-sig')
                st.download_button(
                    f"📥 Baixar {len(df_selected)} IPs Selecionados (CSV)",
                    csv_selecionados.encode('utf-8'),
                    "ips_selecionados.csv", "text/csv", key="inv_dl_selecionados"
                )

            st.divider()
            st.markdown("**Resumo por Provedor:**")
            if 'Provedor_Selecionado' in df_selecionados.columns:
                resumo = df_selecionados.groupby('Provedor_Selecionado').agg(
                    Qtd=('Ip', 'count'),
                    IPv6=('Tipo_IP', lambda x: (x == 'IPv6').sum()) if 'Tipo_IP' in df_selecionados.columns else ('Ip', 'count'),
                    Score_Medio=('Score', 'mean')
                ).sort_values('Score_Medio', ascending=False).reset_index()
                resumo.columns = ['Provedor', 'Qtd IPs', 'IPv6', 'Score Médio']
                resumo['Score Médio'] = resumo['Score Médio'].round(1)
                st.dataframe(resumo, use_container_width=True, hide_index=True)

        # ---- ASSISTENTE AI ----
            st.divider()
            st.markdown("### 🤖 Assistente AI")
            st.caption("Consulte a AI para uma segunda opinião sobre a seleção de IPs")

            from ai_assistant import (
                AI_MODELS,
                check_model_available,
                check_ollama_status,
                get_default_ai_tier,
                run_ai_analysis,
            )

            ai_tier = st.session_state.get('ai_tier', get_default_ai_tier())
            if ai_tier not in AI_MODELS:
                ai_tier = get_default_ai_tier()
            ai_url = st.session_state.get('ai_ollama_url', 'http://localhost:11434')

            col_ai1, col_ai2 = st.columns([2, 1])
            with col_ai1:
                status = check_ollama_status(ai_url)
                if status['online']:
                    model_info = AI_MODELS.get(ai_tier, AI_MODELS[get_default_ai_tier()])
                    model_available = check_model_available(model_info['model'], ai_url)
                    if model_available:
                        st.markdown(f'<span class="badge badge-green">🟢 Ollama Online</span> '
                                    f'<span class="badge badge-blue">{model_info["label"]}</span>',
                                    unsafe_allow_html=True)
                    else:
                        st.warning(f"Modelo `{model_info['model']}` não encontrado. "
                                   f"Execute: `ollama pull {model_info['model']}`")
                else:
                    st.error("🔴 Ollama offline. Inicie com `ollama serve`")

            with col_ai2:
                ai_btn_disabled = not status.get('online', False)
                if st.button("🤖 Consultar AI", type="secondary", key="inv_ai_btn",
                              disabled=ai_btn_disabled):
                    with st.spinner("🤖 AI analisando dados..."):
                        resultado_ai = run_ai_analysis(
                            df_scored=df_scored,
                            provedores_sel=provedores_sel,
                            contagem_prov=contagem_prov,
                            dt_fato=dt_fato,
                            periodo_fato=st.session_state.get('inv_periodo', '☀️ Diurno'),
                            janela_horas=st.session_state.get('inv_janela', 72),
                            ips_por_provedor=st.session_state.get('inv_ips_prov', 5),
                            tier=ai_tier,
                            alvo=st.session_state.get('alvo', ''),
                            base_url=ai_url,
                        )
                        st.session_state['inv_ai_result'] = resultado_ai

            if 'inv_ai_result' in st.session_state:
                ai_res = st.session_state['inv_ai_result']
                if ai_res['success']:
                    data = ai_res['data']
                    st.markdown(f"**Modelo:** `{ai_res['model_used']}` | "
                                f"**Tempo:** {ai_res['elapsed_seconds']:.1f}s | "
                                f"**Confiança:** {data.get('confianca', 'N/A')}")
                    if ai_res.get('fallback_used'):
                        st.info(
                            f"Fallback automático ativado: solicitado `{ai_res.get('requested_model')}`, "
                            f"usado `{ai_res.get('model_used')}`."
                        )
                    for note in ai_res.get('notes', []):
                        st.info(note)
                    for alerta in data.get('alertas', []):
                        st.warning(alerta)
                    for prov in data.get('provedores', []):
                        with st.expander(f"🏢 {prov['nome']} - {len(prov.get('ips_selecionados', []))} IPs "
                                         f"({prov.get('percentual_cobertura', 0):.1f}%)", expanded=True):
                            st.caption(prov.get('justificativa', ''))
                            df_ai_ips = pd.DataFrame(prov.get('ips_selecionados', []))
                            if not df_ai_ips.empty:
                                st.dataframe(df_ai_ips, hide_index=True, use_container_width=True)
                    with st.expander("📝 Resumo Narrativo (AI)", expanded=False):
                        st.code(data.get('resumo_narrativo', ''), language=None)
                        st.download_button("📥 Baixar Resumo AI (TXT)",
                            data.get('resumo_narrativo', '').encode('utf-8'),
                            "resumo_ai.txt", "text/plain", key="inv_dl_ai_resumo")
                else:
                    for note in ai_res.get('notes', []):
                        st.warning(note)
                    st.error(f"Erro na análise AI: {ai_res.get('error', 'Desconhecido')}")

    # ---- ABA 5: IPs de Atenção ----
    with tab_atencao:
        st.subheader("⚠️ IPs de Atenção")
        st.caption("IPs que merecem análise individual - fora dos top 3 provedores mas potencialmente relevantes")

        if df_atencao.empty:
            st.success("✅ Nenhum IP de atenção detectado fora dos provedores selecionados.")
        else:
            st.dataframe(df_atencao, use_container_width=True, hide_index=True)
            st.caption(f"{len(df_atencao)} IP(s) de atenção encontrados")

    # ---- ABA 6: IPv6 /64 e CGNAT ----
    with tab_v6:
        st.subheader("🌐 Análise IPv6 /64 e Detecção CGNAT")

        # IPv6 /64 Grouping
        st.markdown("**Agrupamento por Prefixo IPv6 /64**")
        st.caption("IPs do mesmo prefixo /64 provavelmente vêm do mesmo roteador/rede doméstica")
        df_v6_groups = agrupar_ipv6_por_prefixo(df_scored)
        if not df_v6_groups.empty:
            st.dataframe(df_v6_groups, use_container_width=True, hide_index=True)
            n_prefixes = len(df_v6_groups)
            n_single = (df_v6_groups['Qtd_IPs'] == 1).sum()
            st.markdown(f"**{n_prefixes}** prefixos /64 encontrados. "
                        f"**{n_prefixes - n_single}** prefixos com múltiplos IPs (forte indício de mesmo roteador).")
        else:
            st.info("Nenhum endereço IPv6 encontrado nos dados.")

        st.divider()

        # CGNAT Detection
        st.markdown("**Detecção de CGNAT (Carrier-Grade NAT)**")
        st.caption("IPs na faixa 100.64.0.0/10 são compartilhados por múltiplos usuários e NÃO identificam um indivíduo")
        cgnat_result = detectar_cgnat(df_scored)
        if cgnat_result['count'] > 0:
            st.error(cgnat_result['warning'])
            st.markdown(f"IPs CGNAT: `{'`, `'.join(cgnat_result['ips'][:10])}`")
        else:
            st.success("✅ Nenhum IP em range CGNAT detectado.")

    # ---- ABA 7: Resumo Narrativo ----
    with tab_resumo:
        st.subheader("📝 Resumo Narrativo")
        st.caption("Texto descritivo gerado automaticamente - copie e adapte conforme necessário")

        if resumo_narrativo:
            st.code(resumo_narrativo, language=None)
            st.download_button(
                "📥 Baixar Resumo (TXT)",
                resumo_narrativo.encode('utf-8'),
                "resumo_investigativo.txt", "text/plain", key="inv_dl_resumo"
            )
        else:
            st.info("Resumo não disponível.")
