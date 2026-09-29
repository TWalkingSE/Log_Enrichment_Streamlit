"""Texto livre e listas de IPs: a data de cada IP é a da própria linha."""

import logging
import os
import re

import pandas as pd

from api_client import is_valid_ip
from data_processing.formats import COLUNAS_MODELO, IP_REGEX_PATTERN
from data_processing.timezone import (
    TZ_LABEL,
    TZ_OFFSET_HOURS,
    format_iso_date,
    get_periodo,
)
from validators import parse_data

logger = logging.getLogger(__name__)


def detectar_separador_csv(arquivo):
    """Detecta o separador usado em um arquivo CSV"""
    try:
        with open(arquivo, 'r', encoding='utf-8', errors='replace') as f:
            primeira_linha = f.readline().strip()

        # Verificar separadores comuns
        for sep in [';', ',', '\t', '|']:
            if sep in primeira_linha:
                return sep

        # Padrão
        return ','
    except (OSError, UnicodeError):
        return ','


# Data/hora numa linha de texto livre: ISO (`2024-03-05 10:00[:00]`, com `T`
# opcional) ou numérica (`05/03/2024 10:00[:00]`). A ordem dia/mês desta
# última é decidida depois, pela coluna inteira (`parse_data`).
_DATA_LINHA_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{1,2}:\d{2}(?::\d{2})?'
    r'|\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}(?::\d{2})?')
# Marcador de UTC logo depois da data: `Z`, `UTC`, `GMT` ou `+00:00`.
_UTC_APOS_DATA_RE = re.compile(r'\s*(?:Z\b|UTC\b|GMT\b|\+00:?00\b)')


def _registros_por_linha(content, alvo, data_padrao=None):
    """Extrai IPs de texto livre associando cada um à data DA MESMA LINHA.

    Antes, o texto livre ou perdia as datas (formato simples) ou emparelhava
    a n-ésima data do texto com o n-ésimo IP (método alternativo): uma linha
    sem data deslocava a data de todos os registros seguintes — datas
    atribuídas ao IP errado. Aqui:

    - uma data na linha: vale para os IPs daquela linha;
    - nenhuma data: `data_padrao` (data do nome do arquivo, quando houver)
      ou vazio — nada é inventado;
    - mais de uma data na linha: ambíguo, fica vazio e é contado no log.

    Data com marcador de UTC (`Z`, `UTC`, `GMT`, `+00:00`) é convertida para o
    fuso local configurado. Data ISO também é convertida quando "UTC" aparece
    em qualquer ponto do texto (cabeçalhos como "horários em UTC") — o
    critério que o método anterior já aplicava. Data numérica sem marcador é
    mantida como escrita.
    """
    ips, brutas, utc = [], [], []
    ambiguas = 0
    utc_no_texto = 'UTC' in content
    for linha in content.splitlines():
        datas = list(_DATA_LINHA_RE.finditer(linha))
        # A data sai da linha antes de buscar IPs: `10:00:00` casa com o
        # padrão de IPv6 (e só é descartado pela validação).
        sem_datas = _DATA_LINHA_RE.sub(' ', linha)
        ips_linha = [ip for ip in re.findall(IP_REGEX_PATTERN, sem_datas) if is_valid_ip(ip)]
        if not ips_linha:
            continue
        bruta, eh_utc = None, False
        if len(datas) == 1:
            m = datas[0]
            bruta = re.sub(r'[T,]', ' ', m.group(0))
            bruta = re.sub(r'\s+', ' ', bruta).strip()
            eh_utc = (bool(_UTC_APOS_DATA_RE.match(linha, m.end()))
                      or (utc_no_texto and bruta[:4].isdigit()))
        elif len(datas) > 1:
            ambiguas += 1
        if bruta is None and data_padrao:
            bruta = data_padrao
        for ip in ips_linha:
            ips.append(ip)
            brutas.append(bruta)
            utc.append(eh_utc)

    if ambiguas:
        logger.warning("%d linha(s) com mais de uma data: registros sem data atribuída", ambiguas)

    brutas_s = pd.Series(brutas, dtype='object')
    dt = parse_data(brutas_s) if len(brutas_s) else pd.Series([], dtype='datetime64[ns]')
    dt = pd.to_datetime(dt, errors='coerce')
    utc_s = pd.Series(utc, dtype=bool)
    if utc_s.any():
        dt = dt.where(~utc_s, dt + pd.Timedelta(hours=TZ_OFFSET_HOURS))
    falhas = int((dt.isna() & brutas_s.notna()).sum())
    if falhas:
        logger.warning("%d data(s) de texto livre não interpretáveis; registros sem data", falhas)

    ok = dt.notna()
    df = pd.DataFrame({'Alvo': alvo, 'Ip': ips}, columns=['Alvo', 'Ip'])
    df['Data'] = dt.dt.strftime('%Y-%m-%d %H:%M:%S').where(ok, None)
    df['Data_Fuso'] = pd.Series(TZ_LABEL, index=df.index).where(ok, None)
    df['Periodo'] = dt.dt.hour.map(lambda h: get_periodo(int(h)) if pd.notna(h) else None)
    df['ISO_Date'] = dt.map(lambda d: format_iso_date(d.to_pydatetime()) if pd.notna(d) else None)
    for col in COLUNAS_MODELO:
        if col not in df.columns:
            df[col] = False if col in ('Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor') else None
    return df[COLUNAS_MODELO]


def extrair_ips_do_formato_simples(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs de um texto no formato simples (Modelo Endereços IP)

    Args:
        content: Conteúdo do texto
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs extraídos
    """
    if update_callback:
        update_callback("Extraindo IPs do formato simples")

    # Mantém todos os registros, inclusive repetidos; a data, quando existe,
    # é a da própria linha.
    df = _registros_por_linha(content, alvo)

    if update_callback:
        com_data = int(df['Data'].notna().sum())
        update_callback(f"Extraídos {len(df)} registros ({df['Ip'].nunique()} IPs únicos) do "
                        f"formato simples — {com_data} com data")

    return df


def extrair_ips_texto_simples(file_path_or_content, update_callback=None, is_file=True, alvo='desconhecido'):
    """
    Método alternativo para extrair IPs e datas de arquivos de texto
    usando uma abordagem mais simples de busca por padrões
    """
    try:
        if update_callback:
            update_callback(f"Tentando método alternativo de extração para textos")

        # Obter o conteúdo do texto
        if is_file:
            with open(file_path_or_content, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        else:
            content = file_path_or_content

        # Data do nome do arquivo (ex.: 20250310123909): usada só nas linhas
        # que não trazem data própria.
        file_date = None
        if is_file:
            filename = os.path.basename(file_path_or_content)
            timestamp_match = re.search(r'(\d{14})', filename)
            if timestamp_match:
                ts = timestamp_match.group(1)
                file_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}"

        # Emparelhar a n-ésima data do texto com o n-ésimo IP (como antes)
        # atribuía datas ao IP errado assim que uma linha vinha sem data.
        df = _registros_por_linha(content, alvo, data_padrao=file_date)

        if update_callback:
            update_callback(f"Método alternativo extraiu {len(df)} registros ({df['Ip'].nunique()} IPs únicos)")

        return df

    except (OSError, UnicodeError, TypeError, ValueError) as e:
        logger.error(f"Erro no método alternativo: {e}", exc_info=True)
        if update_callback:
            update_callback(f"Erro no método alternativo: {e}")
        # Retornar DataFrame vazio com as colunas do modelo
        return pd.DataFrame(columns=COLUNAS_MODELO)
