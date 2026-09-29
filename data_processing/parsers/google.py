"""Google: relatório "IP ACTIVITY" e CSV do Preservation (Takeout)."""

import io
import logging
import re
from datetime import datetime

import pandas as pd

from api_client import is_valid_ip
from data_processing.formats import COLUNAS_MODELO
from data_processing.timezone import (
    TZ_LABEL,
    convert_utc_to_local,
    format_iso_date,
    get_periodo,
)
from validators import as_bool

logger = logging.getLogger(__name__)


def extrair_ips_do_formato_google(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs e timestamps do formato Google (IP ACTIVITY com formato tabular)

    O formato Google tem uma seção 'IP ACTIVITY' seguida de uma linha de cabeçalho
    e depois linhas com: Timestamp\tIP Address\tActivity Type\t...

    Args:
        content: Conteúdo do arquivo
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs e dados temporais extraídos
    """
    if update_callback:
        update_callback("Processando formato Google (IP ACTIVITY)...")

    registros = []

    # Encontrar a seção IP ACTIVITY
    ip_activity_pos = content.find('IP ACTIVITY')
    if ip_activity_pos < 0:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    # Pegar texto após IP ACTIVITY
    section = content[ip_activity_pos:]
    lines = section.split('\n')

    # Pular cabeçalho (IP ACTIVITY, linha em branco, linha de títulos das colunas)
    data_started = False
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('IP ACTIVITY') or line.startswith('Timestamp'):
            data_started = True
            continue
        if not data_started:
            continue

        # Tentar extrair timestamp e IP da linha tabular
        # Formato: 2023-02-25 04:34:32 Z\tIP_ADDRESS\tActivity...
        # Usar regex para capturar data+hora e IP
        m = re.match(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*Z?\s+(\S+)',
            line
        )
        if m:
            timestamp_str = m.group(1).strip()
            ip_raw = m.group(2).strip()

            # Validar IP
            if not is_valid_ip(ip_raw):
                continue

            # Converter UTC para fuso local configurável
            try:
                dt_utc = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                dt_local = convert_utc_to_local(dt_utc)
                data_formatada = dt_local.strftime('%Y-%m-%d %H:%M:%S')
                hora = dt_local.hour
                periodo = get_periodo(hora)
                iso_date = format_iso_date(dt_local)
            except (TypeError, ValueError) as e:
                logger.warning(f"Erro ao converter data '{timestamp_str}': {e}")
                data_formatada = timestamp_str
                periodo = None
                iso_date = None

            registro = {
                'Alvo': alvo,
                'Ip': ip_raw,
                'Data': data_formatada,
                'Data_Fuso': TZ_LABEL,
                'Ip_Dono': None,
                'Ip_AS': None,
                'Ip_Regiao': None,
                'Ip_Cidade': None,
                'Ip_Pais': None,
                'Ip_Pais_Codigo': None,
                'Ip_Movel': False,
                'Ip_Proxy': False,
                'Ip_Hospedagem': False,
                'Ip_Tor': False,
                'Ip_Lat': None,
                'Ip_Lon': None,
                'Periodo': periodo,
                'ISO_Date': iso_date
            }
            registros.append(registro)

    if not registros:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    df = pd.DataFrame(registros)

    if update_callback:
        update_callback(f"Extraídos {len(df)} IPs com timestamps do formato Google")

    return df


def extrair_ips_do_formato_preservation_google(content_or_df, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs, timestamps e User Agent do formato Preservation Google (CSV do Google Takeout).

    O formato Preservation Google é um CSV com colunas:
    Gaia ID, Activity Timestamp, IP Address, Proxiedhost IP Address,
    Is Non-routable IP Address, User Agent String, Product Name, ...

    Args:
        content_or_df: Conteúdo CSV (string) ou DataFrame já parseado
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs, dados temporais e User_Agent extraídos
    """
    if update_callback:
        update_callback("Processando formato Preservation Google...")

    # Aceitar tanto texto CSV quanto DataFrame pré-parseado
    if isinstance(content_or_df, pd.DataFrame):
        df_csv = content_or_df
    else:
        try:
            df_csv = pd.read_csv(
                io.StringIO(content_or_df),
                encoding='utf-8',
                on_bad_lines='skip'
            )
        except (pd.errors.ParserError, UnicodeError, TypeError, ValueError) as e:
            logger.warning(f"Erro ao parsear CSV Preservation Google: {e}")
            return pd.DataFrame(columns=COLUNAS_MODELO)

    # Verificar colunas obrigatórias
    required_cols = ['Activity Timestamp', 'IP Address']
    if not all(col in df_csv.columns for col in required_cols):
        logger.warning(f"Colunas obrigatórias não encontradas: {required_cols}")
        return pd.DataFrame(columns=COLUNAS_MODELO)

    registros = []

    for _, row in df_csv.iterrows():
        # Filtrar IPs não roteáveis
        if 'Is Non-routable IP Address' in df_csv.columns:
            if as_bool(row.get('Is Non-routable IP Address'), field='Is Non-routable IP Address'):
                continue

        ip_raw = str(row.get('IP Address', '')).strip()
        if not ip_raw or not is_valid_ip(ip_raw):
            continue

        # Extrair e converter timestamp (formato: "YYYY-MM-DD HH:MM:SS UTC")
        timestamp_str = str(row.get('Activity Timestamp', '')).strip()
        data_formatada = None
        periodo = None
        iso_date = None

        if timestamp_str and timestamp_str != 'nan':
            try:
                # Remover "UTC" e parsear
                ts_clean = timestamp_str.replace(' UTC', '').strip()
                dt_utc = datetime.strptime(ts_clean, '%Y-%m-%d %H:%M:%S')
                dt_local = convert_utc_to_local(dt_utc)
                data_formatada = dt_local.strftime('%Y-%m-%d %H:%M:%S')
                periodo = get_periodo(dt_local.hour)
                iso_date = format_iso_date(dt_local)
            except (TypeError, ValueError) as e:
                logger.warning(f"Erro ao converter timestamp '{timestamp_str}': {e}")
                data_formatada = timestamp_str
                periodo = None
                iso_date = None

        # Extrair User Agent
        user_agent = str(row.get('User Agent String', '')).strip()
        if user_agent == 'nan':
            user_agent = ''

        registro = {
            'Alvo': alvo,
            'Ip': ip_raw,
            'User_Agent': user_agent,
            'Data': data_formatada,
            'Data_Fuso': TZ_LABEL if data_formatada else None,
            'Ip_Dono': None,
            'Ip_AS': None,
            'Ip_Regiao': None,
            'Ip_Cidade': None,
            'Ip_Pais': None,
            'Ip_Pais_Codigo': None,
            'Ip_Movel': False,
            'Ip_Proxy': False,
            'Ip_Hospedagem': False,
            'Ip_Tor': False,
            'Ip_Lat': None,
            'Ip_Lon': None,
            'Periodo': periodo,
            'ISO_Date': iso_date
        }
        registros.append(registro)

    if not registros:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    df = pd.DataFrame(registros)

    # Garantir colunas do modelo base + User_Agent
    for col in COLUNAS_MODELO:
        if col not in df.columns:
            if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                df[col] = False
            elif col == 'Alvo':
                df[col] = alvo
            else:
                df[col] = None

    # Ordenar colunas: modelo base com User_Agent após Ip
    cols_ordered = list(COLUNAS_MODELO)
    idx_ip = cols_ordered.index('Ip')
    cols_ordered.insert(idx_ip + 1, 'User_Agent')
    df = df[[c for c in cols_ordered if c in df.columns]]

    if update_callback:
        update_callback(f"Extraídos {len(df)} registros com User Agent do formato Preservation Google")

    return df
