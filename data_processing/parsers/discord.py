"""Discord: cabeçalho do usuário + tabela "Session Start (UTC) / IP Address"."""

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

logger = logging.getLogger(__name__)


def extrair_ips_do_formato_discord(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs e timestamps do formato Discord (PDF com Session Start/IP Address).

    O formato Discord contém um cabeçalho com dados do usuário (User ID, Username, Email)
    e uma tabela de sessões com: Session Start (UTC) e IP Address.

    Args:
        content: Conteúdo do texto extraído do PDF
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs, dados temporais e metadados Discord (User_ID, Username, Email)
    """
    if update_callback:
        update_callback("Processando formato Discord...")

    # Extrair metadados do cabeçalho
    user_id = ''
    username = ''
    email = ''
    registration_ip = ''
    registration_time = ''

    m = re.search(r'User\s*ID:\s*(\S+)', content)
    if m:
        user_id = m.group(1).strip()

    m = re.search(r'Username:\s*(\S+)', content)
    if m:
        username = m.group(1).strip()

    m = re.search(r'Email:\s*(\S+)', content)
    if m:
        email = m.group(1).strip()

    m = re.search(r'Registration\s+IP:\s*(\S+)', content)
    if m:
        val = m.group(1).strip()
        if val.lower() != 'not' and is_valid_ip(val):
            registration_ip = val

    m = re.search(r'Registration\s+Time\s*\(UTC\):\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', content)
    if m:
        registration_time = m.group(1).strip()

    # Auto-detectar alvo a partir do email se não fornecido
    if alvo == 'desconhecido' and email:
        alvo = email

    registros = []
    ips_processados = set()

    # Incluir Registration IP se válido
    if registration_ip and registration_time:
        try:
            dt_utc = datetime.strptime(registration_time, '%Y-%m-%d %H:%M:%S')
            dt_local = convert_utc_to_local(dt_utc)
            data_formatada = dt_local.strftime('%Y-%m-%d %H:%M:%S')
            periodo = get_periodo(dt_local.hour)
            iso_date = format_iso_date(dt_local)
        except (TypeError, ValueError):
            data_formatada = registration_time
            periodo = None
            iso_date = None

        ips_processados.add((registration_ip, registration_time))
        registros.append({
            'Alvo': alvo,
            'Ip': registration_ip,
            'User_ID': user_id,
            'Username': username,
            'Email': email,
            'Data': data_formatada,
            'Data_Fuso': TZ_LABEL,
            'Ip_Dono': None, 'Ip_AS': None,
            'Ip_Regiao': None, 'Ip_Cidade': None,
            'Ip_Pais': None, 'Ip_Pais_Codigo': None,
            'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False, 'Ip_Tor': False,
            'Ip_Lat': None, 'Ip_Lon': None,
            'Periodo': periodo,
            'ISO_Date': iso_date
        })

    # Parsear tabela de sessões: "Session Start (UTC)    IP Address"
    # Formato: YYYY-MM-DD HH:MM:SS    IP
    pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)'

    # Localizar início da tabela de sessões
    session_pos = content.find('Session Start')
    if session_pos >= 0:
        session_section = content[session_pos:]
        lines = session_section.split('\n')

        for line in lines[1:]:  # Pular cabeçalho
            line = line.strip()
            if not line:
                continue

            m = re.match(pattern, line)
            if m:
                timestamp_str = m.group(1).strip()
                ip_raw = m.group(2).strip()

                if not is_valid_ip(ip_raw):
                    continue

                if (ip_raw, timestamp_str) in ips_processados:
                    continue
                ips_processados.add((ip_raw, timestamp_str))

                try:
                    dt_utc = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    dt_local = convert_utc_to_local(dt_utc)
                    data_formatada = dt_local.strftime('%Y-%m-%d %H:%M:%S')
                    periodo = get_periodo(dt_local.hour)
                    iso_date = format_iso_date(dt_local)
                except (TypeError, ValueError) as e:
                    logger.warning(f"Erro ao converter timestamp Discord '{timestamp_str}': {e}")
                    data_formatada = timestamp_str
                    periodo = None
                    iso_date = None

                registros.append({
                    'Alvo': alvo,
                    'Ip': ip_raw,
                    'User_ID': user_id,
                    'Username': username,
                    'Email': email,
                    'Data': data_formatada,
                    'Data_Fuso': TZ_LABEL,
                    'Ip_Dono': None, 'Ip_AS': None,
                    'Ip_Regiao': None, 'Ip_Cidade': None,
                    'Ip_Pais': None, 'Ip_Pais_Codigo': None,
                    'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False, 'Ip_Tor': False,
                    'Ip_Lat': None, 'Ip_Lon': None,
                    'Periodo': periodo,
                    'ISO_Date': iso_date
                })

    if not registros:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    df = pd.DataFrame(registros)

    # Garantir colunas do modelo base + Discord extras
    for col in COLUNAS_MODELO:
        if col not in df.columns:
            if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                df[col] = False
            elif col == 'Alvo':
                df[col] = alvo
            else:
                df[col] = None

    # Ordenar colunas: modelo base com User_ID, Username, Email após Ip
    cols_ordered = list(COLUNAS_MODELO)
    idx_ip = cols_ordered.index('Ip')
    for i, extra_col in enumerate(['User_ID', 'Username', 'Email']):
        cols_ordered.insert(idx_ip + 1 + i, extra_col)
    df = df[[c for c in cols_ordered if c in df.columns]]

    if update_callback:
        update_callback(f"Extraídos {len(df)} registros do formato Discord")

    return df
