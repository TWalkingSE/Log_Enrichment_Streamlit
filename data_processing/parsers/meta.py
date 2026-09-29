"""Registros da Meta Platforms e do WhatsApp (IP:porta lógica, horários em UTC)."""

import logging
import re
from datetime import datetime

import pandas as pd

from api_client import is_valid_ip
from data_processing.timezone import (
    TZ_LABEL,
    convert_utc_to_local,
    format_iso_date,
    get_periodo,
)

logger = logging.getLogger(__name__)


def parse_meta_ip_port(raw):
    """Extrai IP e porta lógica do formato Meta Platforms
    Formatos suportados:
    - IPv4:porta (ex: 198.51.100.10:22859)
    - [IPv6]:porta (ex: [2001:0db8:1354:6500:29a9:2a7f:ee68:d955]:59483)
    - IPv4 ou IPv6 sem porta
    """
    raw = raw.strip()
    # IPv6 entre colchetes com porta: [ipv6]:porta
    m = re.match(r'^\[([^\]]+)\]:(\d+)$', raw)
    if m:
        return m.group(1), m.group(2)
    # IPv4 com porta: ipv4:porta
    m = re.match(r'^((\d{1,3}\.){3}\d{1,3}):(\d+)$', raw)
    if m:
        return m.group(1), m.group(3)
    # IP sem porta
    return raw, ''


def extrair_ips_do_formato_whatsapp(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs e timestamps do formato WhatsApp (Time primeiro, depois IP Address)

    Args:
        content: Conteúdo do texto
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs e dados temporais extraídos
    """
    if update_callback:
        update_callback("Extraindo IPs e timestamps do formato WhatsApp")

    # Lista para armazenar os resultados
    resultados = []

    # Conjunto para rastrear pares IP+data já processados
    ips_processados = set()

    # Remover linhas de quebra de página do WhatsApp
    content_clean = re.sub(r'WhatsApp Business Record Page \d+', '', content)

    # Padrão WhatsApp: Time -> data -> IP Address -> ip
    pattern = r'Time\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC)\s+IP\s+Address\s+(\S+)'

    # Encontrar todos os pares de data/IP
    matches = re.findall(pattern, content_clean, re.DOTALL | re.IGNORECASE)

    for date_utc, ip_raw in matches:
        ip = ip_raw.strip()
        if is_valid_ip(ip) and (ip, date_utc) not in ips_processados:
            ips_processados.add((ip, date_utc))

            # Converter de UTC para fuso local configurável
            try:
                dt = datetime.strptime(date_utc, '%Y-%m-%d %H:%M:%S UTC')
                dt = convert_utc_to_local(dt)
                data = dt.strftime('%Y-%m-%d %H:%M:%S')
                hora = dt.hour
                periodo = get_periodo(hora)
                iso_date = format_iso_date(dt)
            except (TypeError, ValueError) as e:
                logger.warning(f"Erro ao converter data '{date_utc}': {e}")
                # Preservar o valor bruto — inventar a data (ex.: now())
                # fabrica o timestamp do evento no laudo.
                data = date_utc
                periodo = None
                iso_date = None

            resultados.append({
                'Alvo': alvo,
                'Ip': ip,
                'Data': data,
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
            })

    # Criar DataFrame
    df = pd.DataFrame(resultados)

    if update_callback:
        update_callback(f"Extraídos {len(df)} IPs com timestamps do formato WhatsApp")

    return df

def extrair_ips_do_formato_meta(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs, portas lógicas e timestamps do formato Meta Platforms (IP Address primeiro, depois Time)

    Args:
        content: Conteúdo do texto
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs, portas e dados temporais extraídos (inclui coluna 'Porta')
    """
    if update_callback:
        update_callback("Extraindo IPs e timestamps do formato Meta Platforms")

    # Lista para armazenar os resultados
    resultados = []

    # Conjunto para rastrear pares IP+porta+data já processados
    ips_processados = set()

    # Remover linhas de quebra de página do Meta
    content_clean = re.sub(r'Meta Platforms Business Record Page \d+', '', content)

    # Padrão Meta: IP Address -> ip[:porta] -> Time -> data
    pattern = r'IP\s+Address\s+(\S+)\s+Time\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+UTC)'

    # Encontrar todos os pares de IP/data
    matches = re.findall(pattern, content_clean, re.DOTALL | re.IGNORECASE)

    for ip_raw, date_utc in matches:
        # Extrair IP e porta usando o parser de Meta
        ip, porta = parse_meta_ip_port(ip_raw)

        if is_valid_ip(ip) and (ip, porta, date_utc) not in ips_processados:
            ips_processados.add((ip, porta, date_utc))

            # Converter de UTC para fuso local configurável
            try:
                dt = datetime.strptime(date_utc, '%Y-%m-%d %H:%M:%S UTC')
                dt = convert_utc_to_local(dt)
                data = dt.strftime('%Y-%m-%d %H:%M:%S')
                hora = dt.hour
                periodo = get_periodo(hora)
                iso_date = format_iso_date(dt)
            except (TypeError, ValueError) as e:
                logger.warning(f"Erro ao converter data '{date_utc}': {e}")
                data = date_utc
                periodo = None
                iso_date = None

            resultados.append({
                'Alvo': alvo,
                'Ip': ip,
                'Porta': porta,
                'Data': data,
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
            })

    # Criar DataFrame
    df = pd.DataFrame(resultados)

    if update_callback:
        update_callback(f"Extraídos {len(df)} IPs com timestamps do formato Meta Platforms")

    return df
