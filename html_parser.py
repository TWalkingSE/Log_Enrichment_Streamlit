"""
Log Enrichment - HTML Parser Module
Parses IP data from HTML files of WhatsApp, Meta Platforms (Facebook/Instagram) and Google.
Extracts IP addresses with timestamps and returns standardized DataFrames.
"""

import re
import logging
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
from data_processor import (
    TZ_LABEL, convert_utc_to_local, format_iso_date, get_periodo,
    COLUNAS_MODELO
)
from api_client import is_valid_ip

logger = logging.getLogger(__name__)


# ============================================================
# PLATFORM DETECTION
# ============================================================

def detect_html_platform(html_content):
    """
    Detecta a plataforma de origem do HTML.
    Retorna: 'whatsapp', 'meta', 'google' ou 'unknown'
    """
    content_lower = html_content[:10000].lower()
    if 'whatsapp business record' in content_lower:
        return 'whatsapp'
    if 'meta platforms business record' in content_lower:
        return 'meta'
    if 'google subscriber information' in content_lower or 'ip activity' in content_lower:
        return 'google'
    return 'unknown'


# ============================================================
# WHATSAPP HTML PARSER
# ============================================================

def parse_whatsapp_html(html_content, alvo='desconhecido', update_callback=None):
    """
    Extrai IPs e timestamps do HTML do WhatsApp Business Record.
    Formato: seção #property-ip_addresses com pares Time → IP Address em divs.
    """
    if update_callback:
        update_callback("Parsing HTML do WhatsApp...")

    soup = BeautifulSoup(html_content, 'html.parser')
    ips_section = soup.find(id='property-ip_addresses')

    if not ips_section:
        logger.warning("Seção 'ip_addresses' não encontrada no HTML do WhatsApp")
        return pd.DataFrame(columns=COLUNAS_MODELO)

    pairs = []
    current_time = None

    for div in ips_section.find_all('div', class_='t i'):
        if not div.contents:
            continue
        text = str(div.contents[0]).strip()
        m_div = div.find('div', class_='m')
        value = m_div.get_text(strip=True) if m_div else ''

        if text.startswith('Time'):
            current_time = value
        elif text.startswith('IP Address') and current_time:
            if value and is_valid_ip(value):
                pairs.append((current_time, value))
            current_time = None

    if update_callback:
        update_callback(f"WhatsApp: {len(pairs)} pares Time/IP encontrados")

    return _build_dataframe(pairs, alvo, has_port=False)


# ============================================================
# META PLATFORMS HTML PARSER (Facebook / Instagram)
# ============================================================

def parse_meta_html(html_content, alvo='desconhecido', update_callback=None):
    """
    Extrai IPs e timestamps do HTML do Meta Platforms Business Record.
    Formato: seção #property-ip_addresses com pares IP Address → Time em divs.
    IPs podem ter porta (Instagram: 187.68.195.77:1135) ou não (Facebook).
    IPv6 vem entre brackets: [2804:29b8:...]:porta
    """
    if update_callback:
        update_callback("Parsing HTML da Meta Platforms...")

    soup = BeautifulSoup(html_content, 'html.parser')
    ips_section = soup.find(id='property-ip_addresses')

    if not ips_section:
        logger.warning("Seção 'ip_addresses' não encontrada no HTML da Meta")
        return pd.DataFrame(columns=COLUNAS_MODELO)

    pairs = []
    current_ip_raw = None

    for div in ips_section.find_all('div', class_='t i'):
        if not div.contents:
            continue
        text = str(div.contents[0]).strip()
        m_div = div.find('div', class_='m')
        value = m_div.get_text(strip=True) if m_div else ''

        if text.startswith('IP Address'):
            current_ip_raw = value
        elif text.startswith('Time') and current_ip_raw:
            if current_ip_raw:
                pairs.append((value, current_ip_raw))
            current_ip_raw = None

    if update_callback:
        update_callback(f"Meta: {len(pairs)} pares Time/IP encontrados")

    return _build_dataframe_meta(pairs, alvo)


# ============================================================
# GOOGLE HTML PARSER
# ============================================================

def parse_google_html(html_content, alvo='desconhecido', update_callback=None):
    """
    Extrai IPs e timestamps do HTML do Google Subscriber Information.
    Formato: tabela HTML com colunas Timestamp, IP Address, Activity Type, etc.
    """
    if update_callback:
        update_callback("Parsing HTML do Google...")

    soup = BeautifulSoup(html_content, 'html.parser')
    table = soup.find('table')

    if not table:
        logger.warning("Tabela IP ACTIVITY não encontrada no HTML do Google")
        return pd.DataFrame(columns=COLUNAS_MODELO)

    rows = table.find_all('tr')
    if len(rows) < 2:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    # Identificar colunas pelo header
    headers = [th.get_text(strip=True).lower() for th in rows[0].find_all(['th', 'td'])]
    ts_idx = next((i for i, h in enumerate(headers) if 'timestamp' in h), 0)
    ip_idx = next((i for i, h in enumerate(headers) if 'ip address' in h), 1)

    pairs = []
    for row in rows[1:]:
        cells = row.find_all('td')
        if len(cells) > max(ts_idx, ip_idx):
            timestamp = cells[ts_idx].get_text(strip=True)
            ip = cells[ip_idx].get_text(strip=True)
            if ip and is_valid_ip(ip):
                pairs.append((timestamp, ip))

    if update_callback:
        update_callback(f"Google: {len(pairs)} registros IP encontrados")

    return _build_dataframe(pairs, alvo, has_port=False, tz_suffix='Z')


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def parse_html_file(html_content, alvo='desconhecido', update_callback=None):
    """
    Detecta automaticamente a plataforma e faz o parsing do HTML.
    Retorna: (DataFrame, platform_name)
    """
    platform = detect_html_platform(html_content)

    if platform == 'whatsapp':
        df = parse_whatsapp_html(html_content, alvo, update_callback)
    elif platform == 'meta':
        df = parse_meta_html(html_content, alvo, update_callback)
    elif platform == 'google':
        df = parse_google_html(html_content, alvo, update_callback)
    else:
        logger.warning("Plataforma HTML não reconhecida")
        df = pd.DataFrame(columns=COLUNAS_MODELO)

    if update_callback:
        update_callback(f"HTML ({platform}): {len(df)} registros extraídos")

    return df, platform


# ============================================================
# HELPERS — DataFrame builders
# ============================================================

def _parse_timestamp(ts_str, tz_suffix='UTC'):
    """Parse timestamp string para datetime local."""
    ts_str = ts_str.strip()
    # Formatos comuns: "2025-12-10 18:58:48 UTC", "2025-08-19 02:48:23 Z"
    for fmt in ['%Y-%m-%d %H:%M:%S UTC', '%Y-%m-%d %H:%M:%S Z',
                '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
        try:
            dt_utc = datetime.strptime(ts_str.replace(' Z', ' UTC').rstrip(), fmt)
            return convert_utc_to_local(dt_utc)
        except ValueError:
            continue
    # Fallback: tentar sem conversão
    try:
        clean = re.sub(r'\s*(UTC|Z)\s*$', '', ts_str)
        return datetime.strptime(clean, '%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def _build_dataframe(pairs, alvo, has_port=False, tz_suffix='UTC'):
    """Constrói DataFrame padrão a partir de pares (timestamp, ip)."""
    resultados = []
    for ts_str, ip_raw in pairs:
        ip = ip_raw.strip()
        porta = ''

        if has_port:
            ip, porta = _split_ip_port(ip_raw)
        
        dt = _parse_timestamp(ts_str, tz_suffix)
        if dt:
            data = dt.strftime('%Y-%m-%d %H:%M:%S')
            periodo = get_periodo(dt.hour)
            iso_date = format_iso_date(dt)
        else:
            data = ts_str
            periodo = '☀️ Diurno'
            iso_date = None

        row = {
            'Alvo': alvo,
            'Ip': ip,
            'Data': data,
            'Data_Fuso': TZ_LABEL,
            'Ip_Dono': None, 'Ip_AS': None,
            'Ip_Regiao': None, 'Ip_Cidade': None,
            'Ip_Pais': None, 'Ip_Pais_Codigo': None,
            'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False,
            'Ip_Lat': None, 'Ip_Lon': None,
            'Periodo': periodo, 'ISO_Date': iso_date,
        }
        if has_port:
            row['Porta'] = porta
        resultados.append(row)

    return pd.DataFrame(resultados)


def _build_dataframe_meta(pairs, alvo):
    """Constrói DataFrame para Meta (com separação IP/Porta)."""
    resultados = []
    for ts_str, ip_raw in pairs:
        ip, porta = _split_ip_port(ip_raw)

        if not ip or not is_valid_ip(ip):
            continue

        dt = _parse_timestamp(ts_str)
        if dt:
            data = dt.strftime('%Y-%m-%d %H:%M:%S')
            periodo = get_periodo(dt.hour)
            iso_date = format_iso_date(dt)
        else:
            data = ts_str
            periodo = '☀️ Diurno'
            iso_date = None

        resultados.append({
            'Alvo': alvo,
            'Ip': ip,
            'Porta': porta,
            'Data': data,
            'Data_Fuso': TZ_LABEL,
            'Ip_Dono': None, 'Ip_AS': None,
            'Ip_Regiao': None, 'Ip_Cidade': None,
            'Ip_Pais': None, 'Ip_Pais_Codigo': None,
            'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False,
            'Ip_Lat': None, 'Ip_Lon': None,
            'Periodo': periodo, 'ISO_Date': iso_date,
        })

    return pd.DataFrame(resultados)


def _split_ip_port(ip_raw):
    """
    Separa IP e porta do formato Meta Platforms.
    Formatos: '187.68.195.77:1135', '[2804:29b8:...]:63629', '187.68.195.77' (sem porta)
    """
    ip_raw = ip_raw.strip()

    # IPv6 entre brackets: [2804:...]:porta
    match_v6 = re.match(r'^\[([^\]]+)\]:?(\d+)?$', ip_raw)
    if match_v6:
        ip = match_v6.group(1)
        porta = match_v6.group(2) or ''
        return ip, porta

    # IPv4 com porta: 187.68.195.77:1135
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}:\d+$', ip_raw):
        parts = ip_raw.rsplit(':', 1)
        return parts[0], parts[1]

    # IPv4 sem porta ou IPv6 sem brackets
    return ip_raw, ''
