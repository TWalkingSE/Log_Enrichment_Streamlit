import pandas as pd
import re
import io
import logging
import os
from datetime import datetime, timedelta
from api_client import is_valid_ip
from data_processing.providers import (
    PROVIDER_ALIASES,
    normalizar_provedor,
    normalizar_provedor_df,
)
from data_processing.timezone import (
    TZ_LABEL,
    TZ_OFFSET_HOURS,
    convert_utc_to_local,
    format_iso_date,
    get_periodo,
    is_diurno,
    is_noturno,
    normalizar_periodo,
    periodo_matches,
)

# Configurar logger para este módulo
logger = logging.getLogger(__name__)

# Padrão regex de IP reutilizável (IPv4 + IPv6)
IP_REGEX_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}):?(?::[0-9a-fA-F]{1,4}){1,7}'

# Definição das colunas do modelo (interno, inclui Lat/Lon para mapa)
COLUNAS_MODELO = [
    'Alvo', 'Ip', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade', 'Ip_Pais', 'Ip_Pais_Codigo',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Periodo', 'ISO_Date'
]

# Colunas para exportação (com Lat/Lon para mapa de geolocalização)
COLUNAS_EXPORT = [
    'Alvo', 'Ip', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação Meta Platforms (com Porta lógica)
COLUNAS_EXPORT_META = [
    'Alvo', 'Ip', 'Porta', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação Preservation Google (com User_Agent)
COLUNAS_EXPORT_PRESERVATION_GOOGLE = [
    'Alvo', 'Ip', 'User_Agent', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação Discord (com User_ID, Username e Email)
COLUNAS_EXPORT_DISCORD = [
    'Alvo', 'Ip', 'User_ID', 'Username', 'Email', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação TikTok (com Evento)
COLUNAS_EXPORT_TIKTOK = [
    'Alvo', 'Ip', 'Evento', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas extras específicas de provedor, inseridas após 'Ip' na saída
COLUNAS_EXTRAS_PROVEDOR = ['Porta', 'Evento', 'User_ID', 'Username', 'Email', 'User_Agent']

# Exemplos dos formatos suportados
FORMATO_1 = """Endereços IP
191.13.51.97
2804:18:18bf:9681:1:0:70f2:df19
2804:18:1054:5f90:1:2:3be4:cd25
2804:18:1149:ae06:1796:ad93:296c:cbe4
"""

FORMATO_2 = """Ip Addresses Definition
IP Addresses: IP addresses and source port/port numbers associated with the account.
Ip Addresses
IP Address
24.152.81.150:22859
Time
2025-09-29 11:15:01 UTC
IP Address
[2804:04b0:1354:6500:29a9:2a7f:ee68:d955]:59483
Time
2025-09-21 23:01:39 UTC
"""

FORMATO_3 = """Ip Addresses Definition
IP Addresses: IP addresses an account holder has connected from.
Ip Addresses
Time
2025-12-10 18:58:48 UTC
IP Address
2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7
Time
2025-12-05 19:35:57 UTC
IP Address
2804:38a:a04d:49b8:97e0:c894:9e09:859c
"""

FORMATO_4 = """GOOGLE SUBSCRIBER INFORMATION

Google Account ID: 5333504493224
Name: Lorem Silva
e-Mail: LoremSilva@gmail.com

IP ACTIVITY

Timestamp   IP Address  Activity Type   Android ID  Apple iOS IDFV  Raw User Agents
2023-02-25 04:34:32 Z   2804:214:82ae:6fb1:1:1:b8eb:1d22    Login
2023-02-24 22:54:13 Z   2804:214:82ae:6fb1:1:1:b8eb:1d22    Login
2023-02-24 17:56:18 Z   187.37.136.128    Login
"""

FORMATO_DISCORD = """User ID:                     1366836644673622076
Username:                    r1rex47#0
Email:                       xxxxxx.6666@gmail.com
Email verified:              Yes
Phone number:                Not found
Registration IP:             Not found
Registration Time (UTC):     2025-04-29 18:00:50
Last Seen Time (UTC):        2025-05-14 01:43:39
Last Seen IP:                89.39.104.194

Session Start (UTC)    IP Address
2025-05-14 00:47:29    89.39.104.194
2025-05-13 23:55:51    179.63.13.130
2025-05-12 08:46:41    179.63.13.130
2025-05-11 18:07:57    45.187.170.1
2025-05-11 13:56:56    179.63.13.130
"""

FORMATO_PRESERVATION_GOOGLE = """Gaia ID,Activity Timestamp,IP Address,Proxiedhost IP Address,Is Non-routable IP Address,User Agent String,Product Name
314329686157,2026-03-11 02:49:39 UTC,2804:214:85c1:b496:81e9:9e8e:a396:d027,,No,App : YOUTUBE_APP. App Version : 21.10.2. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,YouTube
314329686157,2026-03-11 02:33:59 UTC,2804:214:85c1:b496:81e9:9e8e:a396:d027,,No,App : GMAIL_APP. App Version : 6.0.260302. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,Gmail
314329686157,2026-03-11 00:04:30 UTC,168.0.233.233,,No,App : GMAIL_APP. App Version : 6.0.260302.1803824. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,Gmail
"""

FORMATO_TIKTOK = """Events IP Data
Date: 27/07/2026 03:04:43PM (UTC +00)
IP: 203.0.113.45
Event: video_play
Country: Brazil
Date: 27/07/2026 03:04:31PM (UTC +00)
IP: 203.0.113.45
Event: like
Country: Brazil
Date: 27/07/2026 02:48:12PM (UTC +00)
IP: 203.0.113.45
Event: publish
Country: Brazil
"""

def parse_meta_ip_port(raw):
    """Extrai IP e porta lógica do formato Meta Platforms
    Formatos suportados:
    - IPv4:porta (ex: 24.152.81.150:22859)
    - [IPv6]:porta (ex: [2804:04b0:1354:6500:29a9:2a7f:ee68:d955]:59483)
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

    # Encontrar todos os IPs no conteúdo
    ips = re.findall(IP_REGEX_PATTERN, content)
    ips = [ip for ip in ips if is_valid_ip(ip)]

    # Criar resultados (sem data — manter todos os registros, incluindo repetidos)
    resultados = []

    for ip in ips:
        resultados.append({
            'Alvo': alvo,
            'Ip': ip,
            'Data': None,
            'Data_Fuso': None,
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
            'Periodo': None,
            'ISO_Date': None
        })

    # Criar DataFrame
    df = pd.DataFrame(resultados)

    if update_callback:
        update_callback(f"Extraídos {len(df)} registros ({df['Ip'].nunique()} IPs únicos) do formato simples")

    return df

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
                data = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                periodo = '☀️ Diurno'
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
                data = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                periodo = '☀️ Diurno'
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
                periodo = '☀️ Diurno'
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
            if str(row.get('Is Non-routable IP Address', '')).strip().lower() == 'yes':
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


def extrair_ips_do_formato_tiktok(content, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs, eventos e timestamps do formato TikTok (Events IP Data).

    O formato TikTok (PDF da TikTok Pte. Limited) contém registros com campos
    rotulados, um por linha, na ordem Date -> IP -> Event -> Country:

        Date: 27/07/2026 03:04:43PM (UTC +00)
        IP: 203.0.113.45
        Event: video_play
        Country: Brazil

    Rodapés de página ("TikTok Pte. Limited", endereço e número da página) podem
    aparecer intercalados no meio de um registro e são removidos na limpeza.

    Args:
        content: Conteúdo do texto extraído do PDF
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs, dados temporais e coluna extra 'Evento'
    """
    if update_callback:
        update_callback("Processando formato TikTok (Events IP Data)...")

    # Remover ruído de paginação: cabeçalho, rodapé da empresa e números de página.
    # Seguro porque linhas de dados sempre têm o formato "Chave: valor".
    lines_clean = []
    for line in content.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped == 'Events IP Data':
            continue
        if 'TikTok Pte' in line_stripped:
            continue
        if line_stripped.startswith('One Raffles Quay'):
            continue
        # Linha contendo apenas número de página
        if re.fullmatch(r'\d{1,4}', line_stripped):
            continue
        lines_clean.append(line_stripped)

    # Máquina de estados: acumula campos rotulados até completar um registro.
    # Tolerante à ordem dos campos e a registros divididos entre páginas.
    field_pattern = re.compile(r'^(Date|IP|Event|Country)\s*:\s*(.+?)\s*$', re.IGNORECASE)
    registros_brutos = []
    atual = {}

    for line in lines_clean:
        m = field_pattern.match(line)
        if not m:
            continue
        campo = m.group(1).capitalize()  # Date, Ip->IP, Event, Country
        if campo == 'Ip':
            campo = 'IP'
        valor = m.group(2).strip()

        # Se o campo já existe no registro atual, o anterior estava incompleto:
        # emitir se estiver completo e reiniciar pelo campo repetido.
        if campo in atual:
            if all(k in atual for k in ('Date', 'IP', 'Event')):
                registros_brutos.append(atual)
            atual = {}
        atual[campo] = valor

        # Registro completo: Date + IP + Event (Country é opcional/descartado)
        if all(k in atual for k in ('Date', 'IP', 'Event')):
            registros_brutos.append(atual)
            atual = {}

    # Registro pendente ao final do documento
    if 'IP' in atual and 'Date' in atual and 'Event' in atual:
        registros_brutos.append(atual)

    resultados = []
    ips_processados = set()

    for reg in registros_brutos:
        ip = reg['IP'].strip()
        if not is_valid_ip(ip):
            continue

        evento = reg['Event'].strip()
        date_raw = reg['Date'].strip()

        # Remover sufixo de fuso: "27/07/2026 03:04:43PM (UTC +00)" -> "27/07/2026 03:04:43PM"
        date_str = re.sub(r'\s*\(UTC\s*[+\-]?\d+\)\s*$', '', date_raw).strip()

        # Dedup por (IP, data, evento) — mantém eventos distintos no mesmo segundo
        dedup_key = (ip, date_str, evento)
        if dedup_key in ips_processados:
            continue
        ips_processados.add(dedup_key)

        # Converter de UTC para fuso local configurável
        try:
            dt_utc = datetime.strptime(date_str, '%d/%m/%Y %I:%M:%S%p')
            dt_local = convert_utc_to_local(dt_utc)
            data = dt_local.strftime('%Y-%m-%d %H:%M:%S')
            periodo = get_periodo(dt_local.hour)
            iso_date = format_iso_date(dt_local)
        except (TypeError, ValueError) as e:
            logger.warning(f"Erro ao converter data TikTok '{date_raw}': {e}")
            data = date_str
            periodo = '☀️ Diurno'
            iso_date = None

        resultados.append({
            'Alvo': alvo,
            'Ip': ip,
            'Evento': evento,
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

    if not resultados:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    df = pd.DataFrame(resultados)

    # Ordenar colunas: modelo base com Evento após Ip
    cols_ordered = list(COLUNAS_MODELO)
    idx_ip = cols_ordered.index('Ip')
    cols_ordered.insert(idx_ip + 1, 'Evento')
    df = df[[c for c in cols_ordered if c in df.columns]]

    if update_callback:
        update_callback(f"Extraídos {len(df)} registros ({df['Evento'].nunique()} tipos de evento) do formato TikTok")

    return df


def detectar_formato_log(content):
    """
    Detecta o formato do log de acesso baseado no conteúdo.
    Retorna: 'preservation_google', 'meta', 'whatsapp', 'google', 'discord', 'tiktok' ou 'generico'
    """
    # Preservation Google: CSV do Google Takeout com colunas específicas
    if 'Activity Timestamp' in content and 'User Agent String' in content and 'Product Name' in content:
        return 'preservation_google'
    # Discord: contém "Session Start (UTC)" com "User ID:" ou "Username:"
    if 'Session Start (UTC)' in content and ('User ID:' in content or 'Username:' in content):
        return 'discord'
    # TikTok: PDF "Events IP Data" da TikTok Pte. Limited (campos Date/IP/Event/Country)
    if 'Events IP Data' in content or 'TikTok Pte' in content:
        return 'tiktok'
    # Meta Platforms: contém "source port/port numbers" ou "Meta Platforms Business Record"
    if 'source port' in content.lower() or 'Meta Platforms Business Record' in content:
        return 'meta'
    # WhatsApp: contém "WhatsApp Business Record" ou padrão específico WhatsApp
    if 'WhatsApp Business Record' in content or 'IP addresses an account holder has connected from' in content:
        return 'whatsapp'
    # Google: contém "IP ACTIVITY" com formato tabular
    if 'IP ACTIVITY' in content:
        return 'google'
    # Se tem Time e IP Address mas não é Meta nem WhatsApp, tentar detectar pela ordem
    if 'Time' in content and 'IP Address' in content:
        # Verificar qual aparece primeiro após "Ip Addresses"
        pos_time = content.find('Time')
        pos_ip = content.find('IP Address')
        if pos_ip >= 0 and pos_time >= 0:
            if pos_ip < pos_time:
                return 'meta'  # IP Address aparece primeiro = Meta
            else:
                return 'whatsapp'  # Time aparece primeiro = WhatsApp
    return 'generico'

def extrair_ips_de_texto(file_path_or_content, is_file=True, update_callback=None, alvo='desconhecido'):
    """
    Extrai IPs e dados temporais de um arquivo de texto ou conteúdo de texto

    Args:
        file_path_or_content: Caminho para o arquivo ou conteúdo de texto
        is_file: Indicador se é um caminho de arquivo (True) ou conteúdo (False)
        update_callback: Função para atualizar status
        alvo: Identificador do alvo

    Returns:
        DataFrame com IPs e dados temporais extraídos
    """
    try:
        # Obter o conteúdo do texto
        if is_file:
            if update_callback:
                update_callback(f"Extraindo IPs e dados temporais de {file_path_or_content}")

            with open(file_path_or_content, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            content = file_path_or_content
            if update_callback:
                update_callback("Extraindo IPs e dados temporais do texto colado")

        # Detectar formato do log
        formato = detectar_formato_log(content)

        if update_callback:
            update_callback(f"Formato detectado: {formato}")

        # Formato Discord (Session Start/IP Address com metadados do usuário)
        if formato == 'discord':
            df = extrair_ips_do_formato_discord(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato TikTok (Events IP Data: Date/IP/Event/Country)
        if formato == 'tiktok':
            df = extrair_ips_do_formato_tiktok(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato Meta Platforms (IP Address primeiro, com porta lógica)
        if formato == 'meta':
            df = extrair_ips_do_formato_meta(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato WhatsApp (Time primeiro, depois IP Address)
        if formato == 'whatsapp':
            df = extrair_ips_do_formato_whatsapp(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato Preservation Google (CSV do Google Takeout com User Agent)
        if formato == 'preservation_google':
            df = extrair_ips_do_formato_preservation_google(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato Google (IP ACTIVITY tabular)
        if formato == 'google':
            df = extrair_ips_do_formato_google(content, update_callback, alvo)
            if not df.empty:
                return df

        # Formato simples de lista de IPs
        if formato == 'generico':
            df = extrair_ips_do_formato_simples(content, update_callback, alvo)
            if not df.empty:
                return df

        # Se não conseguimos identificar o formato específico, tentar método genérico
        return extrair_ips_texto_simples(content, update_callback, is_file=False, alvo=alvo)

    except (OSError, UnicodeError, TypeError, ValueError, pd.errors.ParserError) as e:
        logger.error(f"Erro ao extrair IPs: {e}", exc_info=True)
        if update_callback:
            update_callback(f"Erro ao processar texto: {e}")
        # Tentar método alternativo em caso de erro
        return extrair_ips_texto_simples(file_path_or_content, update_callback, is_file, alvo=alvo)

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
            with open(file_path_or_content, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            content = file_path_or_content

        # Padrões para extração
        ip_pattern = IP_REGEX_PATTERN

        # Padrões de data/hora
        data_patterns = [
            # YYYY-MM-DD HH:MM:SS
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            # DD/MM/YYYY HH:MM:SS
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
        ]

        # Encontrar todos os IPs
        ips = re.findall(ip_pattern, content)
        ips = [ip for ip in ips if is_valid_ip(ip)]

        # Encontrar todas as datas
        dates = []
        for pattern in data_patterns:
            matches = re.findall(pattern, content)
            dates.extend(matches)

        # Se temos mais datas que IPs, reduzir para o mesmo número
        if len(dates) > len(ips):
            dates = dates[:len(ips)]
        # Se temos mais IPs que datas, usar datas do nome do arquivo ou data atual
        elif len(dates) < len(ips):
            # Tentar extrair data do nome do arquivo
            file_date = None

            if is_file:
                filename = os.path.basename(file_path_or_content)
                # Verificar formato específico 20250310123909
                timestamp_match = re.search(r'(\d{14})', filename)
                if timestamp_match:
                    timestamp_str = timestamp_match.group(1)
                    try:
                        file_date = f"{timestamp_str[0:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]} {timestamp_str[8:10]}:{timestamp_str[10:12]}:{timestamp_str[12:14]}"
                    except (TypeError, ValueError) as e:
                        logger.warning(f"Erro ao extrair data do nome do arquivo: {e}")

            # Usar data do arquivo para preencher (ou None se não disponível)
            current_date = file_date
            while len(dates) < len(ips):
                dates.append(current_date)

        # Criar resultados
        resultados = []
        for i, ip in enumerate(ips):
            if i < len(dates) and dates[i] is not None:
                data = dates[i]
                # Converter para formato YYYY-MM-DD se necessário
                if re.match(r'^\d{2}/\d{2}/\d{4}', data):
                    try:
                        dt = datetime.strptime(data, '%d/%m/%Y %H:%M:%S')
                        data = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except (TypeError, ValueError) as e:
                        logger.warning(f"Erro ao converter data '{data}': {e}")
                elif re.match(r'^\d{4}-\d{2}-\d{2}', data):
                    try:
                        dt = datetime.strptime(data, '%Y-%m-%d %H:%M:%S')
                        # Ajustar para fuso local se a data estiver em UTC
                        if "UTC" in content:
                            dt = convert_utc_to_local(dt)
                        data = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except (TypeError, ValueError) as e:
                        logger.warning(f"Erro ao converter data '{data}': {e}")

                # Calcular período e ISO_Date
                try:
                    dt = datetime.strptime(data, '%Y-%m-%d %H:%M:%S')
                    periodo = get_periodo(dt.hour)
                    iso_date = format_iso_date(dt)
                except (TypeError, ValueError) as e:
                    logger.warning(f"Erro ao calcular periodo para '{data}': {e}")
                    periodo = '☀️ Diurno'
                    iso_date = None
            else:
                data = None
                periodo = None
                iso_date = None

            resultados.append({
                'Alvo': alvo,
                'Ip': ip,
                'Data': data,
                'Data_Fuso': TZ_LABEL if data else None,
                'Periodo': periodo,
                'ISO_Date': iso_date,
                'Ip_Movel': False,
                'Ip_Proxy': False,
                'Ip_Hospedagem': False,
                'Ip_Tor': False,
                'Ip_Lat': None,
                'Ip_Lon': None
            })

        # Criar DataFrame
        df = pd.DataFrame(resultados)

        # Garantir todas as colunas do modelo
        for col in COLUNAS_MODELO:
            if col not in df.columns:
                if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                    df[col] = False
                elif col == 'Alvo':
                    df[col] = alvo
                elif col == 'Data_Fuso':
                    df[col] = TZ_LABEL
                else:
                    df[col] = None

        # Garantir a ordem exata das colunas
        df = df[COLUNAS_MODELO]

        if update_callback:
            update_callback(f"Método alternativo extraiu {len(df)} registros ({df['Ip'].nunique()} IPs únicos)")

        return df

    except (OSError, UnicodeError, TypeError, ValueError) as e:
        logger.error(f"Erro no método alternativo: {e}", exc_info=True)
        if update_callback:
            update_callback(f"Erro no método alternativo: {e}")
        # Retornar DataFrame vazio com as colunas do modelo
        return pd.DataFrame(columns=COLUNAS_MODELO)

def processar_resultados(df_original, resultados_ips):
    """Processa os resultados da API e combina com o DataFrame original (vetorizado)"""
    df_processado = df_original.copy()

    # Colunas extras de provedor presentes (Porta=Meta, Evento=TikTok,
    # User_ID/Username/Email=Discord, User_Agent=Preservation Google)
    extras_presentes = [c for c in COLUNAS_EXTRAS_PROVEDOR if c in df_processado.columns]

    # Garantir que temos todos os campos do modelo
    for col in COLUNAS_MODELO:
        if col not in df_processado.columns:
            if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                df_processado[col] = False
            elif col == 'Alvo':
                df_processado[col] = 'desconhecido'
            elif col == 'Data_Fuso':
                df_processado[col] = TZ_LABEL
            elif col == 'Periodo':
                df_processado[col] = '☀️ Diurno'
            else:
                df_processado[col] = None

    # Criar DataFrame de resultados da API para merge vetorizado
    if resultados_ips:
        api_records = []
        for ip, result in resultados_ips.items():
            record = {'_merge_ip': ip}
            for campo, valor in result.items():
                if campo == 'status' or campo == '_cached_at':
                    continue
                if valor is not None and valor != '' and (not isinstance(valor, str) or (valor != 'Erro' and not valor.startswith('Erro:'))):
                    record[campo] = valor
            api_records.append(record)

        if api_records:
            df_api = pd.DataFrame(api_records)
            # Mapear resultados por IP usando merge
            campos_api = [c for c in df_api.columns if c != '_merge_ip' and c in df_processado.columns]
            for campo in campos_api:
                ip_to_value = dict(zip(df_api['_merge_ip'], df_api[campo]))
                mask = df_processado['Ip'].isin(ip_to_value.keys())
                df_processado.loc[mask, campo] = df_processado.loc[mask, 'Ip'].map(ip_to_value)

    # Calcular Periodo e ISO_Date vetorizado
    if 'Data' in df_processado.columns:
        try:
            data_parsed = pd.to_datetime(df_processado['Data'], errors='coerce')
            valid_mask = data_parsed.notna()
            if valid_mask.any():
                horas = data_parsed[valid_mask].dt.hour
                df_processado.loc[valid_mask, 'Periodo'] = horas.apply(get_periodo)
                df_processado.loc[valid_mask, 'ISO_Date'] = data_parsed[valid_mask].apply(
                    lambda dt: format_iso_date(dt.to_pydatetime()) if pd.notna(dt) else None
                )
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning(f"Erro ao calcular Periodo/ISO_Date vetorizado: {e}")

    # Definir colunas de saída preservando extras de provedor após 'Ip'
    if extras_presentes:
        colunas_saida = [col for col in COLUNAS_MODELO]
        idx_ip = colunas_saida.index('Ip')
        for i, extra_col in enumerate(extras_presentes):
            colunas_saida.insert(idx_ip + 1 + i, extra_col)
        return df_processado[colunas_saida]
    else:
        return df_processado[COLUNAS_MODELO]
