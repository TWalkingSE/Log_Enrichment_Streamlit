"""
Log Enrichment - HTML Parser Module
Parses IP data from HTML files of WhatsApp, Meta Platforms (Facebook/Instagram) and Google.
Extracts IP addresses with timestamps and returns standardized DataFrames.
"""

import re
import logging
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup, NavigableString
from data_processor import (
    TZ_LABEL, convert_utc_to_local, format_iso_date, get_periodo,
    COLUNAS_MODELO
)
from api_client import is_valid_ip

logger = logging.getLogger(__name__)


# ============================================================
# LEITURA DE SEÇÕES COM QUEBRA DE PÁGINA
# ============================================================

def _campos_da_secao(secao):
    """Campos (rótulo, valor) da seção, com as quebras de página remendadas.

    Meta e WhatsApp partem um campo ao meio na virada de página: o rótulo fica
    no fim de uma página com o valor **vazio**, e o valor reaparece na página
    seguinte num bloco **sem rótulo**, embrulhado num invólucro novo:

        <div class="t i">IP Address<div class="m"><div></div></div></div>
        <div class="pageBreak">Business Record Page 4</div>
        <div class="t i"><div class="m"><div>            <- invólucro
          <div class="t i"><div class="m"><div>203.0.113.7:12538</div></div></div>

    Lido ingenuamente, o rótulo órfão fica com valor vazio, o valor órfão é
    descartado por não ter rótulo conhecido, e o registro inteiro some do
    artefato. Numa ferramenta pericial isso é perda de prova, não defeito
    cosmético — daí o remendo aqui, no ponto onde a estrutura ainda existe.
    """
    brutos = []
    for div in secao.find_all('div', class_='t i'):
        # Blocos que contêm outros blocos são invólucros — inclusive o que a
        # Meta abre logo depois de cada quebra. O texto deles é a concatenação
        # de tudo que vem dentro e não corresponde a campo nenhum.
        if div.find('div', class_='t i'):
            continue
        rotulo = ''
        if div.contents and isinstance(div.contents[0], NavigableString):
            rotulo = str(div.contents[0]).strip()
        m_div = div.find('div', class_='m')
        valor = m_div.get_text(strip=True) if m_div else ''
        brutos.append((rotulo, valor))

    campos = []
    aguardando = None   # índice do campo cujo valor ficou na página seguinte
    orfaos = 0
    for rotulo, valor in brutos:
        if rotulo:
            campos.append([rotulo, valor])
            # Só um rótulo sem valor pode reclamar a continuação da página
            # seguinte; qualquer rótulo novo cancela a espera.
            aguardando = None if valor else len(campos) - 1
        elif valor:
            if aguardando is None:
                orfaos += 1
                continue
            campos[aguardando][1] = valor
            aguardando = None

    if orfaos:
        logger.warning(
            "%d valor(es) sem rótulo correspondente na seção — possível quebra "
            "de página em formato não previsto", orfaos)
    return [(rotulo, valor) for rotulo, valor in campos]


def _pares_ip_tempo(secao, plataforma=''):
    """Pares (timestamp, ip_bruto) da seção de IPs.

    O par fecha quando os dois lados chegam, em qualquer ordem: a Meta emite
    `IP Address` -> `Time` e o WhatsApp emite `Time` -> `IP Address`.
    """
    pares = []
    ip = tempo = None
    incompletos = 0

    for rotulo, valor in _campos_da_secao(secao):
        if rotulo.startswith('IP Address'):
            if ip is not None:
                incompletos += 1
            ip = valor
        elif rotulo.startswith('Time'):
            if tempo is not None:
                incompletos += 1
            tempo = valor
        else:
            continue
        if ip is not None and tempo is not None:
            pares.append((tempo, ip))
            ip = tempo = None

    if ip is not None or tempo is not None:
        incompletos += 1
    if incompletos:
        logger.warning("%s: %d registro(s) de IP sem par IP/Time completo",
                       plataforma or 'HTML', incompletos)
    return pares


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
    invalidos = 0
    com_porta = False
    for ts_str, ip_raw in _pares_ip_tempo(ips_section, 'WhatsApp'):
        # Hoje o WhatsApp entrega o IP sozinho, mas a Meta já entrega
        # `IP:porta` e a tendência é o WhatsApp seguir. Separar antes de
        # validar deixa o parser pronto sem mudar nada enquanto a porta não
        # vier: `_split_ip_port` devolve porta vazia num IP puro. Validar o
        # valor bruto, ao contrário, reprovaria `203.0.113.7:12538` e
        # descartaria o registro inteiro no dia da virada — justamente a porta
        # que identifica o assinante atrás de CGNAT.
        ip, porta = _split_ip_port(ip_raw)
        if not ip or not is_valid_ip(ip):
            # Descartar em silêncio é como a quebra de página passou
            # despercebida: o total do artefato não batia com o do documento.
            invalidos += 1
            logger.warning("WhatsApp: IP inválido descartado: %r", ip_raw)
            continue
        com_porta = com_porta or bool(porta)
        pairs.append((ts_str, ip_raw))

    if invalidos:
        logger.warning("WhatsApp: %d registro(s) descartados por IP inválido", invalidos)
    if com_porta:
        # Mudança de formato do provedor merece registro: o laudo passa a ter
        # uma coluna que os anteriores não tinham.
        logger.info("WhatsApp: registro traz porta lógica — coluna Porta incluída")
    if update_callback:
        update_callback(f"WhatsApp: {len(pairs)} pares Time/IP encontrados")

    # A coluna Porta só entra quando o documento de fato traz porta. Incluí-la
    # sempre acrescentaria uma coluna vazia a todo laudo de WhatsApp de hoje.
    return _build_dataframe(pairs, alvo, has_port=com_porta)


# ============================================================
# META PLATFORMS HTML PARSER (Facebook / Instagram)
# ============================================================

def parse_meta_html(html_content, alvo='desconhecido', update_callback=None):
    """
    Extrai IPs e timestamps do HTML do Meta Platforms Business Record.
    Formato: seção #property-ip_addresses com pares IP Address → Time em divs.
    IPs podem ter porta (Instagram: 198.51.100.19:1135) ou não (Facebook).
    IPv6 vem entre brackets: [2001:db8:...]:porta
    """
    if update_callback:
        update_callback("Parsing HTML da Meta Platforms...")

    soup = BeautifulSoup(html_content, 'html.parser')
    ips_section = soup.find(id='property-ip_addresses')

    if not ips_section:
        logger.warning("Seção 'ip_addresses' não encontrada no HTML da Meta")
        return pd.DataFrame(columns=COLUNAS_MODELO)

    pairs = _pares_ip_tempo(ips_section, 'Meta')

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

        # Porta logo depois de Ip, na mesma posição em que a Meta a entrega —
        # o dict preserva a ordem de inserção e ela vira a ordem das colunas.
        row = {'Alvo': alvo, 'Ip': ip}
        if has_port:
            row['Porta'] = porta
        row.update({
            'Data': data,
            'Data_Fuso': TZ_LABEL,
            'Ip_Dono': None, 'Ip_AS': None,
            'Ip_Regiao': None, 'Ip_Cidade': None,
            'Ip_Pais': None, 'Ip_Pais_Codigo': None,
            'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False,
            'Ip_Lat': None, 'Ip_Lon': None,
            'Periodo': periodo, 'ISO_Date': iso_date,
        })
        resultados.append(row)

    return pd.DataFrame(resultados)


def _build_dataframe_meta(pairs, alvo):
    """Constrói DataFrame para Meta (com separação IP/Porta)."""
    resultados = []
    invalidos = 0
    sem_data = 0
    for ts_str, ip_raw in pairs:
        ip, porta = _split_ip_port(ip_raw)

        if not ip or not is_valid_ip(ip):
            # Descartar em silêncio é como a quebra de página passou
            # despercebida: o total do artefato não batia com o do documento.
            invalidos += 1
            logger.warning("Meta: IP inválido descartado: %r", ip_raw)
            continue

        if not ts_str.strip():
            sem_data += 1

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

    if invalidos:
        logger.warning("Meta: %d registro(s) descartados por IP inválido", invalidos)
    if sem_data:
        logger.warning("Meta: %d registro(s) sem timestamp — verifique quebras "
                       "de página no documento de origem", sem_data)
    return pd.DataFrame(resultados)


def _split_ip_port(ip_raw):
    """
    Separa IP e porta do formato Meta Platforms.
    Formatos: '198.51.100.19:1135', '[2001:db8:...]:63629', '198.51.100.19' (sem porta)
    """
    ip_raw = ip_raw.strip()

    # IPv6 entre brackets: [2001:db8:...]:porta
    match_v6 = re.match(r'^\[([^\]]+)\]:?(\d+)?$', ip_raw)
    if match_v6:
        ip = match_v6.group(1)
        porta = match_v6.group(2) or ''
        return ip, porta

    # IPv4 com porta: 198.51.100.19:1135
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}:\d+$', ip_raw):
        parts = ip_raw.rsplit(':', 1)
        return parts[0], parts[1]

    # IPv4 sem porta, ou IPv6 sem brackets.
    #
    # Um IPv6 sem brackets é ambíguo por construção: em `2001:db8:7002::1:37229`
    # não há como saber se o último grupo é porta ou parte do endereço, porque
    # os dois usam `:`. Meta e WhatsApp colocam brackets sempre que há porta,
    # então a leitura conservadora é tratar o valor inteiro como endereço.
    # Chutar uma porta aqui inventaria dado que o documento não afirma.
    return ip_raw, ''
