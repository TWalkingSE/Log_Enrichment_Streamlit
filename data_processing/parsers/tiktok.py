"""TikTok: relatório "Events IP Data" da TikTok Pte. Limited."""

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
        update_callback('Processando formato TikTok (Events IP Data)...')

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
        if re.fullmatch(r'\d{1,4}', line_stripped):
            continue
        lines_clean.append(line_stripped)

    field_pattern = re.compile(r'^(Date|IP|Event|Country)\s*:\s*(.+?)\s*$', re.IGNORECASE)
    registros_brutos = []
    atual = {}

    for line in lines_clean:
        m = field_pattern.match(line)
        if not m:
            continue
        campo = m.group(1).capitalize()
        if campo == 'Ip':
            campo = 'IP'
        valor = m.group(2).strip()

        # Campo repetido = começou um novo registro antes de fechar o anterior.
        if campo in atual:
            if all(k in atual for k in ('Date', 'IP', 'Event')):
                registros_brutos.append(atual)
            atual = {}
        atual[campo] = valor

        if all(k in atual for k in ('Date', 'IP', 'Event')):
            registros_brutos.append(atual)
            atual = {}

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
        date_str = re.sub(r'\s*\(UTC\s*[+\-]?\d+\)\s*$', '', date_raw).strip()

        dedup_key = (ip, date_str, evento)
        if dedup_key in ips_processados:
            continue
        ips_processados.add(dedup_key)

        try:
            dt_utc = datetime.strptime(date_str, '%d/%m/%Y %I:%M:%S%p')
            dt_local = convert_utc_to_local(dt_utc)
            data = dt_local.strftime('%Y-%m-%d %H:%M:%S')
            periodo = get_periodo(dt_local.hour)
            iso_date = format_iso_date(dt_local)
        except (TypeError, ValueError) as e:
            logger.warning(f"Erro ao converter data TikTok '{date_raw}': {e}")
            data = date_str
            periodo = None
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
            'ISO_Date': iso_date,
        })

    if not resultados:
        return pd.DataFrame(columns=COLUNAS_MODELO)

    df = pd.DataFrame(resultados)

    cols_ordered = list(COLUNAS_MODELO)
    idx_ip = cols_ordered.index('Ip')
    cols_ordered.insert(idx_ip + 1, 'Evento')
    df = df[[c for c in cols_ordered if c in df.columns]]

    if update_callback:
        update_callback(f"Extraídos {len(df)} registros "
                        f"({df['Evento'].nunique()} tipos de evento) do formato TikTok")

    return df
