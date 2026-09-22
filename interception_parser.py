"""
WhatsApp Interception Parser
Parses WhatsApp Business Record HTML files (Interceptação Telemática)
to extract Message Log and Call Log entries with IPs, ports, and metadata.
"""

import re
import io
import os
import zipfile
import logging
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
from api_client import is_valid_ip
from data_processor import TZ_LABEL, convert_utc_to_local, format_iso_date, get_periodo

logger = logging.getLogger(__name__)

# Colunas do modelo de saída para interceptação
COLUNAS_INTERCEPTACAO = [
    'FROM', 'Sender IP', 'Sender Port', 'Data', 'Data_Fuso',
    'Ip_Dono', 'Ip_AS', 'Ip_Regiao', 'Ip_Cidade',
    'Ip_Pais', 'Ip_Pais_Codigo',
    'Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem',
    'Ip_Lat', 'Ip_Lon', 'Periodo', 'ISO_Date', 'type'
]

COLUNAS_EXPORT_INTERCEPTACAO = [
    'FROM', 'Sender IP', 'Sender Port', 'Data', 'Data_Fuso',
    'Ip_Dono', 'Ip_AS', 'Ip_Regiao', 'Ip_Cidade',
    'Ip_Pais', 'Ip_Pais_Codigo',
    'Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem',
    'Reputação', 'Periodo', 'ISO_Date', 'type'
]


def parse_html_records(html_content, update_callback=None):
    """
    Parse a WhatsApp Business Record HTML file and extract
    Message Log and Call Log entries.

    Returns:
        list of dicts with keys: from_number, ip, port, timestamp, type
    """
    records = []

    # Use BeautifulSoup to extract text with separators
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract Account Identifier (target phone)
    full_text = soup.get_text(separator='|', strip=True)

    # --- Parse Message Log ---
    msg_section = soup.find('div', id='property-message_log')
    if msg_section:
        msg_text = msg_section.get_text(separator='|', strip=True)
        # Remove page breaks
        msg_text = re.sub(r'WhatsApp Business Record Page \d+\|?', '', msg_text)
        # Remove definition section
        parts = msg_text.split('Message Log|', 1)
        if len(parts) > 1:
            msg_data = parts[1]
        else:
            msg_data = msg_text

        # Split by Message entries
        messages = re.split(r'\|?Message\|', msg_data)
        for msg in messages:
            if not msg.strip():
                continue

            fields = msg.split('|')
            entry = {}
            i = 0
            while i < len(fields):
                key = fields[i].strip()
                if key == 'Timestamp' and i + 1 < len(fields):
                    entry['timestamp'] = fields[i + 1].strip()
                    i += 2
                elif key == 'Sender' and i + 1 < len(fields):
                    entry['from'] = fields[i + 1].strip()
                    i += 2
                elif key == 'Sender Ip' and i + 1 < len(fields):
                    entry['ip'] = fields[i + 1].strip()
                    i += 2
                elif key == 'Sender Port' and i + 1 < len(fields):
                    entry['port'] = fields[i + 1].strip()
                    i += 2
                elif key == 'Type' and i + 1 < len(fields):
                    entry['msg_type'] = fields[i + 1].strip()
                    i += 2
                else:
                    i += 1

            if entry.get('ip') and entry.get('timestamp'):
                records.append({
                    'from_number': entry.get('from', ''),
                    'ip': entry['ip'],
                    'port': entry.get('port', ''),
                    'timestamp': entry['timestamp'],
                    'type': f"message/{entry.get('msg_type', 'unknown')}"
                })

    # --- Parse Call Log ---
    call_section = soup.find('div', id='property-call_logs')
    if not call_section:
        # Try alternative: find by scanning for Call Logs section
        for div in soup.find_all('div', class_='content-pane'):
            text = div.get_text(strip=True)[:100]
            if 'Call Logs Definition' in text or 'Call Log' in text:
                call_section = div
                break

    if call_section:
        call_text = call_section.get_text(separator='|', strip=True)
        # Remove page breaks
        call_text = re.sub(r'WhatsApp Business Record Page \d+\|?', '', call_text)
        # Remove definition
        parts = call_text.split('Call Log|', 1)
        if len(parts) > 1:
            call_data = parts[1]
        else:
            call_data = call_text

        # Split by Call entries
        calls = re.split(r'\|?Call\|', call_data)
        for call in calls:
            if not call.strip():
                continue

            fields = call.split('|')
            # Each call can have multiple events (offer, accept, terminate)
            # Each event has its own From, From Ip, From Port
            current_call_id = ''
            media_type = ''
            i = 0
            events = []
            current_event = {}

            while i < len(fields):
                key = fields[i].strip()
                if key == 'Call Id' and i + 1 < len(fields):
                    current_call_id = fields[i + 1].strip()
                    i += 2
                elif key == 'Media Type' and i + 1 < len(fields):
                    media_type = fields[i + 1].strip()
                    i += 2
                elif key == 'Type' and i + 1 < len(fields):
                    # New event starts
                    if current_event.get('ip'):
                        events.append(current_event.copy())
                    current_event = {'event_type': fields[i + 1].strip()}
                    i += 2
                elif key == 'Timestamp' and i + 1 < len(fields):
                    current_event['timestamp'] = fields[i + 1].strip()
                    i += 2
                elif key == 'From' and i + 1 < len(fields):
                    current_event['from'] = fields[i + 1].strip()
                    i += 2
                elif key == 'From Ip' and i + 1 < len(fields):
                    current_event['ip'] = fields[i + 1].strip()
                    i += 2
                elif key == 'From Port' and i + 1 < len(fields):
                    current_event['port'] = fields[i + 1].strip()
                    i += 2
                else:
                    i += 1

            # Don't forget last event
            if current_event.get('ip'):
                events.append(current_event)

            for evt in events:
                if evt.get('ip') and evt.get('timestamp'):
                    call_type = f"call/{media_type}" if media_type else "call"
                    records.append({
                        'from_number': evt.get('from', ''),
                        'ip': evt['ip'],
                        'port': evt.get('port', ''),
                        'timestamp': evt['timestamp'],
                        'type': call_type
                    })

    if update_callback:
        update_callback(f"Extraídos {len(records)} registros do HTML")

    return records


def records_to_dataframe(records, update_callback=None):
    """
    Convert parsed records to a DataFrame with standardized columns.
    Converts timestamps from UTC to GMT-3.
    """
    rows = []
    for rec in records:
        ip = rec.get('ip', '').strip()
        if not ip or not is_valid_ip(ip):
            continue

        port = rec.get('port', '').strip()
        timestamp_str = rec.get('timestamp', '').strip()

        # Remove 'UTC' suffix if present
        timestamp_str = timestamp_str.replace(' UTC', '').strip()

        # Convert from UTC to local timezone
        try:
            dt_utc = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            dt_local = convert_utc_to_local(dt_utc)
            data_formatada = dt_local.strftime('%Y-%m-%d %H:%M:%S')
            hora = dt_local.hour
            periodo = get_periodo(hora)
            iso_date = format_iso_date(dt_local)
        except Exception as e:
            logger.warning(f"Erro ao converter timestamp '{timestamp_str}': {e}")
            data_formatada = timestamp_str
            periodo = None
            iso_date = None

        rows.append({
            'FROM': rec.get('from_number', ''),
            'Sender IP': ip,
            'Sender Port': port,
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
            'Ip_Lat': None,
            'Ip_Lon': None,
            'Periodo': periodo,
            'ISO_Date': iso_date,
            'type': rec.get('type', '')
        })

    if not rows:
        return pd.DataFrame(columns=COLUNAS_INTERCEPTACAO)

    df = pd.DataFrame(rows)

    if update_callback:
        update_callback(f"DataFrame criado com {len(df)} registros válidos")

    return df


# Limites de segurança para extração de ZIP
MAX_ZIP_FILE_SIZE = 500 * 1024 * 1024  # 500 MB por arquivo extraído
MAX_ZIP_TOTAL_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB total extraído
MAX_ZIP_DEPTH = 2  # Máximo de ZIPs aninhados
MAX_ZIP_RATIO = 100  # Ratio máximo compressed/uncompressed (proteção zip bomb)


def _is_safe_zip_entry(name):
    """Valida que o nome do arquivo no ZIP não contém path traversal."""
    # Rejeitar caminhos absolutos e traversal
    normalized = os.path.normpath(name)
    if normalized.startswith(('..', os.sep, '/', '\\')):
        return False
    if '..' in normalized.split(os.sep):
        return False
    # Rejeitar caminhos com drive letter (Windows absolute paths)
    if len(normalized) >= 2 and normalized[1] == ':':
        return False
    return True


def _check_zip_bomb(zf, max_ratio=MAX_ZIP_RATIO, max_total=MAX_ZIP_TOTAL_SIZE):
    """Verifica se o ZIP parece ser um zip bomb baseado no ratio de compressão."""
    total_compressed = 0
    total_uncompressed = 0
    for info in zf.infolist():
        total_compressed += info.compress_size or 1
        total_uncompressed += info.file_size
        if total_uncompressed > max_total:
            return False, f"Tamanho total excede {max_total // (1024*1024)}MB"
    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        if ratio > max_ratio:
            return False, f"Ratio de compressão suspeito ({ratio:.0f}x > {max_ratio}x)"
    return True, ""


def parse_zip_interception(zip_path_or_bytes, update_callback=None):
    """
    Parse a ZIP file containing WhatsApp interception data.
    Supports:
    - ZIP of ZIPs (each inner ZIP has records.html)
    - ZIP with HTML files directly
    - Single HTML file

    Returns:
        DataFrame with all extracted records
    """
    all_records = []

    if isinstance(zip_path_or_bytes, (str, os.PathLike)):
        zf = zipfile.ZipFile(zip_path_or_bytes)
    else:
        zf = zipfile.ZipFile(io.BytesIO(zip_path_or_bytes))

    # Verificar zip bomb
    safe, reason = _check_zip_bomb(zf)
    if not safe:
        logger.error(f"ZIP rejeitado por segurança: {reason}")
        if update_callback:
            update_callback(f"⚠️ ZIP rejeitado: {reason}")
        zf.close()
        return records_to_dataframe([], update_callback)

    file_count = 0
    for name in zf.namelist():
        # Proteção contra path traversal
        if not _is_safe_zip_entry(name):
            logger.warning(f"Entrada ZIP ignorada (path traversal): {name}")
            continue

        if name.endswith('.zip'):
            # Inner ZIP — extract and parse records.html from it (depth=1)
            try:
                info = zf.getinfo(name)
                if info.file_size > MAX_ZIP_FILE_SIZE:
                    logger.warning(f"Arquivo {name} excede limite ({info.file_size} bytes), ignorando")
                    continue
                inner_data = zf.read(name)
                inner_zf = zipfile.ZipFile(io.BytesIO(inner_data))
                # Verificar zip bomb no ZIP interno
                inner_safe, inner_reason = _check_zip_bomb(inner_zf)
                if not inner_safe:
                    logger.warning(f"ZIP interno {name} rejeitado: {inner_reason}")
                    inner_zf.close()
                    continue
                for inner_name in inner_zf.namelist():
                    if not _is_safe_zip_entry(inner_name):
                        logger.warning(f"Entrada ZIP interna ignorada (path traversal): {inner_name}")
                        continue
                    # Não permitir mais ZIPs aninhados (depth=2 seria 3o nível)
                    if inner_name.endswith('.zip'):
                        logger.warning(f"ZIP aninhado demais ignorado: {name}/{inner_name}")
                        continue
                    if inner_name.endswith('.html') and 'records' in inner_name.lower():
                        inner_info = inner_zf.getinfo(inner_name)
                        if inner_info.file_size > MAX_ZIP_FILE_SIZE:
                            logger.warning(f"Arquivo {inner_name} excede limite, ignorando")
                            continue
                        html = inner_zf.read(inner_name).decode('utf-8', errors='replace')
                        records = parse_html_records(html, update_callback)
                        all_records.extend(records)
                        file_count += 1
                        if update_callback:
                            update_callback(f"Processado {name}/{inner_name}: {len(records)} registros")
                inner_zf.close()
            except Exception as e:
                logger.error(f"Erro ao processar {name}: {e}")
                if update_callback:
                    update_callback(f"Erro em {name}: {e}")

        elif name.endswith('.html') and 'records' in name.lower():
            # Direct HTML in ZIP
            try:
                info = zf.getinfo(name)
                if info.file_size > MAX_ZIP_FILE_SIZE:
                    logger.warning(f"Arquivo {name} excede limite ({info.file_size} bytes), ignorando")
                    continue
                html = zf.read(name).decode('utf-8', errors='replace')
                records = parse_html_records(html, update_callback)
                all_records.extend(records)
                file_count += 1
                if update_callback:
                    update_callback(f"Processado {name}: {len(records)} registros")
            except Exception as e:
                logger.error(f"Erro ao processar {name}: {e}")

    zf.close()

    if update_callback:
        update_callback(f"Total: {len(all_records)} registros de {file_count} arquivos HTML")

    return records_to_dataframe(all_records, update_callback)


def _add_reputacao_interceptacao(df):
    """Adiciona coluna Reputação (delega à implementação compartilhada)."""
    from analysis import add_reputacao_column
    return add_reputacao_column(df)


def processar_resultados_interceptacao(df, resultados_api):
    """
    Merge API enrichment results into the interception DataFrame.
    Supports both raw API responses and normalized IPAPIClient results.

    Usa o mesmo idioma vetorizado de `data_processor.processar_resultados`:
    a versão anterior fazia `df['Sender IP'] == ip` por IP — com milhares de
    IPs sobre 200k linhas isso são bilhões de comparações e dezenas de
    milhares de escritas `.loc` encadeadas.
    """
    if not resultados_api:
        return df

    # Campo de destino -> chaves aceitas na resposta (normalizada ou crua)
    CAMPOS = (
        ('Ip_Dono', ('Ip_Dono', 'org', 'isp')),
        ('Ip_AS', ('Ip_AS', 'as')),
        ('Ip_Regiao', ('Ip_Regiao', 'regionName')),
        ('Ip_Cidade', ('Ip_Cidade', 'city')),
        ('Ip_Pais', ('Ip_Pais', 'country')),
        ('Ip_Pais_Codigo', ('Ip_Pais_Codigo', 'countryCode')),
    )
    # Estes são gravados mesmo quando falsos/nulos, preservando o
    # comportamento anterior (um False da API sobrescreve o default).
    CAMPOS_DIRETOS = (
        ('Ip_Movel', ('Ip_Movel', 'mobile'), False),
        ('Ip_Proxy', ('Ip_Proxy', 'proxy'), False),
        ('Ip_Hospedagem', ('Ip_Hospedagem', 'hosting'), False),
        ('Ip_Lat', ('Ip_Lat', 'lat'), None),
        ('Ip_Lon', ('Ip_Lon', 'lon'), None),
    )

    def _first(dados, chaves):
        for k in chaves:
            if k in dados:
                return dados[k]
        return None

    registros = []
    for ip, dados in resultados_api.items():
        status = dados.get('status', '')
        if not (status == 'success' or 'Ip_Dono' in dados):
            continue
        rec = {'_merge_ip': ip}
        for destino, chaves in CAMPOS:
            val = _first(dados, chaves)
            if val in (None, ''):
                continue
            texto = str(val)
            if texto == 'Erro' or texto.startswith('Erro:'):
                continue
            rec[destino] = val
        for destino, chaves, default in CAMPOS_DIRETOS:
            val = _first(dados, chaves)
            rec[destino] = default if val is None else val
        registros.append(rec)

    if not registros:
        return df

    df_api = pd.DataFrame(registros)
    campos = [c for c in df_api.columns if c != '_merge_ip' and c in df.columns]
    for campo in campos:
        ip_to_value = dict(zip(df_api['_merge_ip'], df_api[campo]))
        # Valores ausentes neste campo não devem apagar o que já existe.
        ip_to_value = {k: v for k, v in ip_to_value.items() if not pd.isna(v)}
        if not ip_to_value:
            continue
        mask = df['Sender IP'].isin(ip_to_value.keys())
        df.loc[mask, campo] = df.loc[mask, 'Sender IP'].map(ip_to_value)

    return df


async def processar_interceptacao_async(zip_data, output_file, batch_size=500, period=0,
                                         cache_file='ip_cache.json',
                                         update_callback=None, progress_callback=None,
                                         api_key=None):
    """
    Full async pipeline: parse ZIP → extract IPs → enrich via shared service → save CSV.
    """
    from enrich_service import enrich_dataframe

    if update_callback:
        update_callback("Iniciando processamento de interceptação telemática...")

    df = parse_zip_interception(zip_data, update_callback)

    if df.empty:
        if update_callback:
            update_callback("Nenhum registro encontrado no ZIP")
        return df

    if update_callback:
        update_callback(f"Total de registros: {len(df)}")

    df, _results = await enrich_dataframe(
        df,
        'Sender IP',
        cache_file=cache_file,
        api_key=api_key,
        batch_size=batch_size,
        period=period,
        update_callback=update_callback,
        progress_callback=progress_callback,
        apply_results=processar_resultados_interceptacao,
    )

    df = _add_reputacao_interceptacao(df)

    from file_handler import salvar_exportacao
    salvar_exportacao(df, COLUNAS_EXPORT_INTERCEPTACAO, output_file, update_callback)

    return df
