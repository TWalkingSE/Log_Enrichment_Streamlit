"""Detecção de formato e extração de IPs por plataforma.

Um módulo por família de documento; aqui ficam a detecção
(`detectar_formato_log`) e o despachante (`extrair_ips_de_texto`). A fachada
pública continua sendo `data_processor`.
"""

import logging

import pandas as pd

from data_processing.parsers.discord import extrair_ips_do_formato_discord
from data_processing.parsers.google import (
    extrair_ips_do_formato_google,
    extrair_ips_do_formato_preservation_google,
)
from data_processing.parsers.meta import (
    extrair_ips_do_formato_meta,
    extrair_ips_do_formato_whatsapp,
    parse_meta_ip_port,
)
from data_processing.parsers.texto import (
    detectar_separador_csv,
    extrair_ips_do_formato_simples,
    extrair_ips_texto_simples,
)
from data_processing.parsers.tiktok import extrair_ips_do_formato_tiktok

logger = logging.getLogger(__name__)

__all__ = [
    'detectar_formato_log',
    'detectar_separador_csv',
    'extrair_ips_de_texto',
    'extrair_ips_do_formato_discord',
    'extrair_ips_do_formato_google',
    'extrair_ips_do_formato_meta',
    'extrair_ips_do_formato_preservation_google',
    'extrair_ips_do_formato_simples',
    'extrair_ips_do_formato_tiktok',
    'extrair_ips_do_formato_whatsapp',
    'extrair_ips_texto_simples',
    'parse_meta_ip_port',
]


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
    # TikTok: relatório "Events IP Data" da TikTok Pte. Limited
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

            with open(file_path_or_content, 'r', encoding='utf-8', errors='replace') as f:
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

        # Formato TikTok (Events IP Data)
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
