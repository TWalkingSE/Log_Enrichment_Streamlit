"""
Log Enrichment - Shared Helper Functions
Functions used across multiple pages: logging, history, anomaly detection.
"""

import streamlit as st
import pandas as pd
import os
import re
import json
import logging
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


def add_log(msg):
    timestamp = datetime.now().strftime('%H:%M:%S')
    st.session_state.log_messages.append(f"[{timestamp}] {msg}")
    if len(st.session_state.log_messages) > 200:
        st.session_state.log_messages = st.session_state.log_messages[-200:]


def extract_alvo_from_filename(filename):
    """Extrai número de telefone (10-15 dígitos) do nome do arquivo.
    Ignora números maiores (ex: Discord User IDs de 17-19 dígitos)."""
    name = os.path.splitext(filename)[0]
    match = re.search(r'\+?(?<!\d)(\d{10,15})(?!\d)', name)
    return match.group(1) if match else ''


def save_history(alvo, total_ips, output_file, fmt):
    entry = {
        'data': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'alvo': alvo,
        'total_ips': total_ips,
        'output_file': output_file,
        'formato': fmt
    }
    st.session_state.history.append(entry)
    try:
        hist_file = 'processing_history.json'
        existing = []
        if os.path.exists(hist_file):
            with open(hist_file, 'r') as f:
                existing = json.load(f)
        existing.append(entry)
        with open(hist_file, 'w') as f:
            json.dump(existing[-50:], f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erro ao salvar histórico: {e}")


def load_history():
    try:
        if os.path.exists('processing_history.json'):
            with open('processing_history.json', 'r') as f:
                st.session_state.history = json.load(f)
    except Exception as e:
        logger.error(f"Erro ao carregar histórico: {e}")


def detect_anomalies(df):
    """Detect IPs in unusual locations compared to the majority"""
    anomalies = []
    if 'Ip_Cidade' not in df.columns or 'Ip' not in df.columns:
        return anomalies

    city_counts = df['Ip_Cidade'].value_counts()
    if len(city_counts) < 2:
        return anomalies

    top_city = city_counts.index[0]
    top_count = city_counts.iloc[0]
    total = len(df)

    if top_count / total < 0.3:
        return anomalies

    for _, row in df.iterrows():
        city = row.get('Ip_Cidade')
        if pd.notna(city) and city != top_city:
            count_this = city_counts.get(city, 0)
            if count_this <= max(2, total * 0.05):
                is_proxy = row.get('Ip_Proxy', False)
                is_hosting = row.get('Ip_Hospedagem', False)
                flags = []
                if is_proxy:
                    flags.append('Proxy/VPN')
                if is_hosting:
                    flags.append('Hosting')
                anomalies.append({
                    'Ip': row.get('Ip', ''),
                    'Cidade': city,
                    'Regiao': row.get('Ip_Regiao', ''),
                    'Provedor': row.get('Ip_Dono', ''),
                    'Data': row.get('Data', ''),
                    'Flags': ', '.join(flags) if flags else 'Nenhum',
                    'Motivo': f'Localização incomum (cidade principal: {top_city})'
                })

    seen = set()
    unique = []
    for a in anomalies:
        if a['Ip'] not in seen:
            seen.add(a['Ip'])
            unique.append(a)
    return unique[:20]


def run_processing(input_data, output_file, is_file, batch_size, period,
                   cache_file, incremental, alvo, api_key=None,
                   progress_callback=None):
    from file_handler import processar_log_acesso_async
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            processar_log_acesso_async(
                input_data, output_file, is_file, batch_size, period,
                cache_file, incremental,
                update_callback=lambda msg: add_log(msg),
                progress_callback=progress_callback or (lambda cur, tot: None),
                alvo=alvo, api_key=api_key
            )
        )
    finally:
        loop.close()
