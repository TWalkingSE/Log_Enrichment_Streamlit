"""
Log Enrichment - Shared Helper Functions
Functions used across multiple pages: logging, history, anomaly detection.
"""

import streamlit as st
import os
import re
import json
import logging
import asyncio
from datetime import datetime

from validators import as_bool

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
    """Detect IPs in unusual locations compared to the majority (vectorized)."""
    anomalies = []
    if df is None or df.empty or 'Ip_Cidade' not in df.columns or 'Ip' not in df.columns:
        return anomalies

    city_counts = df['Ip_Cidade'].value_counts()
    if len(city_counts) < 2:
        return anomalies

    top_city = city_counts.index[0]
    top_count = int(city_counts.iloc[0])
    total = len(df)
    if top_count / total < 0.3:
        return anomalies

    threshold = max(2, total * 0.05)
    rare_cities = set(city_counts[city_counts <= threshold].index)
    rare_cities.discard(top_city)
    if not rare_cities:
        return anomalies

    mask = df['Ip_Cidade'].isin(rare_cities) & df['Ip_Cidade'].notna()
    subset = df.loc[mask]
    if subset.empty:
        return anomalies

    seen = set()
    for row in subset.itertuples(index=False):
        ip = getattr(row, 'Ip', '')
        if ip in seen:
            continue
        seen.add(ip)
        city = getattr(row, 'Ip_Cidade', '')
        is_proxy = as_bool(getattr(row, 'Ip_Proxy', None), field='Ip_Proxy') if hasattr(row, 'Ip_Proxy') else False
        is_hosting = as_bool(getattr(row, 'Ip_Hospedagem', None), field='Ip_Hospedagem') if hasattr(row, 'Ip_Hospedagem') else False
        flags = []
        if is_proxy:
            flags.append('Proxy/VPN')
        if is_hosting:
            flags.append('Hosting')
        anomalies.append({
            'Ip': ip,
            'Cidade': city,
            'Regiao': getattr(row, 'Ip_Regiao', '') if hasattr(row, 'Ip_Regiao') else '',
            'Provedor': getattr(row, 'Ip_Dono', '') if hasattr(row, 'Ip_Dono') else '',
            'Data': getattr(row, 'Data', '') if hasattr(row, 'Data') else '',
            'Flags': ', '.join(flags) if flags else 'Nenhum',
            'Motivo': f'Localização incomum (cidade principal: {top_city})',
        })
        if len(anomalies) >= 20:
            break
    return anomalies


def run_async(coro):
    """Run a coroutine safely from Streamlit (no nested-loop crashes)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def run_processing(input_data, output_file, is_file, batch_size, period,
                   cache_file, incremental, alvo, api_key=None,
                   progress_callback=None):
    from file_handler import processar_log_acesso_async
    return run_async(
        processar_log_acesso_async(
            input_data, output_file, is_file, batch_size, period,
            cache_file, incremental,
            update_callback=lambda msg: add_log(msg),
            progress_callback=progress_callback or (lambda cur, tot: None),
            alvo=alvo, api_key=api_key
        )
    )
