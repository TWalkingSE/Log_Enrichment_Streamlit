"""Fusão dos resultados da API de geolocalização no DataFrame do log.

Separado de `data_processor` (que continua sendo a fachada pública).
"""

import logging

import pandas as pd

from data_processing.formats import COLUNAS_EXTRAS_PROVEDOR, COLUNAS_MODELO
from data_processing.timezone import TZ_LABEL, format_iso_date, get_periodo
from validators import parse_data

logger = logging.getLogger(__name__)


def processar_resultados(df_original, resultados_ips):
    """Processa os resultados da API e combina com o DataFrame original (vetorizado)"""
    df_processado = df_original.copy()

    # Colunas extras específicas do provedor presentes neste DataFrame
    # (Porta no Meta, Evento no TikTok, User_Agent no Preservation Google, ...)
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
            data_parsed = parse_data(df_processado['Data'])
            valid_mask = data_parsed.notna()
            if valid_mask.any():
                horas = data_parsed[valid_mask].dt.hour
                df_processado.loc[valid_mask, 'Periodo'] = horas.apply(get_periodo)
                df_processado.loc[valid_mask, 'ISO_Date'] = data_parsed[valid_mask].apply(
                    lambda dt: format_iso_date(dt.to_pydatetime()) if pd.notna(dt) else None
                )
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning(f"Erro ao calcular Periodo/ISO_Date vetorizado: {e}")

    # Definir colunas de saída preservando as colunas extras do provedor
    if extras_presentes:
        colunas_saida = [col for col in COLUNAS_MODELO]
        # Inserir as extras logo após Ip, na ordem de COLUNAS_EXTRAS_PROVEDOR
        idx_ip = colunas_saida.index('Ip')
        for i, extra_col in enumerate(extras_presentes):
            colunas_saida.insert(idx_ip + 1 + i, extra_col)
        return df_processado[colunas_saida]
    else:
        return df_processado[COLUNAS_MODELO]
