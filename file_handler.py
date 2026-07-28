import pandas as pd
import logging
import os
import re
import json
from pathlib import Path
from data_processor import (COLUNAS_MODELO, COLUNAS_EXPORT, COLUNAS_EXPORT_META,
                          COLUNAS_EXPORT_PRESERVATION_GOOGLE, COLUNAS_EXPORT_DISCORD,
                          COLUNAS_EXPORT_TIKTOK,
                          detectar_separador_csv, extrair_ips_de_texto, processar_resultados,
                          extrair_ips_do_formato_preservation_google,
                          TZ_LABEL, get_periodo, format_iso_date)
from api_client import is_valid_ip
from analysis import format_reputacao

# Configurar logger para este módulo
logger = logging.getLogger(__name__)

def carregar_arquivo_log(input_file, update_callback=None, alvo='desconhecido'):
    """Carrega um arquivo de log e extrai os IPs com seus dados temporais"""
    ext = Path(input_file).suffix.lower()

    try:
        if update_callback:
            update_callback(f"Carregando arquivo {input_file}")

        # Extrair data do nome do arquivo se possível
        filename = os.path.basename(input_file)
        data_arquivo = None

        # Verificar formato específico 20250310123909
        timestamp_match = re.search(r'(\d{14})', filename)
        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            try:
                data_arquivo = f"{timestamp_str[0:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]} {timestamp_str[8:10]}:{timestamp_str[10:12]}:{timestamp_str[12:14]}"
                logger.info(f"Data extraída do nome do arquivo: {data_arquivo}")
            except (TypeError, ValueError):
                pass

        if ext == '.csv':
            # Detectar separador
            separador = detectar_separador_csv(input_file)
            logger.info(f"Separador detectado: '{separador}'")

            # Tentar diferentes encodings
            for encoding in ['utf-8', 'latin1', 'cp1252']:
                try:
                    df = pd.read_csv(input_file, sep=separador, encoding=encoding)
                    break
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    raise e
            else:
                df = pd.read_csv(input_file, sep=separador, encoding='utf-8', errors='replace')
        elif ext in ('.xls', '.xlsx'):
            df = pd.read_excel(input_file)
        elif ext == '.txt':
            # Usar função específica para extrair IPs de texto
            return extrair_ips_de_texto(input_file, True, update_callback, alvo=alvo)
        elif ext in ('.html', '.htm'):
            # HTML de plataformas (WhatsApp, Meta, Google)
            from html_parser import parse_html_file
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                html_content = f.read()
            df_html, platform = parse_html_file(html_content, alvo=alvo, update_callback=update_callback)
            if update_callback:
                update_callback(f"HTML ({platform}): {len(df_html)} registros extraídos")
            return df_html
        elif ext == '.pdf':
            # Extrair texto do PDF e processar como texto
            try:
                import pdfplumber
                text_parts = []
                with pdfplumber.open(input_file) as pdf:
                    for page in pdf.pages:
                        try:
                            page_text = page.extract_text()
                            if page_text:
                                text_parts.append(page_text)
                        except Exception:
                            continue
                content = '\n'.join(text_parts)
                if not content.strip():
                    raise ValueError("PDF sem conteúdo de texto extraível")
                if update_callback:
                    update_callback(f"Texto extraído do PDF ({len(text_parts)} páginas)")
                return extrair_ips_de_texto(content, False, update_callback, alvo=alvo)
            except ImportError:
                raise ValueError("Biblioteca 'pdfplumber' necessária para PDFs. Instale com: pip install pdfplumber")
        else:
            raise ValueError(f"Formato de arquivo não suportado: {ext}")

        # Detectar formato Preservation Google (CSV do Google Takeout)
        preservation_google_cols = ['Activity Timestamp', 'IP Address', 'User Agent String']
        if all(col in df.columns for col in preservation_google_cols):
            if update_callback:
                update_callback("Formato Preservation Google detectado")
            return extrair_ips_do_formato_preservation_google(df, update_callback, alvo=alvo)

        # Se já temos um arquivo no formato do modelo
        modelo_columns_lower = [col.lower() for col in COLUNAS_MODELO]
        df_columns_lower = [col.lower() for col in df.columns]

        if all(col in df_columns_lower for col in ['ip', 'data']):
            # Padronizar nomes das colunas para o modelo
            rename_map = {}
            for i, col in enumerate(df.columns):
                col_lower = col.lower()
                if col_lower in modelo_columns_lower:
                    index = modelo_columns_lower.index(col_lower)
                    if col != COLUNAS_MODELO[index]:
                        rename_map[col] = COLUNAS_MODELO[index]

            if rename_map:
                df = df.rename(columns=rename_map)

            # Garantir que todas as colunas do modelo existam
            for col in COLUNAS_MODELO:
                if col not in df.columns:
                    if col == 'Alvo':
                        df[col] = 'desconhecido'
                    elif col == 'Data_Fuso':
                        df[col] = TZ_LABEL
                    elif col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                        df[col] = False
                    elif col == 'Periodo':
                        # Calcular período a partir da data
                        if 'Data' in df.columns:
                            try:
                                sample = df['Data'].iloc[0] if not df.empty else None
                                if sample and '/' in str(sample):
                                    data_dt = pd.to_datetime(df['Data'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
                                else:
                                    data_dt = pd.to_datetime(df['Data'], errors='coerce')

                                df['Periodo'] = data_dt.dt.hour.apply(get_periodo)
                            except (AttributeError, TypeError, ValueError) as e:
                                logger.warning(f"Erro ao calcular Periodo: {e}")
                                df['Periodo'] = '☀️ Diurno'
                        else:
                            df['Periodo'] = '☀️ Diurno'
                    elif col == 'ISO_Date':
                        # Gerar ISO_Date a partir da Data
                        if 'Data' in df.columns:
                            try:
                                sample = df['Data'].iloc[0] if not df.empty else None
                                if sample and '/' in str(sample):
                                    data_dt = pd.to_datetime(df['Data'], format='%d/%m/%Y %H:%M:%S', errors='coerce')
                                else:
                                    data_dt = pd.to_datetime(df['Data'], errors='coerce')

                                df['ISO_Date'] = data_dt.apply(
                                    lambda dt: format_iso_date(dt.to_pydatetime()) if pd.notna(dt) else None
                                )
                            except (AttributeError, TypeError, ValueError) as e:
                                logger.warning(f"Erro ao calcular ISO_Date: {e}")
                                df['ISO_Date'] = None
                        else:
                            df['ISO_Date'] = None
                    else:
                        df[col] = None

            # Garantir a ordem exata das colunas do modelo (preservar colunas extras por formato)
            if 'User_ID' in df.columns:
                colunas = [col for col in COLUNAS_MODELO]
                idx_ip = colunas.index('Ip')
                for i, extra_col in enumerate(['User_ID', 'Username', 'Email']):
                    colunas.insert(idx_ip + 1 + i, extra_col)
                df = df[[c for c in colunas if c in df.columns]]
            elif 'Porta' in df.columns:
                colunas = [col for col in COLUNAS_MODELO]
                idx_ip = colunas.index('Ip')
                colunas.insert(idx_ip + 1, 'Porta')
                df = df[[c for c in colunas if c in df.columns]]
            else:
                df = df[COLUNAS_MODELO]

            # Filtrar apenas linhas com IPs válidos
            df['Ip_Valido'] = df['Ip'].apply(lambda x: is_valid_ip(str(x)))
            df = df[df['Ip_Valido']].copy()
            df = df.drop('Ip_Valido', axis=1)

            # Definir Alvo
            df['Alvo'] = alvo

            return df
        else:
            # Criar DataFrame com estrutura do modelo a partir dos dados
            registros = []

            for _, row in df.iterrows():
                # Extrair IP e data
                ip = None
                data = None

                # Tentar encontrar o IP e a data nas colunas
                for col in df.columns:
                    col_str = str(col).lower()
                    valor = row[col]

                    # Procurar IP
                    if not ip and ('ip' in col_str or 'address' in col_str or 'endereco' in col_str):
                        if is_valid_ip(str(valor)):
                            ip = str(valor)

                    # Procurar data
                    if not data and ('data' in col_str or 'date' in col_str or 'time' in col_str or 'hora' in col_str):
                        try:
                            data = str(valor)
                        except (TypeError, ValueError):
                            pass

                # Se não achou IP, tentar qualquer coluna
                if not ip:
                    for col in df.columns:
                        if is_valid_ip(str(row[col])):
                            ip = str(row[col])
                            break

                # Se tem IP válido, adicionar ao resultado
                if ip and is_valid_ip(ip):
                    # Se não tem data, usar a extraída do nome do arquivo (ou deixar vazio)
                    if not data:
                        data = data_arquivo

                    # Determinar período do dia
                    periodo = None
                    iso_date = None

                    if data:
                        # Tentar converter a data para calcular período e ISO_Date
                        try:
                            data_dt = pd.to_datetime(data).to_pydatetime()

                            hora = data_dt.hour
                            periodo = get_periodo(hora)
                            iso_date = format_iso_date(data_dt)
                        except (AttributeError, TypeError, ValueError) as e:
                            logger.warning(f"Erro ao converter data '{data}': {e}")

                        # Converter data para formato padrão
                        try:
                            data = pd.to_datetime(data).strftime('%Y-%m-%d %H:%M:%S')
                        except (AttributeError, TypeError, ValueError) as e:
                            logger.warning(f"Erro ao formatar data '{data}': {e}")

                    # Criar registro no formato do modelo
                    registro = {
                        'Alvo': alvo,
                        'Ip': ip,
                        'Data': data,
                        'Data_Fuso': TZ_LABEL if data else None,
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

            # Criar DataFrame com registros extraídos
            df_resultado = pd.DataFrame(registros)

            # Se vazio, criar DataFrame vazio com colunas do modelo
            if df_resultado.empty:
                df_resultado = pd.DataFrame(columns=COLUNAS_MODELO)
            else:
                # Garantir a ordem das colunas
                for col in COLUNAS_MODELO:
                    if col not in df_resultado.columns:
                        if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                            df_resultado[col] = False
                        elif col == 'Alvo':
                            df_resultado[col] = 'desconhecido'
                        elif col == 'Data_Fuso':
                            df_resultado[col] = TZ_LABEL
                        elif col == 'Periodo':
                            df_resultado[col] = '☀️ Diurno'
                        else:
                            df_resultado[col] = None

                df_resultado = df_resultado[COLUNAS_MODELO]

            return df_resultado

    except Exception as e:
        raise e


async def processar_log_acesso_async(input_file_or_content, output_file, is_file=True, batch_size=500, period=0,
                               cache_file='ip_cache.json', incremental=True,
                               update_callback=None, progress_callback=None, alvo='desconhecido', api_key=None):
    """Processa arquivo de log ou texto, consultando IPs na API"""
    try:
        # Atualizar status
        if update_callback:
            if is_file:
                update_callback(f"Carregando arquivo: {input_file_or_content}")
            else:
                update_callback("Processando texto colado")

        # Carregar os dados
        if is_file:
            df = carregar_arquivo_log(input_file_or_content, update_callback, alvo=alvo)
        else:
            df = extrair_ips_de_texto(input_file_or_content, False, update_callback, alvo=alvo)

        # Detectar formato pelas colunas extras: Meta (Porta), Preservation Google (User_Agent),
        # Discord (User_ID) ou TikTok (Evento)
        is_meta = 'Porta' in df.columns
        is_preservation_google = 'User_Agent' in df.columns
        is_discord = 'User_ID' in df.columns
        is_tiktok = 'Evento' in df.columns

        if df.empty:
            if update_callback:
                update_callback("Nenhum IP válido encontrado nos dados")
            if is_discord:
                return pd.DataFrame(columns=COLUNAS_EXPORT_DISCORD)
            if is_preservation_google:
                return pd.DataFrame(columns=COLUNAS_EXPORT_PRESERVATION_GOOGLE)
            if is_tiktok:
                return pd.DataFrame(columns=COLUNAS_EXPORT_TIKTOK)
            return pd.DataFrame(columns=COLUNAS_EXPORT_META if is_meta else COLUNAS_EXPORT)

        total_records = len(df)
        total_unique_all = df['Ip'].nunique()
        if update_callback:
            update_callback(f"Extraídos {total_records} registros com {total_unique_all} IPs únicos")

        # Verificar se o arquivo já existe e carregar para modo incremental
        df_resultado = None
        if incremental and os.path.exists(output_file):
            try:
                ext_saida = Path(output_file).suffix.lower()
                if ext_saida in ('.xlsx', '.xls'):
                    df_resultado = pd.read_excel(output_file)
                else:
                    sep_existente = detectar_separador_csv(output_file)
                    for encoding in ['utf-8', 'latin1', 'cp1252']:
                        try:
                            df_resultado = pd.read_csv(output_file, sep=sep_existente, encoding=encoding)
                            break
                        except UnicodeDecodeError:
                            continue
                        except (OSError, ValueError, pd.errors.ParserError) as e:
                            raise e
                    else:
                        df_resultado = pd.read_csv(output_file, sep=sep_existente, encoding='utf-8', errors='replace')

                # Verificar se resultado existente é Meta, Preservation Google, Discord ou TikTok
                if 'Porta' in df_resultado.columns:
                    is_meta = True
                if 'User_Agent' in df_resultado.columns:
                    is_preservation_google = True
                if 'User_ID' in df_resultado.columns:
                    is_discord = True
                if 'Evento' in df_resultado.columns:
                    is_tiktok = True

                # Garantir que temos as colunas do modelo
                for col in COLUNAS_MODELO:
                    if col not in df_resultado.columns:
                        if col in ['Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor']:
                            df_resultado[col] = False
                        elif col == 'Alvo':
                            df_resultado[col] = alvo
                        elif col == 'Data_Fuso':
                            df_resultado[col] = TZ_LABEL
                        elif col == 'Periodo':
                            df_resultado[col] = 'Diurno'
                        else:
                            df_resultado[col] = None

                # Recuperar Lat/Lon do cache se ausentes no CSV
                lat_missing = df_resultado['Ip_Lat'].isna().all() if 'Ip_Lat' in df_resultado.columns else True
                if lat_missing and cache_file and os.path.exists(cache_file):
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as cf:
                            ip_cache_data = json.load(cf)
                        df_resultado['Ip_Lat'] = df_resultado['Ip'].map(
                            lambda ip: ip_cache_data.get(ip, {}).get('Ip_Lat'))
                        df_resultado['Ip_Lon'] = df_resultado['Ip'].map(
                            lambda ip: ip_cache_data.get(ip, {}).get('Ip_Lon'))
                        recovered = df_resultado['Ip_Lat'].notna().sum()
                        if update_callback and recovered > 0:
                            update_callback(f"Coordenadas recuperadas do cache para {recovered} registros")
                    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as e:
                        logger.warning(f"Erro ao recuperar coordenadas do cache: {e}")

                if update_callback:
                    update_callback(f"Arquivo existente carregado: {len(df_resultado)} registros")
            except Exception as e:
                if update_callback:
                    update_callback(f"Erro ao carregar arquivo existente: {e}")
                logger.warning(f"Erro ao carregar arquivo existente: {e}")

        # Obter lista de IPs únicos para consulta
        ips_unicos = df['Ip'].unique()

        # Verificar se já temos informações sobre algum IP
        if df_resultado is not None:
            # Só considerar IP como "processado" se tiver dados de enriquecimento válidos
            df_enriquecidos = df_resultado[df_resultado['Ip_Dono'].notna() & (df_resultado['Ip_Dono'] != '')]
            ips_processados = set(df_enriquecidos['Ip'].astype(str))
            ips_novos = [ip for ip in ips_unicos if ip not in ips_processados]

            if update_callback:
                update_callback(f"{len(ips_unicos) - len(ips_novos)} IPs já enriquecidos, {len(ips_novos)} IPs para consultar")

            ips_unicos = ips_novos

        # Atualizar progresso inicial
        total_ips = len(ips_unicos)
        if progress_callback:
            progress_callback(0, total_ips)

        # Se não há IPs novos para processar
        if total_ips == 0:
            if update_callback:
                update_callback("Nenhum IP novo para processar")
            if df_resultado is not None:
                return df_resultado
            if is_discord:
                return pd.DataFrame(columns=COLUNAS_EXPORT_DISCORD)
            if is_tiktok:
                return pd.DataFrame(columns=COLUNAS_EXPORT_TIKTOK)
            return pd.DataFrame(columns=COLUNAS_EXPORT_META if is_meta else COLUNAS_EXPORT)

        # Enriquecimento via application layer (use-case facade)
        from application.enrich_use_case import enrich_ip_list

        def _on_batch_progress(processed, total):
            if progress_callback:
                progress_callback(min(processed, total_ips), total_ips, total_records)

        if update_callback:
            update_callback(f"Enviando {total_ips} IPs para o endpoint batch...")

        resultados_ips, _client = await enrich_ip_list(
            list(ips_unicos),
            cache_file=cache_file,
            api_key=api_key,
            batch_size=batch_size,
            period=period,
            update_callback=update_callback,
            progress_callback=_on_batch_progress,
            save_cache=True,
        )

        # Processar resultados finais
        df_processado = processar_resultados(df, resultados_ips)

        # Combinar com dados existentes
        if df_resultado is not None:
            df_final = pd.concat([df_resultado, df_processado])
            dedup_cols = _incremental_dedup_columns(df_final)
            df_final = df_final.drop_duplicates(subset=dedup_cols, keep='last')
        else:
            df_final = df_processado

        # Normalizar nomes de provedores (Claro S.A/NXT/Net → Claro, etc.)
        from data_processor import normalizar_provedor_df
        df_final = normalizar_provedor_df(df_final)

        # Adicionar coluna Reputação
        df_final = _add_reputacao_column(df_final)

        # Definir colunas de exportação (com User_ID/Username/Email para Discord, User_Agent para Preservation Google, Porta para Meta, Evento para TikTok)
        if is_discord:
            export_cols = [c for c in COLUNAS_EXPORT_DISCORD if c in df_final.columns]
        elif is_preservation_google:
            export_cols = [c for c in COLUNAS_EXPORT_PRESERVATION_GOOGLE if c in df_final.columns]
        elif is_tiktok:
            export_cols = [c for c in COLUNAS_EXPORT_TIKTOK if c in df_final.columns]
        elif is_meta:
            export_cols = [c for c in COLUNAS_EXPORT_META if c in df_final.columns]
        else:
            export_cols = [c for c in COLUNAS_EXPORT if c in df_final.columns]
        from validators import sanitize_dataframe_for_csv
        df_export = sanitize_dataframe_for_csv(df_final[export_cols])

        # Salvar como CSV
        df_export.to_csv(output_file, index=False, sep=';', encoding='utf-8-sig')

        if update_callback:
            update_callback(f"Processamento finalizado. {len(df_export)} registros salvos em '{output_file}'")

        return df_final

    except Exception as e:
        logger.error(f"Erro ao processar log de acesso: {str(e)}", exc_info=True)
        if update_callback:
            update_callback(f"Erro: {str(e)}")
        raise


def _incremental_dedup_columns(df):
    """Colunas de dedup incremental: Ip+Data e chaves de formato (Porta/Evento/User_ID/User_Agent)."""
    cols = []
    for c in ('Ip', 'Data', 'Porta', 'Evento', 'User_ID', 'User_Agent'):
        if c in df.columns:
            cols.append(c)
    return cols or list(df.columns[:1])


def _add_reputacao_column(df):
    """Adiciona coluna Reputação ao DataFrame baseada na classificação de infraestrutura."""
    required = ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']
    if not all(c in df.columns for c in required):
        return df
    if 'Reputação' in df.columns:
        return df
    df = df.copy()
    df['Reputação'] = df.apply(format_reputacao, axis=1)
    return df


def export_xlsx_colored(df, output):
    """Exporta DataFrame para Excel com cores na coluna Reputação.

    Args:
        df: DataFrame a exportar.
        output: Caminho do arquivo ou buffer BytesIO.
    """
    from openpyxl import Workbook
    from openpyxl.styles import PatternFill, Font, Alignment
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Resultado"

    # Escrever cabeçalho
    columns = list(df.columns)
    for col_idx, col_name in enumerate(columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")
        cell.alignment = Alignment(horizontal="center")

    # Mapa de cores por label de reputação
    COLOR_MAP = {
        'Proxy / VPN / Tor': 'FECACA',   # vermelho claro
        'Datacenter / VPN':  'FEE2E2',   # vermelho mais claro
        'Cloud Pública':     'FEF3C7',   # amarelo claro
        'Hospedagem':        'FFEDD5',   # laranja claro
        'Rede Móvel':        'DBEAFE',   # azul claro
        'Residencial':       'DCFCE7',   # verde claro
    }

    rep_col_idx = None
    if 'Reputação' in columns:
        rep_col_idx = columns.index('Reputação')

    # Escrever dados
    for row_idx, (_, row) in enumerate(df.iterrows(), 2):
        fill = None
        if rep_col_idx is not None:
            rep_value = str(row.iloc[rep_col_idx])
            for label, color in COLOR_MAP.items():
                if label in rep_value:
                    fill = PatternFill(start_color=color, end_color=color, fill_type="solid")
                    break

        for col_idx, value in enumerate(row, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            if fill:
                cell.fill = fill

    # Ajustar largura das colunas
    for col_idx, col_name in enumerate(columns, 1):
        max_len = len(str(col_name))
        for row_idx in range(2, min(len(df) + 2, 102)):  # amostra de até 100 linhas
            val = ws.cell(row=row_idx, column=col_idx).value
            if val is not None:
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 2, 50)

    wb.save(output)


