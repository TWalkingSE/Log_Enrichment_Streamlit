"""Google: relatório "IP ACTIVITY", CSV do Preservation (Takeout) e os dois
CSVs "Aggregated Activities" (serviços acessados e conexões entre
identificadores)."""

import csv
import io
import logging
import re
from collections import Counter
from datetime import datetime

import pandas as pd

from api_client import is_valid_ip
from data_processing.formats import COLUNAS_EXTRAS_PROVEDOR, COLUNAS_MODELO
from data_processing.timezone import (
    TZ_LABEL,
    convert_utc_to_local,
    format_iso_date,
    get_periodo,
)
from validators import as_bool

logger = logging.getLogger(__name__)


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
                periodo = None
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
            if as_bool(row.get('Is Non-routable IP Address'), field='Is Non-routable IP Address'):
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


# ---------------------------------------------------------------------------
# Google "Aggregated Activities"
# ---------------------------------------------------------------------------
#
# Dois CSVs do mesmo pacote, cada um parseado sozinho e com resultado próprio:
#
# - serviços ("An aggregated representation of the Google services accessed by
#   your device"): uma linha por identificador, com primeiro e último uso e a
#   contagem `Days Active`;
# - conexões ("connections between identifiers seen together in authenticated
#   sessions"): uma linha por PAR de identificadores vistos juntos, com a
#   janela daquele par. O IP aparece em qualquer um dos lados.
#
# Só as linhas de IP entram. As demais (User agent, Product, fingerprints,
# pares sem IP) são contadas e declaradas em `df.attrs['google_agregado']`.

COLUNAS_GOOGLE_ATIVIDADES = (
    'GAIA ID', 'Last Activity Timestamp', 'First Activity Timestamp',
    'Days Active', 'Identifier Type', 'ID',
)
COLUNAS_GOOGLE_CONEXOES = (
    'GAIA ID', 'Last Connection Timestamp', 'First Connection Timestamp',
    'Identifier Type 1', 'ID 1', 'Identifier Type 2', 'ID 2',
)
_TIPO_IP = 'ip address'
_FMT_GOOGLE = '%Y-%m-%d %H:%M:%S'


def _primeira_linha(texto):
    """Primeira linha não vazia (sem BOM), sem varrer o texto inteiro."""
    for linha in io.StringIO(texto):
        linha = linha.lstrip('﻿').strip()
        if linha:
            return linha
    return ''


def _separador(linha):
    """`;` (CSV regravado pelo Excel pt-BR) ou `,` (como o Google entrega)."""
    return ';' if linha.count(';') > linha.count(',') else ','


def cabecalho_csv(content):
    """Colunas da primeira linha não vazia de um texto CSV (`,` ou `;`)."""
    linha = _primeira_linha(content)
    if not linha:
        return []
    return [c.strip() for c in next(csv.reader([linha], delimiter=_separador(linha)))]


def formato_google_agregado(colunas):
    """'google_atividades', 'google_conexoes' ou None, pelo conjunto de colunas.

    Por conjunto, não por substring: 'Activity Timestamp' (Preservation) está
    contido em 'Last Activity Timestamp'.
    """
    nomes = {str(c).lstrip('﻿').strip() for c in colunas}
    if nomes.issuperset(COLUNAS_GOOGLE_CONEXOES):
        return 'google_conexoes'
    if nomes.issuperset(COLUNAS_GOOGLE_ATIVIDADES):
        return 'google_atividades'
    return None


def _ler_csv_agregado(content_or_df):
    """(DataFrame só de texto, linhas malformadas descartadas).

    `dtype=str`: o GAIA ID chega a 21 dígitos e estoura o int64 do pandas.
    Linha com campos demais não some em silêncio — é contada e declarada.
    """
    if isinstance(content_or_df, pd.DataFrame):
        df = content_or_df.copy()
        df.columns = [str(c).lstrip('﻿').strip() for c in df.columns]
        return df.astype(object).where(df.notna(), '').astype(str), 0

    texto = str(content_or_df).lstrip('﻿')
    malformadas: list = []
    df = pd.read_csv(io.StringIO(texto), sep=_separador(_primeira_linha(texto)),
                     dtype=str, keep_default_na=False, engine='python',
                     on_bad_lines=malformadas.append)
    df.columns = [str(c).strip() for c in df.columns]
    return df.fillna(''), len(malformadas)


def _coluna(df, nome):
    """Coluna aparada, ou vazia quando o export não a trouxer."""
    if nome in df.columns:
        return df[nome].str.strip()
    return pd.Series('', index=df.index, dtype=object)


def _instantes(serie):
    """(UTC, local, texto local) de uma coluna `YYYY-MM-DD HH:MM:SS UTC`.

    Formato explícito, nunca inferido. Valor não interpretável fica como veio
    do documento, sem conversão — nada é inventado.
    """
    bruto = serie.str.strip()
    utc = pd.to_datetime(bruto.str.replace(r'\s*UTC$', '', regex=True),
                         format=_FMT_GOOGLE, errors='coerce')
    local = convert_utc_to_local(utc)
    texto = local.dt.strftime(_FMT_GOOGLE).where(utc.notna(), bruto)
    return utc, local, texto.replace({'': None})


def _dias_corridos_utc(primeiro_utc, ultimo_utc):
    """Último − primeiro + 1, em dias de calendário UTC.

    UTC porque é a base em que o Google conta `Days Active`: no caso real que
    motivou este parser, só 2 de 882 linhas ficam com `Days Active` maior que
    os dias corridos contados em UTC, contra 13 em GMT-3. Contar no fuso local
    criaria entre as duas colunas contradições que o documento não tem.
    Intervalo invertido (último antes do primeiro) fica vazio.
    """
    dias = (ultimo_utc.dt.normalize() - primeiro_utc.dt.normalize()).dt.days + 1
    return dias.where(dias >= 1)


def _inteiros(serie):
    """Inteiros Python (ou None) numa coluna object.

    `Int64` com <NA> quebra o `append` do openpyxl no export do Excel.
    """
    return pd.Series([int(v) if pd.notna(v) else None for v in serie],
                     index=serie.index, dtype=object)


def _alvo_ou_gaia(alvo, gaia):
    """Sem alvo informado, o GAIA ID identifica a conta (como o e-mail no Discord)."""
    if alvo != 'desconhecido':
        return pd.Series(alvo, index=gaia.index, dtype=object)
    gaia = gaia.str.strip()
    return gaia.where(gaia.ne(''), 'desconhecido')


def _completar_modelo(out, ultimo_local, data_ok):
    """Completa as colunas do modelo e põe as extras logo após `Ip`."""
    out['Data_Fuso'] = pd.Series(TZ_LABEL, index=out.index, dtype=object).where(data_ok, None)
    out['Periodo'] = None
    out['ISO_Date'] = None
    if data_ok.any():
        out.loc[data_ok, 'Periodo'] = ultimo_local[data_ok].dt.hour.map(get_periodo)
        out.loc[data_ok, 'ISO_Date'] = ultimo_local[data_ok].map(
            lambda dt: format_iso_date(dt.to_pydatetime()))
    for col in ('Ip_Dono', 'Ip_AS', 'Ip_Regiao', 'Ip_Cidade', 'Ip_Pais',
                'Ip_Pais_Codigo', 'Ip_Lat', 'Ip_Lon'):
        out[col] = None
    for col in ('Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Tor'):
        out[col] = False
    colunas = list(COLUNAS_MODELO)
    pos = colunas.index('Ip') + 1
    colunas[pos:pos] = [c for c in COLUNAS_EXTRAS_PROVEDOR if c in out.columns]
    return out[colunas].reset_index(drop=True)


_RESUMO_TEXTOS = (
    ('ips_invalidos', 'linhas de IP com endereço inválido descartadas'),
    ('linhas_malformadas', 'linhas malformadas descartadas'),
    ('datas_invalidas', 'datas não interpretáveis mantidas como no original'),
    ('datas_invertidas', 'intervalos com último uso antes do primeiro (dias corridos vazios)'),
    ('dias_ativos_acima_do_periodo',
     'IPs com Dias ativos (Google) maior que os dias corridos — valor do Google preservado'),
)


def _declarar_resumo(resumo, rotulo, update_callback):
    """Leva ao log de processamento o que foi importado e o que ficou de fora."""
    partes = [f"{resumo['importadas']} registros de IP importados de {resumo['linhas']} linhas"]
    if resumo['sem_ip']:
        detalhe = ', '.join(f'{tipo}: {n}' for tipo, n in resumo.get('ignoradas_por_tipo', {}).items())
        partes.append(f"{resumo['sem_ip']} linhas sem IP não importadas"
                      + (f' ({detalhe})' if detalhe else ''))
    for chave, texto in _RESUMO_TEXTOS:
        if resumo.get(chave):
            partes.append(f'{resumo[chave]} {texto}')
            logger.warning('%s: %d %s', rotulo, resumo[chave], texto)
    if update_callback:
        update_callback(f'{rotulo}: ' + '; '.join(partes))


def extrair_ips_do_formato_google_atividades(content_or_df, update_callback=None, alvo='desconhecido'):
    """Extrai os IPs do CSV "Aggregated Activities" de serviços do Google.

    Uma linha por IP, como no arquivo, com:
    - `Primeiro_Uso` / `Ultimo_Uso`: no fuso local, como as demais datas;
    - `Data`: o último uso (é a coluna que as análises leem);
    - `Dias_Ativos_Google`: o `Days Active` exatamente como veio. O Google
      não diz QUAIS dias foram, e nada aqui afirma isso;
    - `Dias_Corridos`: último − primeiro + 1, em dias UTC (ver
      `_dias_corridos_utc`);
    - `Canal_Autenticacao` e `Multilogin`, crus.

    Args:
        content_or_df: texto CSV, ou DataFrame lido com `dtype=str`
        update_callback: Função para atualizar status
        alvo: Identificador do alvo; sem ele, o GAIA ID

    Returns:
        DataFrame no modelo, com o resumo em `df.attrs['google_agregado']`
    """
    rotulo = 'Google Aggregated Activities (serviços)'
    if update_callback:
        update_callback(f'Processando {rotulo}...')
    try:
        bruto, malformadas = _ler_csv_agregado(content_or_df)
    except (pd.errors.ParserError, UnicodeError, TypeError, ValueError) as e:
        logger.warning('Erro ao ler CSV %s: %s', rotulo, e)
        return pd.DataFrame(columns=COLUNAS_MODELO)
    if formato_google_agregado(bruto.columns) != 'google_atividades':
        logger.warning('Colunas obrigatórias não encontradas: %s', COLUNAS_GOOGLE_ATIVIDADES)
        return pd.DataFrame(columns=COLUNAS_MODELO)

    tipo = bruto['Identifier Type'].str.strip()
    eh_ip = tipo.str.lower().eq(_TIPO_IP)
    ip = bruto.loc[eh_ip, 'ID'].str.strip()
    valido = ip.map(is_valid_ip).astype(bool)
    sel = bruto.loc[valido[valido].index]

    pri_utc, _, pri_txt = _instantes(sel['First Activity Timestamp'])
    ult_utc, ult_local, ult_txt = _instantes(sel['Last Activity Timestamp'])
    corridos = _dias_corridos_utc(pri_utc, ult_utc)
    ativos = pd.to_numeric(sel['Days Active'].str.strip(), errors='coerce')

    out = pd.DataFrame({
        'Alvo': _alvo_ou_gaia(alvo, sel['GAIA ID']),
        'Ip': ip[valido],
        'Primeiro_Uso': pri_txt,
        'Ultimo_Uso': ult_txt,
        'Dias_Ativos_Google': _inteiros(ativos),
        'Dias_Corridos': _inteiros(corridos),
        'Canal_Autenticacao': _coluna(sel, 'Authentication Channel'),
        'Multilogin': _coluna(sel, 'Multilogin Used'),
        'Data': ult_txt,
    }, index=sel.index)
    out = _completar_modelo(out, ult_local, ult_utc.notna())

    datas_ok = pri_utc.notna() & ult_utc.notna()
    resumo = {
        'formato': 'google_atividades',
        'linhas': len(bruto),
        'importadas': len(out),
        'sem_ip': int((~eh_ip).sum()),
        'ignoradas_por_tipo': dict(Counter(tipo[~eh_ip].replace('', '(vazio)')).most_common()),
        'ips_invalidos': int((~valido).sum()),
        'linhas_malformadas': malformadas,
        'datas_invalidas': int((~datas_ok).sum()),
        'datas_invertidas': int((datas_ok & corridos.isna()).sum()),
        'dias_ativos_acima_do_periodo': int((ativos > corridos).sum()),
    }
    out.attrs['google_agregado'] = resumo
    _declarar_resumo(resumo, rotulo, update_callback)
    return out


def extrair_ips_do_formato_google_conexoes(content_or_df, update_callback=None, alvo='desconhecido'):
    """Extrai os IPs do CSV "Aggregated Activities" de conexões do Google.

    Uma linha por par IP ↔ identificador, como no arquivo — o mesmo IP se
    repete, uma vez por identificador visto junto com ele. Cada linha traz:
    - `Vinculado_Tipo` / `Vinculado_Valor`: o outro lado do par, cru. O valor
      do SID cookie é um timestamp, mas funciona como identificador da sessão
      e por isso mantém o `UTC` literal;
    - `Primeiro_Uso` / `Ultimo_Uso` do par, no fuso local; `Data` = último;
    - `Dias_Corridos` do par, em dias UTC.

    Par com IP dos dois lados (não visto em casos reais) vira duas linhas, uma
    para cada IP. Pares sem IP são contados e ficam de fora.

    Returns:
        DataFrame no modelo, com o resumo em `df.attrs['google_agregado']`
    """
    rotulo = 'Google Aggregated Activities (conexões)'
    if update_callback:
        update_callback(f'Processando {rotulo}...')
    try:
        bruto, malformadas = _ler_csv_agregado(content_or_df)
    except (pd.errors.ParserError, UnicodeError, TypeError, ValueError) as e:
        logger.warning('Erro ao ler CSV %s: %s', rotulo, e)
        return pd.DataFrame(columns=COLUNAS_MODELO)
    if formato_google_agregado(bruto.columns) != 'google_conexoes':
        logger.warning('Colunas obrigatórias não encontradas: %s', COLUNAS_GOOGLE_CONEXOES)
        return pd.DataFrame(columns=COLUNAS_MODELO)

    tipo1 = bruto['Identifier Type 1'].str.strip()
    tipo2 = bruto['Identifier Type 2'].str.strip()
    ip1 = tipo1.str.lower().eq(_TIPO_IP)
    ip2 = tipo2.str.lower().eq(_TIPO_IP)
    lado1 = pd.DataFrame({'Ip': bruto['ID 1'].str.strip(), 'Vinculado_Tipo': tipo2,
                          'Vinculado_Valor': bruto['ID 2'].str.strip()})[ip1]
    lado2 = pd.DataFrame({'Ip': bruto['ID 2'].str.strip(), 'Vinculado_Tipo': tipo1,
                          'Vinculado_Valor': bruto['ID 1'].str.strip()})[ip2]
    # Ordem do arquivo; num par com IP dos dois lados, o lado 1 primeiro.
    pares = pd.concat([lado1, lado2]).sort_index(kind='stable')
    valido = pares['Ip'].map(is_valid_ip).astype(bool)
    pares = pares[valido]
    # Índice posicional: o par com IP dos dois lados repete o rótulo da linha.
    sel = bruto.loc[pares.index].reset_index(drop=True)
    pares = pares.reset_index(drop=True)

    pri_utc, _, pri_txt = _instantes(sel['First Connection Timestamp'])
    ult_utc, ult_local, ult_txt = _instantes(sel['Last Connection Timestamp'])
    corridos = _dias_corridos_utc(pri_utc, ult_utc)

    out = pd.DataFrame({
        'Alvo': _alvo_ou_gaia(alvo, sel['GAIA ID']),
        'Ip': pares['Ip'],
        'Vinculado_Tipo': pares['Vinculado_Tipo'],
        'Vinculado_Valor': pares['Vinculado_Valor'],
        'Primeiro_Uso': pri_txt,
        'Ultimo_Uso': ult_txt,
        'Dias_Corridos': _inteiros(corridos),
        'Data': ult_txt,
    })
    out = _completar_modelo(out, ult_local, ult_utc.notna())

    datas_ok = pri_utc.notna() & ult_utc.notna()
    resumo = {
        'formato': 'google_conexoes',
        'linhas': len(bruto),
        'importadas': len(out),
        'sem_ip': int((~(ip1 | ip2)).sum()),
        'ips_invalidos': int((~valido).sum()),
        'linhas_malformadas': malformadas,
        'datas_invalidas': int((~datas_ok).sum()),
        'datas_invertidas': int((datas_ok & corridos.isna()).sum()),
    }
    out.attrs['google_agregado'] = resumo
    _declarar_resumo(resumo, rotulo, update_callback)
    return out
