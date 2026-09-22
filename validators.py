"""
Log Enrichment - Módulo de Validação de Dados
Pipeline de validação em 3 camadas: Schema, Domain, Integrity.
Garante qualidade dos dados antes e depois do processamento.
"""

import pandas as pd
import logging
from ipaddress import ip_address

logger = logging.getLogger(__name__)

# ============================================================
# Coerção de tipos vinda de fontes heterogêneas
# ============================================================
# Os dados chegam de JSON da API (bool nativo), de CSV (strings '1'/'0' ou
# 'True'/'False') e de Excel pt-BR ('VERDADEIRO'/'FALSO'). O idioma antigo
# `str(x).lower() == 'true'` classificava tudo que não fosse literalmente
# 'true' como False — um proxy vindo de CSV aparecia como residencial no
# laudo. Estes helpers centralizam a conversão e tornam o caso desconhecido
# audível no log em vez de silencioso.

_TRUE_TOKENS = {'true', 't', '1', 'yes', 'y', 'sim', 's', 'verdadeiro', 'v'}
_FALSE_TOKENS = {'false', 'f', '0', 'no', 'n', 'nao', 'não', 'falso'}
# Ausentes convertidos em texto: devem respeitar o `default`, como o NaN real,
# em vez de virar False — a diferença importa quando o chamador pede default=True.
_MISSING_TOKENS = {'', 'nan', 'none', 'null', '<na>', 'nat'}
_unknown_bool_tokens = set()

DATA_FMT = '%Y-%m-%d %H:%M:%S'


def as_bool(value, default: bool = False, *, field: str = '') -> bool:
    """Converte um valor heterogêneo em bool.

    Tokens não reconhecidos retornam `default` e emitem UM aviso por token —
    numa ferramenta pericial, uma classificação errada precisa deixar rastro.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value != value:  # NaN
                return default
            return bool(value)
    except TypeError:
        pass
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass
    token = str(value).strip().lower()
    if token in _MISSING_TOKENS:
        return default
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    key = (field, token)
    if key not in _unknown_bool_tokens:
        _unknown_bool_tokens.add(key)
        logger.warning("Valor booleano não reconhecido em %s: %r — assumindo %s",
                       field or '<campo>', value, default)
    return default


def bool_series(df, col: str, default: bool = False):
    """Versão vetorizada de `as_bool` para uma coluna de DataFrame.

    Retorna uma Series booleana alinhada ao índice de `df`; colunas ausentes
    produzem uma Series constante com o valor `default`.
    """
    if df is None or col not in getattr(df, 'columns', ()):
        idx = getattr(df, 'index', None)
        return pd.Series(default, index=idx, dtype=bool) if idx is not None \
            else pd.Series([], dtype=bool)
    s = df[col]
    if pd.api.types.is_bool_dtype(s):
        return s.fillna(default).astype(bool)
    if pd.api.types.is_numeric_dtype(s):
        return s.fillna(int(default)).astype(bool)
    return s.map(lambda v: as_bool(v, default, field=col)).astype(bool)


def parse_data(series):
    """Converte a coluna de data usando o formato canônico do pipeline.

    O pipeline grava sempre '%Y-%m-%d %H:%M:%S'. `format='mixed'` cai no
    parser por elemento do dateutil e é ~50x mais lento — proibitivo em
    200k linhas. Aqui o caminho rápido cobre o caso normal e o fallback
    trata apenas os valores divergentes (arquivos importados de fora),
    registrando quantos foram.
    """
    if series is None or len(series) == 0:
        return pd.to_datetime(pd.Series([], dtype='object'), errors='coerce')
    out = pd.to_datetime(series, format=DATA_FMT, errors='coerce')
    missing = out.isna() & series.notna()
    if missing.any():
        out.loc[missing] = pd.to_datetime(series[missing], format='mixed', errors='coerce')
        logger.info("parse_data: %d de %d valores fora do formato canônico",
                    int(missing.sum()), len(series))
    return out



class ValidationResult:
    """Resultado de validação com detalhes por camada."""

    def __init__(self):
        self.errors = []      # Erros críticos
        self.warnings = []    # Avisos
        self.stats = {}       # Estatísticas de qualidade
        self.valid_count = 0
        self.invalid_count = 0
        self.total_count = 0

    @property
    def is_valid(self):
        return len(self.errors) == 0

    @property
    def quality_pct(self):
        if self.total_count == 0:
            return 0
        return round(self.valid_count / self.total_count * 100, 1)

    def add_error(self, layer, message, count=1):
        self.errors.append({'layer': layer, 'message': message, 'count': count})

    def add_warning(self, layer, message, count=1):
        self.warnings.append({'layer': layer, 'message': message, 'count': count})

    def summary(self):
        return {
            'total': self.total_count,
            'valid': self.valid_count,
            'invalid': self.invalid_count,
            'quality_pct': self.quality_pct,
            'errors': len(self.errors),
            'warnings': len(self.warnings),
        }


# ============================================================
# Layer 1: SCHEMA VALIDATION
# ============================================================

REQUIRED_COLUMNS_STANDARD = ['Ip', 'Data']
REQUIRED_COLUMNS_INTERCEPTACAO = ['Sender IP', 'Data']

EXPECTED_TYPES = {
    'Ip': 'string',
    'Data': 'string',
    'Ip_Lat': 'numeric',
    'Ip_Lon': 'numeric',
    'Ip_Movel': 'bool',
    'Ip_Proxy': 'bool',
    'Ip_Hospedagem': 'bool',
}


def validate_schema(df, mode='standard'):
    """
    Valida schema do DataFrame: colunas obrigatórias e tipos.

    Args:
        df: DataFrame a validar
        mode: 'standard' ou 'interceptacao'

    Returns:
        ValidationResult
    """
    result = ValidationResult()
    result.total_count = len(df)

    if df.empty:
        result.add_error('schema', 'DataFrame vazio')
        return result

    required = REQUIRED_COLUMNS_STANDARD if mode == 'standard' else REQUIRED_COLUMNS_INTERCEPTACAO

    # Check required columns
    missing = [col for col in required if col not in df.columns]
    if missing:
        result.add_error('schema', f'Colunas obrigatórias ausentes: {", ".join(missing)}')
        return result

    # Check types
    ip_col = 'Ip' if mode == 'standard' else 'Sender IP'
    if ip_col in df.columns:
        non_string = df[ip_col].apply(lambda x: not isinstance(x, str) and pd.notna(x)).sum()
        if non_string > 0:
            result.add_warning('schema', f'{non_string} registros com IP não-string', non_string)

    for col, expected in EXPECTED_TYPES.items():
        if col not in df.columns:
            continue
        if expected == 'numeric':
            non_numeric = pd.to_numeric(df[col], errors='coerce').isna().sum() - df[col].isna().sum()
            if non_numeric > 0:
                result.add_warning('schema', f'{col}: {non_numeric} valores não-numéricos', non_numeric)

    result.valid_count = result.total_count
    result.stats['columns_found'] = list(df.columns)
    return result


# ============================================================
# Layer 2: DOMAIN VALIDATION
# ============================================================

def _is_valid_ip_strict(ip_str):
    """Validação estrita de IP."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def validate_domain(df, mode='standard'):
    """
    Valida regras de domínio: IPs válidos, coordenadas, datas.

    Returns:
        ValidationResult com detalhes e DataFrame limpo
    """
    result = ValidationResult()
    result.total_count = len(df)

    if df.empty:
        result.valid_count = 0
        return result

    ip_col = 'Ip' if mode == 'standard' else 'Sender IP'
    valid_mask = pd.Series(True, index=df.index)

    # 1. Validate IPs — por valor distinto: geolocalização por IP tem
    # cardinalidade baixíssima (milhares de IPs para ~200k linhas).
    if ip_col in df.columns:
        serie = df[ip_col]
        unicos = serie.dropna().astype(str).str.strip().unique()
        validos = {ip for ip in unicos if _is_valid_ip_strict(ip)}
        ip_valid = serie.notna() & serie.astype(str).str.strip().isin(validos)
        invalid_ips = (~ip_valid).sum()
        if invalid_ips > 0:
            result.add_warning('domain', f'{invalid_ips} IPs inválidos detectados', invalid_ips)
            valid_mask &= ip_valid

    # 2. Validate coordinates
    for coord_col, limits in [('Ip_Lat', (-90, 90)), ('Ip_Lon', (-180, 180))]:
        if coord_col in df.columns:
            numeric = pd.to_numeric(df[coord_col], errors='coerce')
            out_of_range = ((numeric < limits[0]) | (numeric > limits[1])) & numeric.notna()
            bad_count = out_of_range.sum()
            if bad_count > 0:
                result.add_warning('domain', f'{coord_col}: {bad_count} coordenadas fora do intervalo válido', bad_count)

    # 3. Validate dates — formato canônico primeiro; 'mixed' cairia no
    # parser por elemento do dateutil (~50x mais lento em 200k linhas).
    if 'Data' in df.columns:
        dates = parse_data(df['Data'])
        invalid_dates = dates.isna().sum() - df['Data'].isna().sum()
        if invalid_dates > 0:
            result.add_warning('domain', f'{invalid_dates} datas não parseáveis', invalid_dates)

        # Future dates
        future = (dates > pd.Timestamp.now() + pd.Timedelta(days=1)) & dates.notna()
        future_count = future.sum()
        if future_count > 0:
            result.add_warning('domain', f'{future_count} datas no futuro', future_count)

    result.valid_count = valid_mask.sum()
    result.invalid_count = result.total_count - result.valid_count
    return result


# ============================================================
# Layer 3: INTEGRITY VALIDATION
# ============================================================

def validate_integrity(df, mode='standard'):
    """
    Valida integridade: duplicatas, registros órfãos, consistência.

    Returns:
        ValidationResult
    """
    result = ValidationResult()
    result.total_count = len(df)

    if df.empty:
        result.valid_count = 0
        return result

    ip_col = 'Ip' if mode == 'standard' else 'Sender IP'

    # 1. Duplicatas exatas
    if ip_col in df.columns and 'Data' in df.columns:
        dupes = df.duplicated(subset=[ip_col, 'Data'], keep=False).sum()
        if dupes > 0:
            result.add_warning('integrity', f'{dupes} registros duplicados (IP + Data)', dupes)

    # 2. IPs sem dados de enriquecimento
    if 'Ip_Dono' in df.columns:
        empty_enrichment = df['Ip_Dono'].isna() | (df['Ip_Dono'] == '')
        orphan_count = empty_enrichment.sum()
        if orphan_count > 0:
            result.add_warning('integrity', f'{orphan_count} registros sem dados de enriquecimento', orphan_count)

    # 3. Coordenadas (0,0) — geralmente erro
    if 'Ip_Lat' in df.columns and 'Ip_Lon' in df.columns:
        lat = pd.to_numeric(df['Ip_Lat'], errors='coerce')
        lon = pd.to_numeric(df['Ip_Lon'], errors='coerce')
        zero_coords = ((lat == 0) & (lon == 0) & lat.notna() & lon.notna()).sum()
        if zero_coords > 0:
            result.add_warning('integrity', f'{zero_coords} registros com coordenadas (0,0)', zero_coords)

    # 4. Consistência provedor ↔ IP (mesmo IP, provedores diferentes)
    if ip_col in df.columns and 'Ip_Dono' in df.columns:
        ip_provs = df.groupby(ip_col)['Ip_Dono'].nunique()
        inconsistent = (ip_provs > 1).sum()
        if inconsistent > 0:
            result.add_warning('integrity', f'{inconsistent} IPs com provedores inconsistentes', inconsistent)

    result.valid_count = result.total_count - result.invalid_count
    return result


# ============================================================
# FULL PIPELINE
# ============================================================

def validate_dataframe(df, mode='standard'):
    """
    Executa pipeline completo de validação (3 camadas).

    Returns:
        dict com resultados por camada e resumo geral.
    """
    schema_result = validate_schema(df, mode)
    domain_result = validate_domain(df, mode)
    integrity_result = validate_integrity(df, mode)

    total_errors = len(schema_result.errors) + len(domain_result.errors) + len(integrity_result.errors)
    total_warnings = len(schema_result.warnings) + len(domain_result.warnings) + len(integrity_result.warnings)

    return {
        'schema': schema_result,
        'domain': domain_result,
        'integrity': integrity_result,
        'total_errors': total_errors,
        'total_warnings': total_warnings,
        'is_valid': schema_result.is_valid and domain_result.is_valid,
        'quality_pct': domain_result.quality_pct,
    }


def sanitize_csv_value(value):
    """
    Sanitiza valor para exportação CSV/Excel, prevenindo fórmula injetada.
    Prefixos perigosos: =, +, -, @, |, \\t, \\r, \\n

    O caso do `-` é o delicado: `-38.5044` é uma longitude legítima e não pode
    ganhar aspa, mas `-2+3` é uma fórmula que a planilha avalia — e
    `-2+3+cmd|' /C calc'!A0` é o bypass clássico da regra ingênua de "traço
    seguido de dígito é número". O critério aqui é ser um número por inteiro:
    se `float()` aceita a string toda, é dado; qualquer outra coisa é escapada.
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in ('=', '+', '@', '|', '\t', '\r', '\n'):
        return f"'{value}"
    if value[0] == '-':
        try:
            float(value)
        except ValueError:
            return f"'{value}"
    return value


def sanitize_dataframe_for_csv(df):
    """Aplica sanitize_csv_value a todas as colunas object/string de um DataFrame.

    O DataFrame de entrada nunca é modificado. A cópia é **preguiçosa**: só
    nasce quando alguma célula realmente precisa ser escapada, e copia apenas
    as colunas afetadas. Num caso real de 202 mil linhas a cópia incondicional
    custava ~50 MB de pico — pagos duas vezes no pipeline, já que o CSV
    sanitiza o frame e o export do Excel sanitiza de novo. Com a cópia
    preguiçosa a segunda passagem, que por idempotência não muda nada, sai de
    graça.
    """
    import pandas as pd

    if df is None or getattr(df, 'empty', True):
        return df

    # Pré-filtro vetorizado: só as células realmente perigosas passam pelo
    # sanitizador Python. Em 200k linhas isso troca N*M chamadas por M regex.
    # `^-` sem restrição: quem decide se um valor com traço é número ou fórmula
    # é o `sanitize_csv_value`. Um pré-filtro mais estreito deixaria passar
    # `-2+3` e faria o caminho vetorizado divergir do por célula.
    dangerous = r'^[=+@|\t\r\n]|^-'

    out = None
    for col in df.columns:
        if not (pd.api.types.is_object_dtype(df[col])
                or pd.api.types.is_string_dtype(df[col])):
            continue
        serie = df[col]
        mask = serie.astype('string').str.match(dangerous, na=False)
        if not mask.any():
            continue
        suspeitos = serie[mask]
        escapados = suspeitos.map(
            lambda v: sanitize_csv_value(v) if isinstance(v, str) else v
        )
        # O pré-filtro é deliberadamente largo — `^-` pega toda longitude
        # negativa em coluna de texto. Só quem de fato mudou justifica a cópia.
        if escapados.equals(suspeitos):
            continue
        if out is None:
            out = df.copy(deep=False)
        # Coluna nova e exclusiva: escrever em `serie` alcançaria o frame do
        # chamador, que compartilha os mesmos blocos com a cópia rasa.
        limpa = serie.copy()
        limpa.loc[mask] = escapados
        out[col] = limpa
    return df if out is None else out


def safe_output_path(user_path, default_name='resultado_logs.csv', base_dir=None):
    """
    Restringe path de saída ao diretório base (default: output/csv sob o projeto).
    Previne path traversal e escrita fora do sandbox.
    """
    import os
    from pathlib import Path

    project_root = Path(__file__).resolve().parent
    if base_dir is None:
        base = project_root / 'output' / 'csv'
    else:
        base = Path(base_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)

    raw = (user_path or '').strip() or default_name
    # Usar apenas o basename se houver traversal ou path absoluto suspeito
    candidate = Path(raw)
    name = candidate.name if candidate.name else default_name
    if not name.lower().endswith(('.csv', '.xlsx', '.xls', '.json', '.html', '.zip')):
        name = os.path.splitext(name)[0] + '.csv'

    resolved = (base / name).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError:
        resolved = (base / default_name).resolve()
    return str(resolved)


