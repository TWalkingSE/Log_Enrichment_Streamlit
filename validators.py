"""
Log Enrichment - Módulo de Validação de Dados
Pipeline de validação em 3 camadas: Schema, Domain, Integrity.
Garante qualidade dos dados antes e depois do processamento.
"""

import pandas as pd
import logging
from ipaddress import ip_address

logger = logging.getLogger(__name__)


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

    # 1. Validate IPs
    if ip_col in df.columns:
        ip_valid = df[ip_col].apply(lambda x: _is_valid_ip_strict(str(x)) if pd.notna(x) else False)
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

    # 3. Validate dates
    if 'Data' in df.columns:
        dates = pd.to_datetime(df['Data'], errors='coerce')
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
    Sanitiza valor para exportação CSV, prevenindo CSV injection.
    Prefixos perigosos: =, +, -, @, |, \\t, \\r, \\n
    """
    if not isinstance(value, str):
        return value
    if value and value[0] in ('=', '+', '@', '|', '\t', '\r', '\n'):
        return f"'{value}"
    if value and value[0] == '-' and (len(value) == 1 or not value[1].isdigit()):
        return f"'{value}"
    return value


