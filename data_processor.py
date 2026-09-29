"""Fachada pública do processamento de logs.

O código mora em `data_processing/`: `formats` (colunas e exemplos),
`parsers` (detecção e extração por plataforma), `merge` (fusão com a API),
`timezone` e `providers`. Todo nome abaixo é re-export intencional — páginas,
testes e o pipeline importam daqui; não é código morto.
"""
from datetime import datetime, timedelta  # noqa: F401  (re-export)
# Re-exports intencionais: data_processor é a fachada pública sobre o pacote
# data_processing, e outros módulos importam estes nomes a partir daqui
# (ex.: pages_app/analise/operacional.py usa periodo_matches).
from data_processing.providers import (  # noqa: F401
    PROVIDER_ALIASES,
    normalizar_provedor,
    normalizar_provedor_df,
)
from data_processing.timezone import (  # noqa: F401
    TZ_LABEL,
    TZ_OFFSET_HOURS,
    convert_utc_to_local,
    format_iso_date,
    get_periodo,
    is_diurno,
    is_noturno,
    normalizar_periodo,
    periodo_matches,
)

from data_processing.formats import (  # noqa: F401
    IP_REGEX_PATTERN,
    COLUNAS_MODELO,
    COLUNAS_EXPORT,
    COLUNAS_EXPORT_TIKTOK,
    COLUNAS_EXTRAS_PROVEDOR,
    COLUNAS_EXPORT_META,
    COLUNAS_EXPORT_PRESERVATION_GOOGLE,
    COLUNAS_EXPORT_DISCORD,
    FORMATO_1,
    FORMATO_2,
    FORMATO_3,
    FORMATO_4,
    FORMATO_DISCORD,
    FORMATO_PRESERVATION_GOOGLE,
    FORMATO_TIKTOK,
)
from data_processing.parsers import (  # noqa: F401
    parse_meta_ip_port,
    detectar_separador_csv,
    extrair_ips_do_formato_simples,
    extrair_ips_do_formato_whatsapp,
    extrair_ips_do_formato_meta,
    extrair_ips_do_formato_google,
    extrair_ips_do_formato_preservation_google,
    extrair_ips_do_formato_discord,
    extrair_ips_do_formato_tiktok,
    detectar_formato_log,
    extrair_ips_de_texto,
    extrair_ips_texto_simples,
)
from data_processing.merge import (  # noqa: F401
    processar_resultados,
)
