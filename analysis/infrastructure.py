"""analysis.infrastructure — split from analysis monolith."""
import logging

logger = logging.getLogger(__name__)
from analysis._config import DATACENTER_VPN_KEYWORDS, CLOUD_KEYWORDS
from validators import as_bool

def classify_infrastructure(row):
    """
    Classify an IP's infrastructure type based on ASN and provider name.

    Returns dict with:
        - category: 'datacenter_vpn' | 'cloud' | 'hosting' | 'proxy' | 'mobile' | 'normal'
        - label: Human-readable label
        - color: Hex color for map visualization
        - icon: Emoji icon
        - alert: Whether to show alert
    """
    is_proxy = as_bool(row.get('Ip_Proxy'), field='Ip_Proxy')
    is_hosting = as_bool(row.get('Ip_Hospedagem'), field='Ip_Hospedagem')
    is_mobile = as_bool(row.get('Ip_Movel'), field='Ip_Movel')

    asn = str(row.get('Ip_AS', '')).lower()
    provider = str(row.get('Ip_Dono', '')).lower()
    combined = f"{asn} {provider}"

    # 1. Proxy/VPN flag from API takes priority
    if is_proxy:
        return {
            'category': 'proxy',
            'label': 'Proxy / VPN / Tor',
            'color': '#dc2626',
            'circle_color': '#ef4444',
            'icon': '🛡️',
            'alert': True,
        }

    # 2. Check datacenter/VPN keywords in ASN or provider
    for kw in DATACENTER_VPN_KEYWORDS:
        if kw in combined:
            return {
                'category': 'datacenter_vpn',
                'label': 'Datacenter / VPN',
                'color': '#b91c1c',
                'circle_color': '#f87171',
                'icon': '🏢',
                'alert': True,
            }

    # 3. Check cloud provider keywords
    for kw in CLOUD_KEYWORDS:
        if kw in combined:
            return {
                'category': 'cloud',
                'label': 'Cloud Pública',
                'color': '#d97706',
                'circle_color': '#f59e0b',
                'icon': '☁️',
                'alert': False,
            }

    # 4. Hosting flag from API (not matched above)
    if is_hosting:
        return {
            'category': 'hosting',
            'label': 'Hospedagem',
            'color': '#c2410c',
            'circle_color': '#f97316',
            'icon': '🖥️',
            'alert': False,
        }

    # 5. Mobile
    if is_mobile:
        return {
            'category': 'mobile',
            'label': 'Rede Móvel',
            'color': '#2563eb',
            'circle_color': '#3b82f6',
            'icon': '📱',
            'alert': False,
        }

    # 6. Residencial / Normal
    return {
        'category': 'normal',
        'label': 'Residencial',
        'color': '#16a34a',
        'circle_color': '#22c55e',
        'icon': '🏠',
        'alert': False,
    }


def format_reputacao(row):
    """Return a formatted infrastructure label for display and export."""
    classification = classify_infrastructure(row)
    return f"{classification['icon']} {classification['label']}"


# Colunas de que `classify_infrastructure` depende. A classificação é função
# apenas destas — logo, combinações repetidas produzem o mesmo resultado.
_CLASSIFY_KEYS = ('Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_AS', 'Ip_Dono')

_INFRA_COLUMNS = (
    ('_infra_category', 'category'),
    ('_infra_label', 'label'),
    ('_infra_color', 'circle_color'),
    ('_infra_icon', 'icon'),
    ('_infra_alert', 'alert'),
)


def classify_dataframe(df):
    """
    Add infrastructure classification columns to a DataFrame.
    Adds: _infra_category, _infra_label, _infra_color, _infra_icon, _infra_alert

    Classifica apenas as combinações DISTINTAS das colunas de que a
    classificação depende e mapeia o resultado de volta. A versão anterior
    fazia seis passadas Python sobre o frame inteiro (um `apply(axis=1)`
    produzindo um dict por linha, mais cinco `.apply` sobre essa Series) —
    em 200k linhas isso rodava por inteiro a cada rerun da página do mapa.
    """
    if df.empty:
        return df

    presentes = [c for c in _CLASSIFY_KEYS if c in df.columns]
    df = df.copy()

    if not presentes:
        # Sem nenhuma coluna de entrada, todas as linhas caem no mesmo caso.
        unica = classify_infrastructure({})
        for coluna, campo in _INFRA_COLUMNS:
            df[coluna] = unica[campo]
        return df

    chaves = df[presentes]
    rotulos = {
        valores: classify_infrastructure(dict(zip(presentes, valores)))
        for valores in chaves.drop_duplicates().itertuples(index=False, name=None)
    }
    linhas = list(chaves.itertuples(index=False, name=None))
    for coluna, campo in _INFRA_COLUMNS:
        df[coluna] = [rotulos[v][campo] for v in linhas]
    return df


def add_reputacao_column(df):
    """Adiciona a coluna 'Reputação' a partir da classificação de infraestrutura.

    Implementação única compartilhada pelos dois pipelines (logs de acesso e
    interceptação), que antes tinham cópias separadas e idênticas.

    Classifica apenas as combinações distintas das colunas de entrada: o
    `apply(format_reputacao, axis=1)` anterior fazia uma chamada Python por
    linha, e um caso real tem ~200k linhas para algumas dezenas de combinações.
    """
    required = ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']
    if df is None or not all(c in df.columns for c in required):
        return df
    if 'Reputação' in df.columns:
        return df
    if df.empty:
        df = df.copy()
        df['Reputação'] = []
        return df

    presentes = [c for c in _CLASSIFY_KEYS if c in df.columns]
    chaves = df[presentes]
    rotulos = {
        valores: format_reputacao(dict(zip(presentes, valores)))
        for valores in chaves.drop_duplicates().itertuples(index=False, name=None)
    }
    df = df.copy()
    df['Reputação'] = [rotulos[v] for v in chaves.itertuples(index=False, name=None)]
    return df
