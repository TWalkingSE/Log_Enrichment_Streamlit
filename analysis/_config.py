"""Shared config loaders and keyword lists for analysis package."""
import os
import json
import logging

logger = logging.getLogger(__name__)

_CONFIG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _load_json_config(filename, default=None):
    """Carrega configuração JSON externa com fallback."""
    filepath = os.path.join(_CONFIG_DIR, filename)
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Erro ao carregar {filename}: {e}")
    return default or {}

_providers_config = _load_json_config('infrastructure_providers.json')
_analysis_config = _load_json_config('analysis_config.json')


# ============================================================
# 24. INFRASTRUCTURE CLASSIFICATION (Datacenter/VPN vs Cloud vs Normal)
# ============================================================

# Carrega keywords de arquivo externo (editável sem alterar código)
DATACENTER_VPN_KEYWORDS = _providers_config.get('datacenter_vpn_keywords', [
    'datacamp', 'hostroyal', 'ovh', 'hetzner', 'leaseweb', 'digitalocean',
    'linode', 'vultr', 'choopa', 'm247', 'worldstream', 'contabo',
    'scaleway', 'servers.com', 'cherry servers', 'alexhost', 'hostdime',
    'iqweb', 'iq pl', 'gthost', 'hostzealot', 'cdn77',
    'mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
    'privadovpn', 'protonvpn', 'ipvanish', 'hidemyass', 'pia ',
    'private internet access', 'torguard', 'windscribe',
    'psychz', 'quadranet', 'colocrossing', 'buyvm', 'ramnode',
    'hostwinds', 'hostkey', 'blazingfast', 'sharktech', 'reliablesite',
    'nocix', 'combahton', 'flokinet', '1gservers', 'serverius',
    'xserver', 'vpn', 'proxy', 'tor exit', 'tor relay',
    'tzulo', 'frantech', 'privatelayer', 'incloudzone',
    'ponynet', 'emerald onion', 'calyx institute',
    'path.net', 'arelion', 'zayo', 'he.net', 'hurricane electric',
])

CLOUD_KEYWORDS = _providers_config.get('cloud_keywords', [
    'amazon', 'aws', 'ec2', 'cloudfront', 'amazonaws',
    'google cloud', 'google llc', 'gcp',
    'microsoft azure', 'microsoft corporation',
    'alibaba cloud', 'alicloud', 'aliyun',
    'oracle cloud', 'oracle corporation',
    'tencent cloud', 'tencent',
    'ibm cloud', 'softlayer',
    'rackspace', 'cloudflare', 'fastly', 'akamai',
    'heroku', 'vercel', 'netlify', 'railway',
    'huawei cloud',
])

_vpn_config = _analysis_config.get('vpn_detection', {})

