"""analysis.infrastructure — split from analysis monolith."""
import pandas as pd
import numpy as np
import os
import json
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
from analysis._config import DATACENTER_VPN_KEYWORDS, CLOUD_KEYWORDS

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
    is_proxy = str(row.get('Ip_Proxy', False)).lower() == 'true'
    is_hosting = str(row.get('Ip_Hospedagem', False)).lower() == 'true'
    is_mobile = str(row.get('Ip_Movel', False)).lower() == 'true'

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


def classify_dataframe(df):
    """
    Add infrastructure classification columns to a DataFrame.
    Adds: _infra_category, _infra_label, _infra_color, _infra_icon, _infra_alert
    """
    if df.empty:
        return df

    classifications = df.apply(classify_infrastructure, axis=1)
    df = df.copy()
    df['_infra_category'] = classifications.apply(lambda x: x['category'])
    df['_infra_label'] = classifications.apply(lambda x: x['label'])
    df['_infra_color'] = classifications.apply(lambda x: x['circle_color'])
    df['_infra_icon'] = classifications.apply(lambda x: x['icon'])
    df['_infra_alert'] = classifications.apply(lambda x: x['alert'])
    return df


