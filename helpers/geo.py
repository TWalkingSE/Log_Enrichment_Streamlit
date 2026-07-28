"""
Log Enrichment - Geographic Helper Functions
Haversine distance, popup builders for map page.
"""

import math
from html import escape as _html_escape

from analysis import classify_infrastructure


def _esc(val):
    """Escape untrusted values for HTML popups."""
    if val is None:
        return 'N/A'
    return _html_escape(str(val), quote=True)


def haversine_km(lat1, lon1, lat2, lon2):
    """Calcula distância em km entre dois pontos usando fórmula de Haversine"""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def build_rich_popup(row, ip_counts=None):
    """Cria popup HTML rico com classificação de infraestrutura"""
    ip = _esc(row.get('Ip', 'N/A'))
    raw_ip = row.get('Ip', 'N/A')
    count = ip_counts.get(raw_ip, 1) if ip_counts else 1

    infra = classify_infrastructure(row)
    cat = infra['category']

    pais = row.get('Ip_Pais', '')
    pais_code = row.get('Ip_Pais_Codigo', '')
    if pais and pais_code:
        pais_display = f"{_esc(pais)} ({_esc(pais_code)})"
    else:
        pais_display = _esc(pais) if pais else 'N/A'

    header_colors = {
        'proxy': '#7f1d1d', 'datacenter_vpn': '#7f1d1d',
        'cloud': '#78350f', 'hosting': '#7c2d12',
        'mobile': '#1e3a5f', 'normal': '#1e1e2e',
    }
    header_bg = header_colors.get(cat, '#1e1e2e')
    badge_bg = _esc(infra['circle_color'])
    icon = _esc(infra['icon'])
    label = _esc(infra['label'])

    alert_banner = ""
    if cat == 'proxy':
        alert_banner = """
            <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:4px;padding:6px 10px;margin-bottom:6px;">
                <b style="color:#dc2626;">&#x26A0; PROXY / VPN / TOR</b><br>
                <span style="color:#991b1b;font-size:11px;">A localização exibida pode não corresponder à real.</span>
            </div>"""
    elif cat == 'datacenter_vpn':
        alert_banner = """
            <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:4px;padding:6px 10px;margin-bottom:6px;">
                <b style="color:#b91c1c;">&#x26A0; DATACENTER / VPN</b><br>
                <span style="color:#991b1b;font-size:11px;">ASN associado a infraestrutura de datacenter usada por VPNs. Localização pode ser do servidor, não do usuário.</span>
            </div>"""
    elif cat == 'cloud':
        alert_banner = """
            <div style="background:#fffbeb;border:1px solid #fcd34d;border-radius:4px;padding:6px 10px;margin-bottom:6px;">
                <b style="color:#92400e;">&#x2601; CLOUD PÚBLICA</b><br>
                <span style="color:#78350f;font-size:11px;">IP pertence a provedor de cloud pública. Pode ser aplicação, bot ou infraestrutura.</span>
            </div>"""

    type_label = f'<span style="color:{badge_bg};font-weight:bold;">{icon} {label}</span>'
    lat = _esc(row.get('Ip_Lat', '0'))
    lon = _esc(row.get('Ip_Lon', '0'))

    return f"""
    <div style="font-family:'Segoe UI',Arial,sans-serif;font-size:12px;min-width:290px;line-height:1.5;">
        <div style="background:{header_bg};color:white;padding:8px 12px;border-radius:6px 6px 0 0;margin:-1px;">
            <b style="font-size:14px;">{icon} {ip}</b>
            <span style="float:right;background:{badge_bg};color:white;padding:1px 8px;border-radius:10px;font-size:11px;">{count}x</span>
        </div>
        <div style="padding:8px 12px;background:#f8fafc;border-radius:0 0 6px 6px;">
            {alert_banner}
            <b>Provedor:</b> {_esc(row.get('Ip_Dono', 'N/A'))}<br>
            <b>AS:</b> {_esc(row.get('Ip_AS', 'N/A'))}<br>
            <b>País:</b> {pais_display}<br>
            <b>Região:</b> {_esc(row.get('Ip_Regiao', 'N/A'))}<br>
            <b>Cidade:</b> {_esc(row.get('Ip_Cidade', 'N/A'))}<br>
            <b>Data:</b> {_esc(row.get('Data', 'N/A'))}<br>
            <b>Período:</b> {_esc(row.get('Periodo', 'N/A'))}<br>
            <b>Classificação:</b> {type_label}<br>
            <div style="margin-top:6px;padding-top:6px;border-top:1px solid #e2e8f0;">
                <a href="https://www.google.com/maps/@{lat},{lon},15z" target="_blank" rel="noopener noreferrer" style="color:#3b82f6;text-decoration:none;font-size:11px;">&#x1F4CD; Google Maps</a>
                &nbsp;|&nbsp;
                <a href="https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}" target="_blank" rel="noopener noreferrer" style="color:#22c55e;text-decoration:none;font-size:11px;">&#x1F441; Street View</a>
            </div>
        </div>
    </div>"""


def build_cluster_popup(rows, ip_counts=None):
    """Cria popup HTML para cluster de IPs"""
    cidade = _esc(rows[0].get('Ip_Cidade', 'N/A'))
    regiao = _esc(rows[0].get('Ip_Regiao', 'N/A'))
    pais = rows[0].get('Ip_Pais', '')

    ips_html = ""
    for row in rows[:15]:
        raw_ip = row.get('Ip', 'N/A')
        ip = _esc(raw_ip)
        count = ip_counts.get(raw_ip, 1) if ip_counts else 1
        tipo = '&#x1F6E1;' if row.get('Ip_Proxy', False) else ('&#x1F5A5;' if row.get('Ip_Hospedagem', False) else ('&#x1F4F1;' if row.get('Ip_Movel', False) else ''))
        dono = _esc(str(row.get('Ip_Dono', ''))[:25])
        ips_html += f'<tr><td style="padding:2px 6px;font-size:11px;">{ip}</td><td style="padding:2px 6px;font-size:11px;">{dono}</td><td style="padding:2px 4px;font-size:11px;text-align:center;">{count}</td><td style="padding:2px 4px;font-size:11px;">{tipo}</td></tr>'

    extra = f"<div style='padding:4px 6px;font-size:10px;color:#64748b;'>... e mais {len(rows)-15}</div>" if len(rows) > 15 else ""
    loc_label = f"{cidade}, {regiao}" + (f" - {_esc(pais)}" if pais else "")

    return f"""
    <div style="font-family:'Segoe UI',Arial,sans-serif;font-size:12px;min-width:380px;">
        <div style="background:#1e1e2e;color:white;padding:8px 12px;border-radius:6px 6px 0 0;">
            <b>{len(rows)} IPs</b> em {loc_label}
        </div>
        <div style="padding:4px 0;background:#f8fafc;border-radius:0 0 6px 6px;">
            <table style="width:100%;border-collapse:collapse;">
                <tr style="background:#e2e8f0;">
                    <th style="padding:4px 6px;text-align:left;font-size:11px;">IP</th>
                    <th style="padding:4px 6px;text-align:left;font-size:11px;">Provedor</th>
                    <th style="padding:4px 4px;text-align:center;font-size:11px;">Qtd</th>
                    <th style="padding:4px 4px;font-size:11px;">Tipo</th>
                </tr>
                {ips_html}
            </table>
            {extra}
        </div>
    </div>"""
