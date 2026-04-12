"""
Log Enrichment - Interactive IP Network Graph (4.1)
Uses vis.js embedded in Streamlit to visualize IP/ASN/location connections.
Renders IP/ASN/location network graphs directly in the UI.
"""

import json
import streamlit as st
from styles.theme import COLORS


def render_ip_network_graph(df, height=650):
    """
    Render an interactive IP network graph using vis.js.
    Shows connections between IPs, ASNs, and locations.
    """
    if df is None or df.empty:
        st.info("Nenhum dado disponível para o grafo.")
        return

    ip_col = 'Sender IP' if 'Sender IP' in df.columns else 'Ip'
    if ip_col not in df.columns:
        st.warning("Coluna IP não encontrada.")
        return

    # Build graph data from DataFrame
    nodes = []
    edges = []
    node_ids = set()

    # Group by ASN
    asn_groups = {}
    for _, row in df.iterrows():
        ip = str(row.get(ip_col, ''))
        asn = str(row.get('Ip_AS', 'Desconhecido'))
        provider = str(row.get('Ip_Dono', ''))
        city = str(row.get('Ip_Cidade', ''))
        is_proxy = str(row.get('Ip_Proxy', '')).lower() == 'true'
        is_hosting = str(row.get('Ip_Hospedagem', '')).lower() == 'true'
        is_mobile = str(row.get('Ip_Movel', '')).lower() == 'true'

        if not ip or ip == 'nan':
            continue

        if asn not in asn_groups:
            asn_groups[asn] = {'provider': provider, 'ips': set(), 'cities': set()}
        asn_groups[asn]['ips'].add(ip)
        if city and city != 'nan':
            asn_groups[asn]['cities'].add(city)

        # IP node
        if ip not in node_ids:
            color = COLORS['danger'] if is_proxy else COLORS['hosting'] if is_hosting else COLORS['mobile'] if is_mobile else COLORS['success']
            node_type = 'Proxy/VPN' if is_proxy else 'Hosting' if is_hosting else 'Móvel' if is_mobile else 'Residencial'
            nodes.append({
                'id': ip,
                'label': ip[:20],
                'title': f'IP: {ip}\\nProvedor: {provider}\\nCidade: {city}\\nTipo: {node_type}',
                'color': color,
                'shape': 'dot',
                'size': 8,
                'group': 'ip',
            })
            node_ids.add(ip)

        # ASN node
        asn_id = f'asn_{asn}'
        if asn_id not in node_ids:
            nodes.append({
                'id': asn_id,
                'label': asn[:25] if len(asn) < 25 else asn[:22] + '...',
                'title': f'ASN: {asn}\\nProvedor: {provider}',
                'color': COLORS['primary'],
                'shape': 'diamond',
                'size': 15,
                'group': 'asn',
            })
            node_ids.add(asn_id)

        # City node
        if city and city != 'nan':
            city_id = f'city_{city}'
            if city_id not in node_ids:
                nodes.append({
                    'id': city_id,
                    'label': city,
                    'title': f'Cidade: {city}',
                    'color': '#f59e0b',
                    'shape': 'triangle',
                    'size': 12,
                    'group': 'city',
                })
                node_ids.add(city_id)

            # IP → City edge
            edges.append({'from': ip, 'to': city_id, 'color': {'color': COLORS['border']}, 'width': 1})

        # IP → ASN edge
        edges.append({'from': ip, 'to': asn_id, 'color': {'color': COLORS['text_dim']}, 'width': 1})

    # Limit nodes for performance
    if len(nodes) > 500:
        st.warning(f"Grafo limitado a 500 nós (total: {len(nodes)}). Filtre os dados para visualização completa.")
        nodes = nodes[:500]
        valid_ids = {n['id'] for n in nodes}
        edges = [e for e in edges if e['from'] in valid_ids and e['to'] in valid_ids]

    graph_data = json.dumps({'nodes': nodes, 'edges': edges}, ensure_ascii=False)

    html = f'''
    <html>
    <head>
        <script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
        <style>
            body {{ margin: 0; background: {COLORS['bg']}; overflow: hidden; }}
            #graph {{ width: 100%; height: {height}px; }}
            .legend {{ position: absolute; top: 10px; right: 10px; background: rgba(15,23,42,0.9);
                       padding: 10px; border-radius: 8px; border: 1px solid {COLORS['border']}; font-family: 'Segoe UI', sans-serif; }}
            .legend-item {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; color: {COLORS['text']}; font-size: 12px; }}
            .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
            .legend-diamond {{ width: 10px; height: 10px; transform: rotate(45deg); display: inline-block; }}
            .controls {{ position: absolute; bottom: 10px; left: 10px; display: flex; gap: 6px; }}
            .ctrl-btn {{ background: {COLORS['surface_card']}; border: 1px solid {COLORS['border']}; color: {COLORS['text']}; padding: 6px 12px;
                         border-radius: 6px; cursor: pointer; font-size: 12px; }}
            .ctrl-btn:hover {{ background: {COLORS['accent']}; color: {COLORS['bg']}; }}
        </style>
    </head>
    <body>
        <div id="graph"></div>
        <div class="legend">
            <div style="color:{COLORS['text_muted']};font-weight:bold;margin-bottom:4px;">Legenda</div>
            <div class="legend-item"><span class="legend-dot" style="background:{COLORS['success']};"></span> IP Normal</div>
            <div class="legend-item"><span class="legend-dot" style="background:{COLORS['mobile']};"></span> IP Móvel</div>
            <div class="legend-item"><span class="legend-dot" style="background:{COLORS['danger']};"></span> Proxy/VPN</div>
            <div class="legend-item"><span class="legend-dot" style="background:{COLORS['hosting']};"></span> Hosting</div>
            <div class="legend-item"><span class="legend-diamond" style="background:{COLORS['primary']};"></span> ASN</div>
            <div class="legend-item"><span class="legend-dot" style="background:{COLORS['warning']};border-radius:0;clip-path:polygon(50% 0,100% 100%,0 100%);"></span> Cidade</div>
        </div>
        <div class="controls">
            <button class="ctrl-btn" onclick="network.fit()">Ajustar</button>
            <button class="ctrl-btn" onclick="togglePhysics()">Física On/Off</button>
        </div>
        <script>
            var data = {graph_data};
            var container = document.getElementById('graph');
            var options = {{
                nodes: {{ font: {{ color: '{COLORS['text']}', size: 11 }}, borderWidth: 1 }},
                edges: {{ smooth: {{ type: 'continuous' }}, width: 1 }},
                physics: {{
                    forceAtlas2Based: {{ gravitationalConstant: -30, centralGravity: 0.005,
                                        springLength: 100, springConstant: 0.08 }},
                    solver: 'forceAtlas2Based',
                    stabilization: {{ iterations: 150 }}
                }},
                interaction: {{ hover: true, tooltipDelay: 100, navigationButtons: false }},
                layout: {{ improvedLayout: true }},
                groups: {{
                    ip: {{ shape: 'dot' }},
                    asn: {{ shape: 'diamond' }},
                    city: {{ shape: 'triangle' }}
                }}
            }};
            var network = new vis.Network(container, data, options);
            var physicsOn = true;
            function togglePhysics() {{
                physicsOn = !physicsOn;
                network.setOptions({{ physics: {{ enabled: physicsOn }} }});
            }}
        </script>
    </body>
    </html>'''

    st.iframe(html, height=height + 10)


