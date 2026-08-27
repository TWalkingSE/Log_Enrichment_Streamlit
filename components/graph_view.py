"""
Log Enrichment - Interactive IP Network Graph (4.1)
Uses vis.js embedded in Streamlit to visualize IP/ASN/location connections.
Renders IP/ASN/location network graphs directly in the UI.
"""

import json
import streamlit as st
import streamlit.components.v1 as components
from styles.theme import COLORS

# Tetos de renderização: vis.js roda física em O(nós+arestas) no navegador,
# e o payload trafega inteiro pelo websocket do Streamlit.
MAX_NODES = 500
MAX_EDGES = 5000
from validators import bool_series


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

    # O grafo é de IPs, não de registros: iterar 200k linhas para produzir os
    # mesmos ~4k nós era puro desperdício, e as arestas eram acrescentadas por
    # LINHA sem deduplicação — com poucos IPs únicos o corte de nós nunca
    # disparava e centenas de milhares de arestas idênticas iam para o
    # navegador, derrubando a conexão.
    unique_df = df.drop_duplicates(subset=[ip_col])
    total_ips = len(unique_df)

    proxy_flags = bool_series(unique_df, 'Ip_Proxy').tolist()
    hosting_flags = bool_series(unique_df, 'Ip_Hospedagem').tolist()
    mobile_flags = bool_series(unique_df, 'Ip_Movel').tolist()

    nodes = []
    node_ids = set()
    edge_set = set()   # (origem, destino, tipo) — deduplicação natural

    for pos, (_, row) in enumerate(unique_df.iterrows()):
        ip = str(row.get(ip_col, ''))
        if not ip or ip == 'nan':
            continue

        asn = str(row.get('Ip_AS', 'Desconhecido'))
        provider = str(row.get('Ip_Dono', ''))
        city = str(row.get('Ip_Cidade', ''))
        is_proxy = proxy_flags[pos]
        is_hosting = hosting_flags[pos]
        is_mobile = mobile_flags[pos]

        # IP node
        if ip not in node_ids:
            if len(node_ids) >= MAX_NODES:
                continue
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
        if asn_id not in node_ids and len(node_ids) < MAX_NODES:
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
        city_id = None
        if city and city != 'nan':
            city_id = f'city_{city}'
            if city_id not in node_ids and len(node_ids) < MAX_NODES:
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

        if city_id and ip in node_ids and city_id in node_ids:
            edge_set.add((ip, city_id, 'city'))
        if ip in node_ids and asn_id in node_ids:
            edge_set.add((ip, asn_id, 'asn'))

    edges = [
        {'from': a, 'to': b,
         'color': {'color': COLORS['border'] if kind == 'city' else COLORS['text_dim']},
         'width': 1}
        for a, b, kind in sorted(edge_set)
    ]

    # Truncagem sempre explícita — o analista precisa saber que está vendo
    # uma parte do grafo, não o todo.
    truncated_edges = len(edges) > MAX_EDGES
    if truncated_edges:
        edges = edges[:MAX_EDGES]
    if len(node_ids) >= MAX_NODES or truncated_edges:
        st.warning(
            f"Grafo truncado para {len(nodes)} nós e {len(edges)} arestas "
            f"(de {total_ips} IPs únicos). Filtre os dados para ver o grafo completo."
        )
    else:
        st.caption(f"{len(nodes)} nós e {len(edges)} arestas a partir de {total_ips} IPs únicos.")

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

    components.html(html, height=height + 10, scrolling=False)


