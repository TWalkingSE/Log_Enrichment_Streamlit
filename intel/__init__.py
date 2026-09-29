"""Integrações com fontes externas de inteligência: VirusTotal, AbuseIPDB,
Shodan e a lista de Tor exit nodes.

Tudo aqui sai para a rede e passa por `ensure_network_allowed` (modo
air-gapped). As heurísticas que só leem o DataFrame ficam em `analysis/`.
"""
