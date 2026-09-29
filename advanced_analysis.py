"""
Fachada histórica das análises avançadas.

O código foi dividido por natureza:
- `intel.threat` — AbuseIPDB, VirusTotal e Shodan (saem para a rede);
- `intel.tor` — lista de Tor exit nodes (download, cache e cruzamento);
- `analysis.heuristics` — heurísticas locais sobre o DataFrame.

Estes re-exports preservam a superfície usada por páginas, `tor_updater` e
testes; não são código morto.
"""

from analysis.heuristics import (  # noqa: F401
    compute_data_health,
    detect_digital_silence,
    detect_geo_changes,
    detect_relay_chains,
    detect_shared_wifi,
    fingerprint_device_by_ip_pattern,
    validate_timezone_consistency,
)
from intel.threat import (  # noqa: F401
    batch_check_abuseipdb,
    batch_check_shodan,
    batch_check_virustotal,
    check_abuseipdb,
    check_shodan,
    check_virustotal,
    compute_multi_source_threat_score,
    compute_shodan_risk_indicators,
)
from intel.tor import (  # noqa: F401
    TOR_BULK_EXIT_LIST_URL,
    TOR_CACHE_FILE,
    TOR_CACHE_TTL_HOURS,
    TOR_ONIONOO_DETAILS_URL,
    check_tor_exit_nodes,
    fetch_tor_exit_nodes,
    fetch_tor_exit_nodes_from_onionoo,
    get_tor_exit_cache_status,
    get_tor_exit_nodes,
    load_tor_exit_nodes,
    save_tor_exit_nodes,
    update_tor_exit_nodes_cache,
)
