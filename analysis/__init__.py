"""
Log Enrichment - Analysis package (modularized from analysis.py).
Public API preserved for `from analysis import ...`.
"""

from analysis.infrastructure import (
    classify_infrastructure,
    format_reputacao,
    classify_dataframe,
)
from analysis.cache_ops import backup_cache
from analysis.correlation import (
    cross_target_correlation,
    cross_correlation_temporal,
)
from analysis.temporal import (
    analyze_time_patterns,
    analyze_provider_timing,
    detect_provider_transitions,
)
from analysis.geo import (
    check_geofence,
    detect_life_patterns,
    detect_travel_pattern,
    compute_geo_precision,
)
from analysis.risk import (
    calculate_risk_scores,
    detect_vpn_heuristics,
    compute_ip_confidence,
    compute_unified_reputation,
)
from analysis.comms import detect_disposable_numbers
from analysis.export_kml import export_kml_animated, export_kml
from analysis.io_scan import scan_folder_for_logs
from analysis.movement import (
    detect_impossible_jumps,
    detect_base_locations,
    generate_behavioral_profile,
    compare_periods,
    calculate_movement_area,
)
from analysis.subnet import (
    analyze_subnet_patterns,
    correlate_subnets_cross_target,
    compute_subnet_consistency,
)
from analysis.profile import detect_vpn_timing, detect_usage_profile
from analysis._config import DATACENTER_VPN_KEYWORDS, CLOUD_KEYWORDS

# Re-export advanced_analysis helpers (historical surface of analysis.py)
from advanced_analysis import (
    batch_check_abuseipdb,
    batch_check_virustotal,
    compute_multi_source_threat_score,
    compute_data_health,
    detect_relay_chains,
    fingerprint_device_by_ip_pattern,
    detect_shared_wifi,
    detect_digital_silence,
    validate_timezone_consistency,
    batch_check_shodan,
    compute_shodan_risk_indicators,
    detect_geo_changes,
    get_tor_exit_nodes,
    check_tor_exit_nodes,
)

__all__ = ['DATACENTER_VPN_KEYWORDS', 'CLOUD_KEYWORDS', 'classify_infrastructure', 'format_reputacao', 'classify_dataframe', 'backup_cache', 'cross_target_correlation', 'cross_correlation_temporal', 'analyze_time_patterns', 'analyze_provider_timing', 'detect_provider_transitions', 'check_geofence', 'detect_life_patterns', 'detect_travel_pattern', 'compute_geo_precision', 'calculate_risk_scores', 'detect_vpn_heuristics', 'compute_ip_confidence', 'compute_unified_reputation', 'detect_disposable_numbers', 'export_kml_animated', 'export_kml', 'scan_folder_for_logs', 'detect_impossible_jumps', 'detect_base_locations', 'generate_behavioral_profile', 'compare_periods', 'calculate_movement_area', 'analyze_subnet_patterns', 'correlate_subnets_cross_target', 'compute_subnet_consistency', 'detect_vpn_timing', 'detect_usage_profile', 'batch_check_abuseipdb', 'batch_check_virustotal', 'compute_multi_source_threat_score', 'compute_data_health', 'detect_relay_chains', 'fingerprint_device_by_ip_pattern', 'detect_shared_wifi', 'detect_digital_silence', 'validate_timezone_consistency', 'batch_check_shodan', 'compute_shodan_risk_indicators', 'detect_geo_changes', 'get_tor_exit_nodes', 'check_tor_exit_nodes']
