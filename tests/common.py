import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime

import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from advanced_analysis import (
    batch_check_shodan,
    check_tor_exit_nodes,
    compute_data_health,
    compute_multi_source_threat_score,
    compute_shodan_risk_indicators,
    detect_digital_silence,
    detect_geo_changes,
    detect_relay_chains,
    detect_shared_wifi,
    fingerprint_device_by_ip_pattern,
    get_tor_exit_cache_status,
    get_tor_exit_nodes,
    update_tor_exit_nodes_cache,
    validate_timezone_consistency,
)
from analysis import (
    analyze_provider_timing,
    analyze_subnet_patterns,
    analyze_time_patterns,
    backup_cache,
    calculate_movement_area,
    calculate_risk_scores,
    check_geofence,
    classify_infrastructure,
    compute_geo_precision,
    compute_ip_confidence,
    compute_subnet_consistency,
    compute_unified_reputation,
    correlate_subnets_cross_target,
    cross_correlation_temporal,
    cross_target_correlation,
    detect_base_locations,
    detect_disposable_numbers,
    detect_impossible_jumps,
    detect_life_patterns,
    detect_provider_transitions,
    detect_usage_profile,
    detect_vpn_heuristics,
    detect_vpn_timing,
    generate_behavioral_profile,
    scan_folder_for_logs,
)
from api_client import IPAPIClient, is_cgnat_ip, is_private_ip, is_valid_ip, resolve_rdns
from audit_logger import (
    generate_integrity_receipt,
    get_audit_trail,
    log_audit_event,
    verify_audit_integrity,
)
from data_processor import (
    COLUNAS_EXPORT,
    COLUNAS_EXPORT_META,
    COLUNAS_MODELO,
    FORMATO_4,
    convert_utc_to_local,
    detectar_formato_log,
    extrair_ips_do_formato_google,
    extrair_ips_do_formato_meta,
    extrair_ips_do_formato_simples,
    extrair_ips_do_formato_whatsapp,
    format_iso_date,
    get_periodo,
    parse_meta_ip_port,
)
from report_generator import generate_professional_report
from validators import (
    sanitize_csv_value,
    validate_dataframe,
    validate_domain,
    validate_integrity,
    validate_schema,
)
