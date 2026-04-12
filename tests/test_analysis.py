from tests.common import *


class TestRiskScore(unittest.TestCase):
    def test_normal_ip(self):
        df = pd.DataFrame([
            {
                'Ip': '8.8.8.8',
                'Ip_Proxy': False,
                'Ip_Hospedagem': False,
                'Ip_Movel': False,
                'Ip_Cidade': 'Sao Paulo',
            }
        ] * 5)
        scores = calculate_risk_scores(df)
        self.assertEqual(len(scores), 1)
        self.assertLessEqual(scores.iloc[0]['Score'], 10)

    def test_proxy_ip(self):
        df = pd.DataFrame([
            {
                'Ip': '1.2.3.4',
                'Ip_Proxy': True,
                'Ip_Hospedagem': False,
                'Ip_Movel': False,
                'Ip_Cidade': 'Unknown',
            }
        ] * 5)
        scores = calculate_risk_scores(df)
        self.assertGreaterEqual(scores.iloc[0]['Score'], 40)

    def test_hosting_proxy(self):
        df = pd.DataFrame([
            {
                'Ip': '1.2.3.4',
                'Ip_Proxy': True,
                'Ip_Hospedagem': True,
                'Ip_Movel': False,
                'Ip_Cidade': 'Unknown',
            }
        ] * 5)
        scores = calculate_risk_scores(df)
        self.assertGreaterEqual(scores.iloc[0]['Score'], 60)


class TestTimePatterns(unittest.TestCase):
    def test_basic_analysis(self):
        dates = [f'2025-01-0{day + 1} {hour:02d}:00:00' for day in range(5) for hour in range(24)]
        df = pd.DataFrame({'Data': dates})
        result = analyze_time_patterns(df)
        self.assertIsNotNone(result['hourly_counts'])
        self.assertGreater(len(result['most_active_hours']), 0)

    def test_empty_df(self):
        df = pd.DataFrame({'Data': []})
        result = analyze_time_patterns(df)
        self.assertIsNone(result['hourly_counts'])


class TestGeofencing(unittest.TestCase):
    def test_inside_fence(self):
        df = pd.DataFrame({'Ip_Lat': [-23.5505], 'Ip_Lon': [-46.6333], 'Ip': ['8.8.8.8']})
        inside, outside = check_geofence(df, -23.5505, -46.6333, 100)
        self.assertEqual(len(inside), 1)
        self.assertEqual(len(outside), 0)

    def test_outside_fence(self):
        df = pd.DataFrame({'Ip_Lat': [40.7128], 'Ip_Lon': [-74.0060], 'Ip': ['1.2.3.4']})
        inside, outside = check_geofence(df, -23.5505, -46.6333, 100)
        self.assertEqual(len(inside), 0)
        self.assertEqual(len(outside), 1)


class TestCrossCorrelation(unittest.TestCase):
    def test_common_ips(self):
        df1 = pd.DataFrame({'Ip': ['1.1.1.1', '2.2.2.2', '3.3.3.3'], 'Ip_Dono': ['A', 'B', 'C'], 'Ip_Cidade': ['X', 'Y', 'Z']})
        df2 = pd.DataFrame({'Ip': ['2.2.2.2', '4.4.4.4', '3.3.3.3'], 'Ip_Dono': ['B', 'D', 'C'], 'Ip_Cidade': ['Y', 'W', 'Z']})
        result = cross_target_correlation({'alvo1': df1, 'alvo2': df2})
        self.assertEqual(len(result), 2)

    def test_no_common_ips(self):
        df1 = pd.DataFrame({'Ip': ['1.1.1.1']})
        df2 = pd.DataFrame({'Ip': ['2.2.2.2']})
        result = cross_target_correlation({'a': df1, 'b': df2})
        self.assertEqual(len(result), 0)


class TestDisposableNumbers(unittest.TestCase):
    def test_detection(self):
        df = pd.DataFrame({'FROM': ['A', 'A', 'A', 'A', 'A', 'B', 'C', 'C'], 'Data': ['2025-01-01 10:00:00'] * 8, 'type': ['message/text'] * 8})
        result = detect_disposable_numbers(df, max_appearances=2)
        numbers = result['Numero'].tolist()
        self.assertIn('B', numbers)
        self.assertNotIn('A', numbers)


class TestVPNHeuristics(unittest.TestCase):
    def test_empty_df(self):
        result = detect_vpn_heuristics(pd.DataFrame())
        self.assertEqual(result['score'], 0)

    def test_normal_usage(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8'] * 10,
            'Data': pd.date_range('2025-01-01', periods=10, freq='h'),
            'Ip_AS': ['AS15169'] * 10,
            'Ip_Proxy': [False] * 10,
            'Ip_Hospedagem': [False] * 10,
            'Ip_Pais': ['US'] * 10,
        })
        result = detect_vpn_heuristics(df)
        self.assertLess(result['score'], 30)

    def test_high_asn_diversity(self):
        asns = [f'AS{index}' for index in range(8)]
        df = pd.DataFrame({'Ip': [f'1.2.3.{index}' for index in range(8)], 'Data': pd.date_range('2025-01-01', periods=8, freq='h'), 'Ip_AS': asns})
        result = detect_vpn_heuristics(df)
        self.assertGreater(result['score'], 0)

    def test_mixed_infrastructure(self):
        df = pd.DataFrame({
            'Ip': [f'1.2.3.{index}' for index in range(10)],
            'Data': pd.date_range('2025-01-01', periods=10, freq='h'),
            'Ip_Hospedagem': [True, True, True, False, False, False, False, False, False, False],
        })
        result = detect_vpn_heuristics(df)
        self.assertIn('indicators', result)


class TestIPConfidence(unittest.TestCase):
    def test_empty_df(self):
        result = compute_ip_confidence(pd.DataFrame())
        self.assertEqual(len(result), 0)

    def test_recurring_ip_higher_confidence(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8'] * 15 + ['1.2.3.4'],
            'Ip_Proxy': [False] * 16,
            'Ip_Hospedagem': [False] * 16,
            'Ip_Movel': [False] * 16,
            'Data': pd.date_range('2025-01-01', periods=16, freq='h'),
        })
        result = compute_ip_confidence(df)
        ip1 = result[result['IP'] == '8.8.8.8'].iloc[0]
        ip2 = result[result['IP'] == '1.2.3.4'].iloc[0]
        self.assertGreater(ip1['Confidence'], ip2['Confidence'])

    def test_proxy_ip_lower_confidence(self):
        df = pd.DataFrame({
            'Ip': ['1.2.3.4'] * 5,
            'Ip_Proxy': [True] * 5,
            'Ip_Hospedagem': [False] * 5,
            'Ip_Movel': [False] * 5,
            'Data': pd.date_range('2025-01-01', periods=5, freq='h'),
        })
        result = compute_ip_confidence(df)
        self.assertNotEqual(result.iloc[0]['Classification'], 'IP Real')


class TestLifePatterns(unittest.TestCase):
    def test_empty_df(self):
        df = pd.DataFrame({'Ip_Lat': [], 'Ip_Lon': [], 'Data': []})
        result = detect_life_patterns(df)
        self.assertFalse(result['has_data'])

    def test_insufficient_data(self):
        df = pd.DataFrame({'Ip_Lat': [-23.55], 'Ip_Lon': [-46.63], 'Data': ['2025-01-01 10:00:00']})
        result = detect_life_patterns(df)
        self.assertFalse(result['has_data'])

    def test_zero_coords_excluded(self):
        df = pd.DataFrame({'Ip_Lat': [0, 0, 0, 0, 0], 'Ip_Lon': [0, 0, 0, 0, 0], 'Data': pd.date_range('2025-01-01', periods=5, freq='h')})
        result = detect_life_patterns(df)
        self.assertFalse(result['has_data'])


class TestImpossibleJumps(unittest.TestCase):
    def test_no_jumps(self):
        df = pd.DataFrame({'Ip': ['8.8.8.8'] * 5, 'Ip_Lat': [-23.55] * 5, 'Ip_Lon': [-46.63] * 5, 'Data': pd.date_range('2025-01-01', periods=5, freq='h')})
        jumps = detect_impossible_jumps(df)
        self.assertEqual(len(jumps), 0)

    def test_detected_jump(self):
        df = pd.DataFrame({'Ip': ['1.1.1.1', '2.2.2.2'], 'Ip_Lat': [-23.55, 35.68], 'Ip_Lon': [-46.63, 139.69], 'Data': ['2025-01-01 10:00:00', '2025-01-01 11:00:00']})
        jumps = detect_impossible_jumps(df)
        self.assertGreater(len(jumps), 0)


class TestBaseLocations(unittest.TestCase):
    def test_with_data(self):
        samples = []
        for hour in [22, 23, 0, 1, 2, 3, 4, 5, 6]:
            for day in range(5):
                samples.append({'Ip': '1.1.1.1', 'Ip_Lat': -23.55, 'Ip_Lon': -46.63, 'Data': f'2025-01-{day + 1:02d} {hour:02d}:00:00', 'Ip_Cidade': 'SP', 'Ip_Regiao': 'SP', 'Ip_Dono': 'Vivo'})
        for hour in [9, 10, 11, 12, 13, 14, 15, 16, 17]:
            for day in range(5):
                samples.append({'Ip': '2.2.2.2', 'Ip_Lat': -23.56, 'Ip_Lon': -46.64, 'Data': f'2025-01-{day + 1:02d} {hour:02d}:00:00', 'Ip_Cidade': 'SP Office', 'Ip_Regiao': 'SP', 'Ip_Dono': 'Net'})
        result = detect_base_locations(pd.DataFrame(samples))
        self.assertIsInstance(result, dict)
        self.assertTrue('home' in result or 'work' in result)


class TestMovementArea(unittest.TestCase):
    def test_single_point(self):
        result = calculate_movement_area(pd.DataFrame({'Ip_Lat': [-23.55], 'Ip_Lon': [-46.63]}))
        self.assertEqual(result['area_km2'], 0)

    def test_multiple_points(self):
        df = pd.DataFrame({'Ip_Lat': [-23.55, -23.56, -23.57, -23.55], 'Ip_Lon': [-46.63, -46.64, -46.63, -46.62]})
        result = calculate_movement_area(df)
        self.assertGreater(result['num_points'], 1)


class TestInfrastructureClassification(unittest.TestCase):
    def test_datacenter_keywords(self):
        row = pd.Series({'Ip_Dono': 'Amazon.com Inc', 'Ip_AS': 'AS16509', 'Ip_Proxy': False, 'Ip_Hospedagem': True, 'Ip_Movel': False})
        result = classify_infrastructure(row)
        self.assertIn(result['category'], ['datacenter_vpn', 'cloud', 'hosting'])

    def test_normal_isp(self):
        row = pd.Series({'Ip_Dono': 'Vivo SA', 'Ip_AS': 'AS18881', 'Ip_Proxy': False, 'Ip_Hospedagem': False, 'Ip_Movel': False})
        result = classify_infrastructure(row)
        self.assertEqual(result['category'], 'normal')


class TestUnifiedReputation(unittest.TestCase):
    def test_empty_df(self):
        result = compute_unified_reputation(pd.DataFrame())
        self.assertTrue(result.empty)

    def test_basic_scoring(self):
        df = pd.DataFrame({
            'Ip': ['1.1.1.1', '2.2.2.2'],
            'Data': ['2025-01-01 10:00', '2025-01-01 11:00'],
            'Ip_Proxy': [True, False],
            'Ip_Hospedagem': [False, False],
            'Ip_Movel': [False, True],
            'Ip_Dono': ['VPN Provider', 'Claro'],
            'Ip_AS': ['AS1', 'AS2'],
            'Ip_Cidade': ['NYC', 'SP'],
            'Ip_Pais': ['US', 'BR'],
        })
        result = compute_unified_reputation(df)
        self.assertEqual(len(result), 2)
        self.assertIn('ReputationScore', result.columns)
        self.assertIn('ReputationLevel', result.columns)


class TestVPNTiming(unittest.TestCase):
    def test_empty_df(self):
        result = detect_vpn_timing(pd.DataFrame())
        self.assertFalse(result['detected'])

    def test_no_vpn(self):
        df = pd.DataFrame({'Ip': ['1.1.1.1', '2.2.2.2'], 'Data': ['2025-01-01 10:00:00', '2025-01-01 10:30:00'], 'Ip_Hospedagem': [False, False], 'Ip_Proxy': [False, False]})
        result = detect_vpn_timing(df)
        self.assertEqual(len(result['pairs']), 0)


class TestCrossCorrelationTemporal(unittest.TestCase):
    def test_single_target(self):
        result = cross_correlation_temporal({'a': pd.DataFrame()})
        self.assertTrue(result.empty)

    def test_shared_ip_same_day(self):
        targets = {
            'alvo1': pd.DataFrame({'Ip': ['1.1.1.1'], 'Data': ['2025-01-15 10:00']}),
            'alvo2': pd.DataFrame({'Ip': ['1.1.1.1'], 'Data': ['2025-01-15 14:00']}),
        }
        result = cross_correlation_temporal(targets)
        self.assertGreater(len(result), 0)
        self.assertIn('Dias_Coincidentes', result.columns)


class TestUsageProfile(unittest.TestCase):
    def test_empty_df(self):
        result = detect_usage_profile(pd.DataFrame())
        self.assertEqual(result['profile'], 'indeterminado')

    def test_residential_pattern(self):
        dates = [f'2025-01-01 {hour:02d}:00:00' for hour in [22, 23, 0, 1, 6, 7, 20, 21, 22, 23]]
        df = pd.DataFrame({'Ip': ['2804::1'] * 10, 'Data': dates, 'Ip_Dono': ['Claro'] * 10, 'Ip_Movel': [True] * 10})
        result = detect_usage_profile(df)
        self.assertIn(result['profile'], ['residencial', 'misto', 'indeterminado'])
        self.assertIsInstance(result['indicators'], list)


class TestGeoPrecision(unittest.TestCase):
    def test_proxy_low_precision(self):
        result = compute_geo_precision({'Ip': '1.1.1.1', 'Ip_Proxy': 'True', 'Ip_Hospedagem': 'False', 'Ip_Movel': 'False'})
        self.assertEqual(result['precision'], 'Baixa')

    def test_ipv6_residential_high(self):
        result = compute_geo_precision({'Ip': '2804::1', 'Ip_Proxy': 'False', 'Ip_Hospedagem': 'False', 'Ip_Movel': 'False'})
        self.assertEqual(result['precision'], 'Alta')

    def test_mobile_ipv4_medium(self):
        result = compute_geo_precision({'Ip': '1.1.1.1', 'Ip_Proxy': 'False', 'Ip_Hospedagem': 'False', 'Ip_Movel': 'True'})
        self.assertEqual(result['precision'], 'Média')


class TestKMLAnimated(unittest.TestCase):
    def test_empty_df(self):
        from analysis import export_kml_animated

        result = export_kml_animated(pd.DataFrame(columns=['Ip', 'Ip_Lat', 'Ip_Lon', 'Data']))
        self.assertIn('kml', result.lower())

    def test_basic_export(self):
        from analysis import export_kml_animated

        df = pd.DataFrame({
            'Ip': ['1.1.1.1', '2.2.2.2'],
            'Ip_Lat': [-23.5, -22.9],
            'Ip_Lon': [-46.6, -43.2],
            'Data': ['2025-01-01 10:00:00', '2025-01-02 11:00:00'],
            'Ip_Dono': ['Claro', 'Vivo'],
            'Ip_Cidade': ['SP', 'RJ'],
            'Ip_Proxy': [False, False],
            'Ip_Hospedagem': [False, False],
        })
        result = export_kml_animated(df)
        self.assertIn('1.1.1.1', result)
        self.assertIn('Rota Temporal', result)


class TestGeoHistory(unittest.TestCase):
    def test_empty_cache(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'], 'Ip_Cidade': ['SP'], 'Ip_Dono': ['Vivo']})
        result = detect_geo_changes(df, {})
        self.assertIsInstance(result, dict)
        self.assertEqual(result['total_changes'], 0)

    def test_no_history(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'], 'Ip_Cidade': ['SP'], 'Ip_Dono': ['Vivo']})
        cache = {'1.2.3.4': {'city': 'SP', 'isp': 'Vivo'}}
        result = detect_geo_changes(df, cache)
        self.assertEqual(result['total_changes'], 0)

    def test_with_geo_change(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'], 'Ip_Cidade': ['SP'], 'Ip_Dono': ['Vivo']})
        cache = {
            '1.2.3.4': {
                'Ip_Cidade': 'SP',
                'Ip_Dono': 'Vivo',
                'Ip_Pais': 'Brazil',
                '_geo_history': [{'city': 'RJ', 'isp': 'Claro', 'country': 'Brazil', 'ts': 1704067200}],
            }
        }
        result = detect_geo_changes(df, cache)
        self.assertGreater(result['total_changes'], 0)

    def test_empty_df(self):
        df = pd.DataFrame({'Ip': pd.Series(dtype='str'), 'Ip_Cidade': pd.Series(dtype='str'), 'Ip_Dono': pd.Series(dtype='str')})
        result = detect_geo_changes(df, {'1.2.3.4': {'city': 'SP'}})
        self.assertEqual(result['total_changes'], 0)


class TestSubnetAnalysis(unittest.TestCase):
    def test_empty_df(self):
        result = analyze_subnet_patterns(pd.DataFrame({'Ip': [], 'Data': []}))
        self.assertEqual(result['total_subnets'], 0)

    def test_basic_grouping(self):
        df = pd.DataFrame({'Ip': ['192.168.1.1', '192.168.1.2', '10.0.0.1'], 'Data': ['2025-01-01', '2025-01-02', '2025-01-03'], 'Ip_Dono': ['ISP1', 'ISP1', 'ISP2'], 'Ip_Cidade': ['SP', 'SP', 'RJ']})
        result = analyze_subnet_patterns(df, ipv4_mask=24)
        self.assertGreaterEqual(result['total_subnets'], 2)

    def test_consistency_score(self):
        df = pd.DataFrame({'Ip': ['192.168.1.1'] * 10 + ['10.0.0.1'], 'Data': [f'2025-01-{index + 1:02d} 10:00:00' for index in range(11)]})
        result = compute_subnet_consistency(df, ipv4_mask=24)
        self.assertGreater(result['consistency_score'], 50)
        self.assertIn('primary_subnet', result)

    def test_consistency_empty(self):
        result = compute_subnet_consistency(pd.DataFrame({'Ip': [], 'Data': []}))
        self.assertEqual(result['consistency_score'], 0)

    def test_cross_target_no_shared(self):
        targets = {'A': pd.DataFrame({'Ip': ['192.168.1.1']}), 'B': pd.DataFrame({'Ip': ['10.0.0.1']})}
        shared = correlate_subnets_cross_target(targets)
        self.assertEqual(len(shared), 0)

    def test_cross_target_shared(self):
        targets = {'A': pd.DataFrame({'Ip': ['192.168.1.1']}), 'B': pd.DataFrame({'Ip': ['192.168.1.2']})}
        shared = correlate_subnets_cross_target(targets, ipv4_mask=24)
        self.assertGreater(len(shared), 0)

    def test_cross_target_single(self):
        shared = correlate_subnets_cross_target({'A': pd.DataFrame({'Ip': ['1.2.3.4']})})
        self.assertEqual(len(shared), 0)


class TestTorExitNodes(unittest.TestCase):
    def test_check_tor_empty_set(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4', '5.6.7.8']})
        result = check_tor_exit_nodes(df, set(), ip_col='Ip')
        self.assertIsInstance(result, dict)
        self.assertEqual(result['total_tor'], 0)

    def test_check_tor_with_match(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4', '5.6.7.8']})
        result = check_tor_exit_nodes(df, {'1.2.3.4'}, ip_col='Ip')
        self.assertEqual(result['total_tor'], 1)
        self.assertIn('1.2.3.4', result['tor_ips'])

    def test_check_tor_empty_df(self):
        df = pd.DataFrame({'Ip': pd.Series(dtype='str')})
        result = check_tor_exit_nodes(df, {'1.2.3.4'}, ip_col='Ip')
        self.assertEqual(result['total_tor'], 0)

    def test_check_tor_all_match(self):
        ips = ['1.2.3.4', '5.6.7.8']
        result = check_tor_exit_nodes(pd.DataFrame({'Ip': ips}), set(ips), ip_col='Ip')
        self.assertEqual(result['total_tor'], 2)

    @patch('advanced_analysis.fetch_tor_exit_nodes_from_onionoo')
    @patch('advanced_analysis.fetch_tor_exit_nodes')
    def test_update_tor_exit_nodes_cache_deduplicates_sources(self, mock_bulk, mock_onionoo):
        mock_bulk.return_value = ({'1.1.1.1', '2.2.2.2'}, None)
        mock_onionoo.return_value = ({'2.2.2.2', '2001:4860:4860::8888'}, None)

        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_file = os.path.join(tmp_dir, 'tor_exit_nodes.json')
            result = update_tor_exit_nodes_cache(cache_file=cache_file)

            self.assertTrue(result['success'])
            self.assertEqual(result['node_count'], 3)
            self.assertEqual(result['source_counts']['torbulkexitlist'], 2)
            self.assertEqual(result['source_counts']['onionoo'], 2)

            with open(cache_file, 'r', encoding='utf-8') as handle:
                saved = json.load(handle)

            self.assertEqual(set(saved['nodes']), {'1.1.1.1', '2.2.2.2', '2001:4860:4860::8888'})

    @patch('advanced_analysis.update_tor_exit_nodes_cache')
    def test_get_tor_exit_nodes_uses_stale_cache_when_refresh_fails(self, mock_update):
        mock_update.return_value = {
            'success': False,
            'nodes': set(),
            'node_count': 0,
            'source_counts': {'torbulkexitlist': 0, 'onionoo': 0},
            'source_errors': {'torbulkexitlist': 'offline'},
            'error': 'Falha ao atualizar lista Tor a partir das fontes oficiais.',
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_file = os.path.join(tmp_dir, 'tor_exit_nodes.json')
            with open(cache_file, 'w', encoding='utf-8') as handle:
                json.dump({'cached_at': 0, 'nodes': ['1.2.3.4']}, handle)

            nodes = get_tor_exit_nodes(cache_file=cache_file, ttl_hours=6)
            self.assertEqual(nodes, {'1.2.3.4'})

    def test_get_tor_exit_cache_status_reports_stale_cache(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_file = os.path.join(tmp_dir, 'tor_exit_nodes.json')
            with open(cache_file, 'w', encoding='utf-8') as handle:
                json.dump({'cached_at': 0, 'nodes': ['1.2.3.4', '5.6.7.8']}, handle)

            status = get_tor_exit_cache_status(cache_file=cache_file, ttl_hours=6)

            self.assertTrue(status['available'])
            self.assertTrue(status['is_stale'])
            self.assertEqual(status['node_count'], 2)


class TestProviderTiming(unittest.TestCase):
    def test_empty_df(self):
        df = pd.DataFrame({'Data': [], 'Ip_Dono': [], 'Ip': []})
        result = analyze_provider_timing(df)
        self.assertEqual(len(result['providers']), 0)
        self.assertFalse(result['vpn_schedule']['detected'])

    def test_basic_timing(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'] * 10, 'Data': [f'2025-01-01 {hour:02d}:00:00' for hour in range(10)], 'Ip_Dono': ['TestISP'] * 10})
        result = analyze_provider_timing(df, min_records=5)
        self.assertIn('TestISP', result['providers'])
        self.assertIn('usage_type', result['providers']['TestISP'])

    def test_transitions_empty(self):
        df = pd.DataFrame({'Data': [], 'Ip_Dono': [], 'Ip': []})
        result = detect_provider_transitions(df)
        self.assertEqual(len(result['transitions']), 0)
        self.assertEqual(len(result['sandwich_patterns']), 0)

    def test_sandwich_detection(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4', '5.6.7.8', '1.2.3.4'] * 3, 'Data': [f'2025-01-01 {hour:02d}:00:00' for hour in range(9)], 'Ip_Dono': ['Vivo', 'NordVPN', 'Vivo'] * 3})
        result = detect_provider_transitions(df, window_minutes=120)
        self.assertGreater(len(result['sandwich_patterns']), 0)

    def test_no_transitions_same_provider(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'] * 5, 'Data': [f'2025-01-01 {hour:02d}:00:00' for hour in range(5)], 'Ip_Dono': ['Vivo'] * 5})
        result = detect_provider_transitions(df)
        self.assertEqual(len(result['transitions']), 0)

    def test_columns_definition_includes_tor(self):
        self.assertIn('Ip_Tor', COLUNAS_MODELO)


class TestGeofenceValidation(unittest.TestCase):
    def test_rejects_out_of_bounds_lat(self):
        df = pd.DataFrame({'Ip_Lat': [-23.55], 'Ip_Lon': [-46.63], 'Ip': ['8.8.8.8']})
        inside, outside = check_geofence(df, 100.0, -46.63, 50)
        self.assertEqual(len(inside), 0)
        self.assertEqual(len(outside), 0)

    def test_rejects_null_island(self):
        df = pd.DataFrame({'Ip_Lat': [-23.55], 'Ip_Lon': [-46.63], 'Ip': ['8.8.8.8']})
        inside, outside = check_geofence(df, 0.0, 0.0, 50)
        self.assertEqual(len(inside), 0)
        self.assertEqual(len(outside), 0)

    def test_valid_coordinates_work(self):
        df = pd.DataFrame({'Ip_Lat': [-23.55], 'Ip_Lon': [-46.63], 'Ip': ['8.8.8.8']})
        inside, outside = check_geofence(df, -23.55, -46.63, 100)
        self.assertEqual(len(inside), 1)
