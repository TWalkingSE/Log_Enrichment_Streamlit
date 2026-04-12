from tests.common import *
from unittest.mock import Mock, patch


class TestRelayChains(unittest.TestCase):
    def _make_df(self):
        return pd.DataFrame({
            'Ip': ['1.2.3.4', '5.6.7.8', '10.0.0.1', '192.168.1.1'],
            'Data': ['2025-01-01 10:00:00', '2025-01-01 10:05:00', '2025-01-01 10:08:00', '2025-01-01 11:00:00'],
            'Ip_Hospedagem': [True, False, True, False],
            'Ip_Proxy': [False, False, False, False],
            'Ip_Dono': ['DigitalOcean', 'Claro', 'AWS', 'Vivo'],
            'Ip_Cidade': ['NYC', 'SP', 'Virginia', 'RJ'],
        })

    def test_detect_basic(self):
        result = detect_relay_chains(self._make_df(), max_gap_minutes=10)
        self.assertIsInstance(result, dict)
        self.assertIn('detected', result)
        self.assertIn('chains', result)

    def test_empty_df(self):
        df = pd.DataFrame({'Data': [], 'Ip': [], 'Ip_Hospedagem': [], 'Ip_Proxy': []})
        result = detect_relay_chains(df)
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get('detected', False))


class TestDeviceFingerprint(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(fingerprint_device_by_ip_pattern({}), [])

    def test_single_target(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'], 'Data': ['2025-01-01 10:00:00']})
        self.assertEqual(fingerprint_device_by_ip_pattern({'target1': df}), [])

    def test_two_targets(self):
        df1 = pd.DataFrame({'Ip': ['1.2.3.4', '5.6.7.8', '1.2.3.4'], 'Data': ['2025-01-01 10:00', '2025-01-01 10:05', '2025-01-01 10:15']})
        df2 = pd.DataFrame({'Ip': ['1.2.3.4', '9.9.9.9'], 'Data': ['2025-01-01 10:03', '2025-01-01 10:20']})
        result = fingerprint_device_by_ip_pattern({'a': df1, 'b': df2})
        self.assertIsInstance(result, list)


class TestSharedWifi(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(detect_shared_wifi({}), [])

    def test_shared_ip_same_time(self):
        df1 = pd.DataFrame({'Ip': ['1.2.3.4'], 'Data': ['2025-01-01 10:00:00']})
        df2 = pd.DataFrame({'Ip': ['1.2.3.4'], 'Data': ['2025-01-01 10:00:30']})
        result = detect_shared_wifi({'a': df1, 'b': df2}, tolerance_seconds=60)
        self.assertIsInstance(result, list)


class TestDigitalSilence(unittest.TestCase):
    def test_empty_df(self):
        result = detect_digital_silence(pd.DataFrame({'Data': [], 'Ip': []}))
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get('detected', False))

    def test_with_gap(self):
        df = pd.DataFrame({
            'Ip': ['1.2.3.4', '5.6.7.8'],
            'Data': ['2025-01-01 10:00:00', '2025-01-05 10:00:00'],
            'Ip_Cidade': ['SP', 'RJ'],
            'Ip_Dono': ['Claro', 'Vivo'],
            'Ip_Pais': ['BR', 'BR'],
        })
        result = detect_digital_silence(df, min_gap_hours=24)
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get('detected', False))


class TestTimezoneValidation(unittest.TestCase):
    def test_empty_df(self):
        result = validate_timezone_consistency(pd.DataFrame({'Data': [], 'Ip': []}))
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get('analyzed', False))

    def test_basic_validation(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'] * 20, 'Data': [f'2025-01-01 {hour:02d}:00:00' for hour in range(20)], 'Ip_Pais_Codigo': ['BR'] * 20})
        result = validate_timezone_consistency(df)
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get('analyzed', False))


class TestDataHealth(unittest.TestCase):
    def test_empty_df(self):
        result = compute_data_health(pd.DataFrame())
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('total', 0), 0)

    def test_basic_health(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4', '5.6.7.8'], 'Data': ['2025-01-01', '2025-01-02'], 'Ip_Dono': ['Claro', 'Vivo'], 'Ip_Cidade': ['SP', 'RJ'], 'Ip_Lat': [-23.5, -22.9], 'Ip_Lon': [-46.6, -43.2]})
        result = compute_data_health(df)
        self.assertGreater(result.get('total', 0), 0)
        self.assertIn('overall_score', result)


class TestMultiSourceThreatScore(unittest.TestCase):
    def test_empty_inputs(self):
        self.assertEqual(compute_multi_source_threat_score([], []), [])

    def test_abuse_only(self):
        abuse = [{'ip': '1.2.3.4', 'abuse_score': 80, 'total_reports': 10}]
        result = compute_multi_source_threat_score(abuse, [])
        self.assertGreater(len(result), 0)
        self.assertIn('threat_score', result[0])


class TestAIAssistant(unittest.TestCase):
    def test_build_system_prompt(self):
        from ai_assistant import build_system_prompt

        prompt = build_system_prompt(ips_por_provedor=5, data_fato='15/01/2026')
        self.assertIn('5', prompt)
        self.assertIn('15/01/2026', prompt)
        self.assertIn('IPv6', prompt)
        self.assertIn('CGNAT', prompt)

    def test_build_user_prompt_truncation(self):
        from ai_assistant import build_user_prompt

        df = pd.DataFrame({
            'Ip': [f'192.168.1.{index}' for index in range(100)],
            'Ip_Dono': ['ProvA'] * 50 + ['ProvB'] * 50,
            'Score': list(range(100)),
            'Data': pd.date_range('2026-01-01', periods=100, freq='h'),
            'Ip_Proxy': [False] * 100,
            'Ip_Cidade': ['SP'] * 100,
        })
        prompt = build_user_prompt(df, ['ProvA', 'ProvB'], {'ProvA': 50, 'ProvB': 50}, datetime(2026, 1, 15), 'Diurno', 72, 5)
        self.assertIn('ProvA', prompt)
        self.assertIn('ProvB', prompt)
        ip_lines = [line for line in prompt.split('\n') if '192.168.' in line]
        self.assertLessEqual(len(ip_lines), 30)

    def test_validate_ai_response_valid(self):
        from ai_assistant import validate_ai_response

        response = {
            'provedores': [{
                'nome': 'Vivo',
                'registros_total': 50,
                'percentual_cobertura': 60.0,
                'ips_selecionados': [
                    {'ip': '2804:18::1', 'tipo': 'IPv6', 'data': '2026-01-15', 'provedor': 'Vivo', 'score': 90, 'motivo': 'Ancora'},
                    {'ip': '2804:18::2', 'tipo': 'IPv6', 'data': '2026-01-15', 'provedor': 'Vivo', 'score': 85, 'motivo': 'Dia do fato'},
                    {'ip': '2804:18::3', 'tipo': 'IPv6', 'data': '2026-01-16', 'provedor': 'Vivo', 'score': 80, 'motivo': 'Ultimo'},
                ],
                'justificativa': 'Provedor dominante com IPv6',
            }],
            'cobertura_total': 60.0,
            'resumo_narrativo': 'Texto...',
            'alertas': [],
            'confianca': 'alta',
            'motivo_confianca': 'Dados consistentes',
        }
        df = pd.DataFrame({'Ip': ['2804:18::1', '2804:18::2', '2804:18::3']})
        is_valid, warnings = validate_ai_response(response, df)
        self.assertTrue(is_valid)
        self.assertEqual(len(warnings), 0)

    def test_validate_ai_response_too_many_providers(self):
        from ai_assistant import validate_ai_response

        response = {
            'provedores': [
                {
                    'nome': f'Prov{index}',
                    'ips_selecionados': [
                        {'ip': f'1.1.1.{item}', 'tipo': 'IPv4', 'data': '', 'provedor': '', 'score': 0, 'motivo': ''}
                        for item in range(3)
                    ],
                }
                for index in range(4)
            ],
            'cobertura_total': 90,
            'resumo_narrativo': '',
            'alertas': [],
            'confianca': 'media',
            'motivo_confianca': '',
        }
        df = pd.DataFrame({'Ip': [f'1.1.1.{index}' for index in range(12)]})
        is_valid, warnings = validate_ai_response(response, df)
        self.assertFalse(is_valid)
        self.assertTrue(any('4 provedores' in warning for warning in warnings))

    def test_check_ollama_status_offline(self):
        from ai_assistant import check_ollama_status

        result = check_ollama_status('http://localhost:99999')
        self.assertFalse(result['online'])
        self.assertIsNotNone(result['error'])

    @patch('ai_assistant.requests.post')
    @patch('ai_assistant.check_ollama_status')
    def test_test_ollama_inference_success(self, mock_status, mock_post):
        from ai_assistant import test_ollama_inference

        mock_status.return_value = {
            'online': True,
            'models': [{'name': 'qwen3.5:4b'}],
            'model_names': ['qwen3.5:4b'],
            'error': None,
        }
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {'response': 'OK'}
        mock_post.return_value = response

        result = test_ollama_inference('qwen3.5:4b', timeout_seconds=5)

        self.assertTrue(result['success'])
        self.assertEqual(result['response'], 'OK')
        self.assertEqual(result['model_used'], 'qwen3.5:4b')
        mock_post.assert_called_once()
        self.assertIn('/api/generate', mock_post.call_args.args[0])

    @patch('ai_assistant.query_ollama')
    @patch('ai_assistant.check_ollama_status')
    def test_run_ai_analysis_falls_back_to_lite_on_timeout(self, mock_status, mock_query):
        from ai_assistant import run_ai_analysis

        mock_status.return_value = {
            'online': True,
            'models': [
                {'name': 'qwen3.5:9b-q8_0'},
                {'name': 'qwen3.5:4b'},
            ],
            'model_names': ['qwen3.5:9b-q8_0', 'qwen3.5:4b'],
            'error': None,
        }
        mock_query.side_effect = [
            (None, 'Timeout (90s). Tente o tier Lite ou aumente o timeout configurado.'),
            ({
                'provedores': [{
                    'nome': 'Vivo',
                    'registros_total': 2,
                    'percentual_cobertura': 100.0,
                    'ips_selecionados': [
                        {'ip': '2804:18::1', 'tipo': 'IPv6', 'data': '2026-01-15 10:00', 'provedor': 'Vivo', 'score': 95, 'motivo': 'Primeiro'},
                        {'ip': '2804:18::2', 'tipo': 'IPv6', 'data': '2026-01-15 11:00', 'provedor': 'Vivo', 'score': 90, 'motivo': 'Ultimo'},
                        {'ip': '2804:18::3', 'tipo': 'IPv6', 'data': '2026-01-15 12:00', 'provedor': 'Vivo', 'score': 88, 'motivo': 'Dia do fato'},
                    ],
                    'justificativa': 'Provedor dominante',
                }],
                'cobertura_total': 100.0,
                'resumo_narrativo': 'Resumo gerado.',
                'alertas': [],
                'confianca': 'alta',
                'motivo_confianca': 'Dados consistentes',
            }, None),
        ]

        df = pd.DataFrame({
            'Ip': ['2804:18::1', '2804:18::2', '2804:18::3'],
            'Ip_Dono': ['Vivo', 'Vivo', 'Vivo'],
            'Score': [95, 90, 88],
            'Data': pd.date_range('2026-01-15 10:00:00', periods=3, freq='h'),
            'Ip_Proxy': [False, False, False],
            'Ip_Cidade': ['Aracaju', 'Aracaju', 'Aracaju'],
        })

        result = run_ai_analysis(
            df_scored=df,
            provedores_sel=['Vivo'],
            contagem_prov={'Vivo': 3},
            dt_fato=datetime(2026, 1, 15, 12, 0, 0),
            periodo_fato='Diurno',
            janela_horas=24,
            ips_por_provedor=5,
            tier='standard',
            alvo='Teste',
        )

        self.assertTrue(result['success'])
        self.assertTrue(result['fallback_used'])
        self.assertEqual(result['requested_model'], 'qwen3.5:9b-q8_0')
        self.assertEqual(result['model_used'], 'qwen3.5:4b')
        self.assertEqual(mock_query.call_count, 2)
        self.assertTrue(any('Timeout com qwen3.5:9b-q8_0' in note for note in result['notes']))


class TestShodanRiskIndicators(unittest.TestCase):
    def test_empty_results(self):
        risk = compute_shodan_risk_indicators([])
        self.assertIsInstance(risk, list)
        self.assertEqual(len(risk), 0)

    def test_with_dangerous_ports(self):
        results = [{'ip': '1.2.3.4', 'ports': [22, 23, 3389], 'vulns': [], 'org': 'Test ISP', 'services': []}]
        risk = compute_shodan_risk_indicators(results)
        self.assertGreater(len(risk), 0)
        self.assertIn('dangerous_ports', risk[0])
        self.assertGreater(len(risk[0]['dangerous_ports']), 0)

    def test_with_no_ports(self):
        results = [{'ip': '1.2.3.4', 'ports': [], 'vulns': [], 'org': 'Test ISP', 'services': []}]
        risk = compute_shodan_risk_indicators(results)
        self.assertEqual(len(risk[0]['dangerous_ports']), 0)

    def test_with_org_mismatch(self):
        df = pd.DataFrame({'Ip': ['1.2.3.4'], 'Ip_Dono': ['Different ISP']})
        results = [{'ip': '1.2.3.4', 'ports': [], 'vulns': [], 'org': 'Shodan Org', 'services': []}]
        risk = compute_shodan_risk_indicators(results, df)
        self.assertIsInstance(risk, list)
        self.assertGreater(len(risk), 0)
