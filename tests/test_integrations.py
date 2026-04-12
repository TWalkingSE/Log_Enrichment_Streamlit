from tests.common import *


class TestAPIClient(unittest.TestCase):
    def test_default_config_free_api(self):
        client = IPAPIClient()
        self.assertIn('ip-api.com/json/', client.API_URL)
        self.assertNotIn('pro.', client.API_URL)
        self.assertEqual(client.batch_size, 45)
        self.assertEqual(client.period, 60)
        self.assertIsNone(client.api_key)

    def test_with_api_key(self):
        client = IPAPIClient(api_key='test_key_123')
        self.assertIn('pro.ip-api.com', client.API_URL)
        self.assertEqual(client.batch_size, 500)
        self.assertEqual(client.period, 0)
        self.assertEqual(client.api_key, 'test_key_123')
        self.assertIn('https', client.API_URL)

    def test_cache_init(self):
        client = IPAPIClient(cache_file=None)
        self.assertEqual(len(client.cache), 0)

    def test_make_error_result(self):
        client = IPAPIClient()
        result = client._make_error_result('test error')
        self.assertIn('Erro: test error', result['Ip_Dono'])
        self.assertIn('Ip_Pais', result)
        self.assertIn('Ip_Pais_Codigo', result)

    def test_cache_ttl_default(self):
        self.assertEqual(IPAPIClient().cache_ttl, 30 * 24 * 60 * 60)

    def test_cache_ttl_custom(self):
        self.assertEqual(IPAPIClient(cache_ttl=3600).cache_ttl, 3600)


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.audit_file = os.path.join(self.tmp_dir, 'test_audit.jsonl')

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_log_event(self):
        event = log_audit_event(action='test_action', details={'key': 'value'}, user='test_user')
        self.assertEqual(event['action'], 'test_action')
        self.assertEqual(event['user'], 'test_user')
        self.assertIn('timestamp', event)
        self.assertIn('event_hash', event)

    def test_integrity_receipt(self):
        receipt = generate_integrity_receipt(input_file=__file__, output_file=__file__, alvo='test_target', record_count=1)
        self.assertIn('receipt_hash', receipt)
        self.assertIn('record_count', receipt)
        self.assertEqual(receipt['record_count'], 1)


class TestReportGenerator(unittest.TestCase):
    def _make_sample_df(self):
        return pd.DataFrame({
            'Ip': ['8.8.8.8', '1.1.1.1', '8.8.8.8'],
            'Data': ['2025-01-01 10:00:00', '2025-01-01 11:00:00', '2025-01-02 12:00:00'],
            'Ip_Pais': ['US', 'US', 'US'],
            'Ip_Regiao': ['CA', 'CA', 'CA'],
            'Ip_Cidade': ['LA', 'LA', 'LA'],
            'Ip_Dono': ['Google', 'Cloudflare', 'Google'],
            'Ip_Proxy': [False, False, False],
            'Ip_Hospedagem': [False, False, False],
            'Ip_Movel': [False, False, False],
            'Periodo': ['Diurno', 'Diurno', 'Diurno'],
        })

    def test_generate_basic_report(self):
        pdf_bytes = generate_professional_report(self._make_sample_df(), 'test_target')
        self.assertIsInstance(pdf_bytes, (bytes, bytearray))
        self.assertGreater(len(pdf_bytes), 100)

    def test_basic_report_wrapper(self):
        from helpers.pdf_report import generate_pdf_report

        pdf_bytes = generate_pdf_report(self._make_sample_df(), 'test_target')
        self.assertIsInstance(pdf_bytes, (bytes, bytearray))
        self.assertGreater(len(pdf_bytes), 100)

    def test_report_with_config(self):
        config = {
            'title': 'Test Report',
            'organization': 'Test Org',
            'case_number': 'CASE-001',
            'analyst': 'Agent Smith',
            'classification': 'CONFIDENCIAL',
        }
        pdf_bytes = generate_professional_report(self._make_sample_df(), 'target', config=config)
        self.assertIsInstance(pdf_bytes, (bytes, bytearray))

    def test_report_with_analyses(self):
        analyses = {
            'risk_scores': pd.DataFrame({'IP': ['8.8.8.8'], 'Score': [75], 'Ip_Dono': ['Google'], 'Ip_Pais': ['US']}),
            'impossible_jumps': pd.DataFrame(),
            'vpn_heuristics': {'score': 0, 'indicators': {}, 'suspicious_ips': []},
        }
        pdf_bytes = generate_professional_report(self._make_sample_df(), 'target', analyses=analyses)
        self.assertGreater(len(pdf_bytes), 100)

    def test_report_with_audit_hash(self):
        pdf_bytes = generate_professional_report(self._make_sample_df(), 'target', audit_hash='abc123def456' * 5)
        self.assertGreater(len(pdf_bytes), 100)


class TestCacheCompression(unittest.TestCase):
    def test_cache_metrics(self):
        client = IPAPIClient(cache_file=None)
        self.assertEqual(client.cache_hits, 0)
        self.assertEqual(client.cache_misses, 0)

    def test_get_status(self):
        status = IPAPIClient(cache_file=None).get_status()
        self.assertIn('cache_hit_rate', status)
        self.assertIn('cache_size', status)


class TestSmokeFlows(unittest.TestCase):
    def _make_enriched_df(self):
        df = extrair_ips_do_formato_simples('8.8.8.8\n1.1.1.1', alvo='smoke')
        df['Data'] = ['2025-01-01 10:00:00', '2025-01-01 11:00:00']
        df['Ip_Pais'] = ['BR', 'BR']
        df['Ip_Regiao'] = ['SP', 'SP']
        df['Ip_Cidade'] = ['Sao Paulo', 'Sao Paulo']
        df['Ip_Dono'] = ['Google', 'Cloudflare']
        df['Ip_Proxy'] = [False, False]
        df['Ip_Hospedagem'] = [False, False]
        df['Ip_Movel'] = [False, False]
        df['Periodo'] = ['☀️ Diurno', '☀️ Diurno']
        return df

    def test_simple_input_report_and_xlsx_smoke(self):
        from file_handler import export_xlsx_colored
        from helpers.pdf_report import generate_pdf_report

        df = self._make_enriched_df()
        pdf_bytes = generate_pdf_report(df, 'smoke')
        self.assertGreater(len(pdf_bytes), 100)

        output = io.BytesIO()
        export_xlsx_colored(df, output)
        self.assertGreater(len(output.getvalue()), 0)

    def test_interception_enrichment_smoke(self):
        from interception_parser import processar_resultados_interceptacao

        df = pd.DataFrame({
            'Sender IP': ['8.8.8.8'],
            'Ip_Dono': [''],
            'Ip_AS': [''],
            'Ip_Regiao': [''],
            'Ip_Cidade': [''],
            'Ip_Pais': [''],
            'Ip_Pais_Codigo': [''],
            'Ip_Movel': [False],
            'Ip_Proxy': [False],
            'Ip_Hospedagem': [False],
            'Ip_Lat': [None],
            'Ip_Lon': [None],
        })
        resultados_api = {
            '8.8.8.8': {
                'status': 'success',
                'Ip_Dono': 'Google',
                'Ip_AS': 'AS15169',
                'Ip_Regiao': 'California',
                'Ip_Cidade': 'Mountain View',
                'Ip_Pais': 'United States',
                'Ip_Pais_Codigo': 'US',
                'Ip_Movel': False,
                'Ip_Proxy': False,
                'Ip_Hospedagem': False,
                'Ip_Lat': 37.4056,
                'Ip_Lon': -122.0775,
            }
        }
        result = processar_resultados_interceptacao(df, resultados_api)
        self.assertEqual(result.loc[0, 'Ip_Dono'], 'Google')
        self.assertEqual(result.loc[0, 'Ip_Pais_Codigo'], 'US')
