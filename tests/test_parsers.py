from tests.common import *


class TestIPValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertTrue(is_valid_ip('8.8.8.8'))
        self.assertTrue(is_valid_ip('177.87.87.204'))

    def test_valid_ipv6(self):
        self.assertTrue(is_valid_ip('2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7'))
        self.assertTrue(is_valid_ip('::1'))

    def test_invalid_ip(self):
        self.assertFalse(is_valid_ip(''))
        self.assertFalse(is_valid_ip(None))
        self.assertFalse(is_valid_ip('not_an_ip'))
        self.assertFalse(is_valid_ip('999.999.999.999'))
        self.assertFalse(is_valid_ip('192.168.1'))

    def test_ip_with_port(self):
        self.assertFalse(is_valid_ip('192.168.1.1:8080'))


class TestPrivateIP(unittest.TestCase):
    def test_private_ipv4(self):
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertTrue(is_private_ip('192.168.1.1'))
        self.assertTrue(is_private_ip('172.16.0.1'))
        self.assertTrue(is_private_ip('127.0.0.1'))

    def test_public_ipv4(self):
        self.assertFalse(is_private_ip('8.8.8.8'))
        self.assertFalse(is_private_ip('177.87.87.204'))

    def test_invalid_ip(self):
        self.assertFalse(is_private_ip('not_an_ip'))


class TestCGNATIP(unittest.TestCase):
    def test_cgnat_ipv4(self):
        self.assertTrue(is_cgnat_ip('100.64.0.1'))
        self.assertTrue(is_cgnat_ip('100.127.255.254'))

    def test_non_cgnat_ipv4(self):
        self.assertFalse(is_cgnat_ip('8.8.8.8'))
        self.assertFalse(is_cgnat_ip('192.168.1.1'))

    def test_invalid_or_ipv6(self):
        self.assertFalse(is_cgnat_ip('not_an_ip'))
        self.assertFalse(is_cgnat_ip('2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7'))


class TestResolveRDNS(unittest.TestCase):
    def test_invalid_ip_returns_none(self):
        result = resolve_rdns('999.999.999.999')
        self.assertIsNone(result)

    def test_returns_string_or_none(self):
        result = resolve_rdns('8.8.8.8')
        self.assertTrue(result is None or isinstance(result, str))


class TestTimezoneHelpers(unittest.TestCase):
    def test_get_periodo(self):
        self.assertEqual(get_periodo(6), '☀️ Diurno')
        self.assertEqual(get_periodo(17), '☀️ Diurno')
        self.assertEqual(get_periodo(18), '🌙 Noturno')
        self.assertEqual(get_periodo(5), '🌙 Noturno')
        self.assertEqual(get_periodo(0), '🌙 Noturno')

    def test_format_iso_date(self):
        dt = datetime(2025, 1, 15, 10, 30, 0)
        result = format_iso_date(dt)
        self.assertIn('2025-01-15T10:30:00', result)
        self.assertIn(':00', result)

    def test_convert_utc_to_local(self):
        dt_utc = datetime(2025, 1, 15, 18, 0, 0)
        dt_local = convert_utc_to_local(dt_utc)
        self.assertEqual(dt_local.hour, 15)


class TestMetaIPPortParsing(unittest.TestCase):
    def test_ipv4_with_port(self):
        ip, port = parse_meta_ip_port('24.152.81.150:22859')
        self.assertEqual(ip, '24.152.81.150')
        self.assertEqual(port, '22859')

    def test_ipv6_with_port(self):
        ip, port = parse_meta_ip_port('[2804:04b0:1354:6500:29a9:2a7f:ee68:d955]:59483')
        self.assertEqual(ip, '2804:04b0:1354:6500:29a9:2a7f:ee68:d955')
        self.assertEqual(port, '59483')

    def test_ip_without_port(self):
        ip, port = parse_meta_ip_port('177.87.87.204')
        self.assertEqual(ip, '177.87.87.204')
        self.assertEqual(port, '')

    def test_whitespace(self):
        ip, port = parse_meta_ip_port('  24.152.81.150:22859  ')
        self.assertEqual(ip, '24.152.81.150')
        self.assertEqual(port, '22859')


class TestFormatDetection(unittest.TestCase):
    def test_meta_format(self):
        content = "IP Addresses: IP addresses and source port/port numbers\nIP Address\n24.152.81.150:22859\nTime\n2025-09-29 11:15:01 UTC"
        self.assertEqual(detectar_formato_log(content), 'meta')

    def test_whatsapp_format(self):
        content = "IP addresses an account holder has connected from\nTime\n2025-12-10 18:58:48 UTC\nIP Address\n2804:14d:8e90:866e"
        self.assertEqual(detectar_formato_log(content), 'whatsapp')

    def test_google_format(self):
        content = "GOOGLE SUBSCRIBER INFORMATION\nIP ACTIVITY\nTimestamp   IP Address\n2023-02-25 04:34:32 Z   187.37.136.128"
        self.assertEqual(detectar_formato_log(content), 'google')

    def test_generic_format(self):
        content = "192.168.1.1\n10.0.0.1\n8.8.8.8"
        self.assertEqual(detectar_formato_log(content), 'generico')


class TestWhatsAppParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = """IP addresses an account holder has connected from
Time
2025-12-10 18:58:48 UTC
IP Address
177.87.87.204
Time
2025-12-05 19:35:57 UTC
IP Address
8.8.8.8"""
        df = extrair_ips_do_formato_whatsapp(content, alvo='test')
        self.assertEqual(len(df), 2)
        self.assertIn('Alvo', df.columns)
        self.assertIn('Ip', df.columns)
        self.assertEqual(df.iloc[0]['Alvo'], 'test')
        self.assertNotIn('Porta', df.columns)

    def test_utc_to_gmt3(self):
        content = """Time
2025-12-10 18:00:00 UTC
IP Address
8.8.8.8"""
        df = extrair_ips_do_formato_whatsapp(content, alvo='test')
        self.assertEqual(len(df), 1)
        self.assertIn('15:00:00', df.iloc[0]['Data'])


class TestMetaParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = """IP addresses and source port/port numbers
IP Address
24.152.81.150:22859
Time
2025-09-29 11:15:01 UTC
IP Address
[2804:04b0:1354:6500:29a9:2a7f:ee68:d955]:59483
Time
2025-09-21 23:01:39 UTC"""
        df = extrair_ips_do_formato_meta(content, alvo='meta_test')
        self.assertEqual(len(df), 2)
        self.assertIn('Porta', df.columns)
        self.assertEqual(df.iloc[0]['Porta'], '22859')


class TestGoogleParser(unittest.TestCase):
    def test_basic_parsing(self):
        df = extrair_ips_do_formato_google(FORMATO_4, alvo='google_test')
        self.assertGreater(len(df), 0)
        self.assertEqual(df.iloc[0]['Alvo'], 'google_test')
        for ip in df['Ip']:
            self.assertTrue(is_valid_ip(ip), f'Invalid IP: {ip}')


class TestSimpleParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = "192.168.1.1\n8.8.8.8\n2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7"
        df = extrair_ips_do_formato_simples(content, alvo='simple_test')
        self.assertEqual(len(df), 3)


class TestColumnsDefinition(unittest.TestCase):
    def test_export_columns_subset_of_model(self):
        computed_cols = {'Reputação'}
        for col in COLUNAS_EXPORT:
            if col not in computed_cols:
                self.assertIn(col, COLUNAS_MODELO, f'{col} not in COLUNAS_MODELO')

    def test_meta_has_porta(self):
        self.assertIn('Porta', COLUNAS_EXPORT_META)
        self.assertNotIn('Porta', COLUNAS_EXPORT)

    def test_latlon_in_export(self):
        self.assertIn('Ip_Lat', COLUNAS_EXPORT)
        self.assertIn('Ip_Lon', COLUNAS_EXPORT)

    def test_country_columns_exist(self):
        self.assertIn('Ip_Pais', COLUNAS_MODELO)
        self.assertIn('Ip_Pais_Codigo', COLUNAS_MODELO)
        self.assertNotIn('Ip_Pais', COLUNAS_EXPORT)
        self.assertNotIn('Ip_Pais_Codigo', COLUNAS_EXPORT)


class TestPeriodoHelpers(unittest.TestCase):
    def test_normalizar_periodo(self):
        from data_processor import normalizar_periodo

        self.assertEqual(normalizar_periodo('☀️ Diurno'), 'diurno')
        self.assertEqual(normalizar_periodo('🌙 Noturno'), 'noturno')
        self.assertEqual(normalizar_periodo('Diurno'), 'diurno')
        self.assertEqual(normalizar_periodo('Noturno'), 'noturno')

    def test_is_noturno(self):
        from data_processor import is_diurno, is_noturno

        self.assertTrue(is_noturno('🌙 Noturno'))
        self.assertTrue(is_noturno('Noturno'))
        self.assertFalse(is_noturno('☀️ Diurno'))
        self.assertTrue(is_diurno('☀️ Diurno'))
        self.assertTrue(is_diurno('Diurno'))

    def test_periodo_matches(self):
        from data_processor import periodo_matches

        self.assertTrue(periodo_matches('☀️ Diurno', 'Diurno'))
        self.assertTrue(periodo_matches('🌙 Noturno', 'Noturno'))
        self.assertFalse(periodo_matches('☀️ Diurno', '🌙 Noturno'))


class TestHTMLParser(unittest.TestCase):
    def test_detect_html_platform_whatsapp(self):
        from html_parser import detect_html_platform

        html = '<title>WhatsApp Business Record</title><div>content</div>'
        self.assertEqual(detect_html_platform(html), 'whatsapp')

    def test_detect_html_platform_meta(self):
        from html_parser import detect_html_platform

        html = '<title>Meta Platforms Business Record</title><div>content</div>'
        self.assertEqual(detect_html_platform(html), 'meta')

    def test_detect_html_platform_google(self):
        from html_parser import detect_html_platform

        html = '<h2>GOOGLE SUBSCRIBER INFORMATION</h2><h3>IP ACTIVITY</h3>'
        self.assertEqual(detect_html_platform(html), 'google')

    def test_detect_html_platform_unknown(self):
        from html_parser import detect_html_platform

        self.assertEqual(detect_html_platform('<html><body>random</body></html>'), 'unknown')

    def test_split_ip_port_ipv4_with_port(self):
        from html_parser import _split_ip_port

        ip, port = _split_ip_port('187.68.195.77:1135')
        self.assertEqual(ip, '187.68.195.77')
        self.assertEqual(port, '1135')

    def test_split_ip_port_ipv6_with_port(self):
        from html_parser import _split_ip_port

        ip, port = _split_ip_port('[2804:29b8:5413:9caf:e130:7b53:f760:b833]:63629')
        self.assertEqual(ip, '2804:29b8:5413:9caf:e130:7b53:f760:b833')
        self.assertEqual(port, '63629')

    def test_split_ip_port_ipv4_no_port(self):
        from html_parser import _split_ip_port

        ip, port = _split_ip_port('179.215.90.5')
        self.assertEqual(ip, '179.215.90.5')
        self.assertEqual(port, '')

    def test_parse_google_html(self):
        from html_parser import parse_google_html

        html = """<html><head><title>Google Account</title></head>
        <h2>GOOGLE SUBSCRIBER INFORMATION</h2>
        <h3>IP ACTIVITY</h3>
        <table><tr><th>Timestamp</th><th>IP Address</th><th>Activity Type</th></tr>
        <tr><td>2025-08-19 02:48:23 Z</td><td>45.165.178.195</td><td>Login</td></tr>
        <tr><td>2025-08-18 20:20:20 Z</td><td>45.165.178.195</td><td>Login</td></tr>
        </table></html>"""
        df = parse_google_html(html, alvo='teste')
        self.assertEqual(len(df), 2)
        self.assertIn('Ip', df.columns)
        self.assertEqual(df.iloc[0]['Ip'], '45.165.178.195')
        self.assertEqual(df.iloc[0]['Alvo'], 'teste')

    def test_parse_whatsapp_html_model(self):
        from html_parser import parse_whatsapp_html

        model_path = os.path.join(ROOT_DIR, 'Modelos', 'WhatsApp', 'records.html')
        if os.path.exists(model_path):
            with open(model_path, 'r', encoding='utf-8') as handle:
                html = handle.read()
            df = parse_whatsapp_html(html, alvo='modelo_wa')
            self.assertGreater(len(df), 0)
            self.assertIn('Ip', df.columns)
            self.assertIn('Data', df.columns)
            self.assertIn('Periodo', df.columns)

    def test_parse_meta_html_model(self):
        from html_parser import parse_meta_html

        model_path = os.path.join(ROOT_DIR, 'Modelos', 'Meta Platforms', 'records.html')
        if os.path.exists(model_path):
            with open(model_path, 'r', encoding='utf-8') as handle:
                html = handle.read()
            df = parse_meta_html(html, alvo='modelo_meta')
            self.assertGreater(len(df), 0)
            self.assertIn('Porta', df.columns)

    def test_parse_google_html_model(self):
        from html_parser import parse_google_html
        import glob

        models = glob.glob(os.path.join(ROOT_DIR, 'Modelos', 'Google', '*.html'))
        if models:
            with open(models[0], 'r', encoding='utf-8') as handle:
                html = handle.read()
            df = parse_google_html(html, alvo='modelo_google')
            self.assertGreater(len(df), 0)
