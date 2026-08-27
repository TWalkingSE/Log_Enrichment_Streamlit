from tests.common import *


class TestIPValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertTrue(is_valid_ip('8.8.8.8'))
        self.assertTrue(is_valid_ip('198.51.100.15'))

    def test_valid_ipv6(self):
        self.assertTrue(is_valid_ip('2001:db8:8e90:866e:d4ba:a89a:bcd8:8dc7'))
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
        self.assertFalse(is_private_ip('198.51.100.15'))

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
        self.assertFalse(is_cgnat_ip('2001:db8:8e90:866e:d4ba:a89a:bcd8:8dc7'))


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
        ip, port = parse_meta_ip_port('198.51.100.10:22859')
        self.assertEqual(ip, '198.51.100.10')
        self.assertEqual(port, '22859')

    def test_ipv6_with_port(self):
        ip, port = parse_meta_ip_port('[2001:0db8:1354:6500:29a9:2a7f:ee68:d955]:59483')
        self.assertEqual(ip, '2001:0db8:1354:6500:29a9:2a7f:ee68:d955')
        self.assertEqual(port, '59483')

    def test_ip_without_port(self):
        ip, port = parse_meta_ip_port('198.51.100.15')
        self.assertEqual(ip, '198.51.100.15')
        self.assertEqual(port, '')

    def test_whitespace(self):
        ip, port = parse_meta_ip_port('  198.51.100.10:22859  ')
        self.assertEqual(ip, '198.51.100.10')
        self.assertEqual(port, '22859')


class TestFormatDetection(unittest.TestCase):
    def test_meta_format(self):
        content = "IP Addresses: IP addresses and source port/port numbers\nIP Address\n198.51.100.10:22859\nTime\n2025-09-29 11:15:01 UTC"
        self.assertEqual(detectar_formato_log(content), 'meta')

    def test_whatsapp_format(self):
        content = "IP addresses an account holder has connected from\nTime\n2025-12-10 18:58:48 UTC\nIP Address\n2001:db8:8e90:866e"
        self.assertEqual(detectar_formato_log(content), 'whatsapp')

    def test_google_format(self):
        content = "GOOGLE SUBSCRIBER INFORMATION\nIP ACTIVITY\nTimestamp   IP Address\n2023-02-25 04:34:32 Z   198.51.100.18"
        self.assertEqual(detectar_formato_log(content), 'google')

    def test_generic_format(self):
        content = "192.168.1.1\n10.0.0.1\n8.8.8.8"
        self.assertEqual(detectar_formato_log(content), 'generico')

    def test_tiktok_format(self):
        content = ("Events IP Data\nDate: 27/07/2026 03:04:43PM (UTC +00)\n"
                   "IP: 203.0.113.45\nEvent: video_play\nCountry: Brazil")
        self.assertEqual(detectar_formato_log(content), 'tiktok')

    def test_tiktok_format_by_footer(self):
        content = ("Date: 27/07/2026 03:04:43PM (UTC +00)\nIP: 203.0.113.45\n"
                   "Event: like\nCountry: Brazil\n1\nTikTok Pte. Limited")
        self.assertEqual(detectar_formato_log(content), 'tiktok')


class TestWhatsAppParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = """IP addresses an account holder has connected from
Time
2025-12-10 18:58:48 UTC
IP Address
198.51.100.15
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
198.51.100.10:22859
Time
2025-09-29 11:15:01 UTC
IP Address
[2001:0db8:1354:6500:29a9:2a7f:ee68:d955]:59483
Time
2025-09-21 23:01:39 UTC"""
        df = extrair_ips_do_formato_meta(content, alvo='meta_test')
        self.assertEqual(len(df), 2)
        self.assertIn('Porta', df.columns)
        self.assertEqual(df.iloc[0]['Porta'], '22859')


class TestTikTokParser(unittest.TestCase):
    def test_basic_parsing(self):
        df = extrair_ips_do_formato_tiktok(FORMATO_TIKTOK, alvo='tiktok_test')
        self.assertEqual(len(df), 3)
        self.assertIn('Evento', df.columns)
        self.assertIn('Ip', df.columns)
        self.assertIn('Data', df.columns)
        self.assertEqual(df.iloc[0]['Alvo'], 'tiktok_test')
        self.assertEqual(df.iloc[0]['Evento'], 'video_play')
        self.assertEqual(df.iloc[1]['Evento'], 'like')
        self.assertNotIn('Porta', df.columns)

    def test_evento_column_position(self):
        df = extrair_ips_do_formato_tiktok(FORMATO_TIKTOK, alvo='tiktok_test')
        cols = list(df.columns)
        self.assertEqual(cols.index('Evento'), cols.index('Ip') + 1)

    def test_utc_to_gmt3_with_ampm(self):
        # 03:04:43PM UTC = 15:04:43 UTC -> 12:04:43 no fuso GMT -03
        content = """Events IP Data
Date: 27/07/2026 03:04:43PM (UTC +00)
IP: 203.0.113.45
Event: video_play
Country: Brazil"""
        df = extrair_ips_do_formato_tiktok(content, alvo='test')
        self.assertEqual(len(df), 1)
        self.assertIn('12:04:43', df.iloc[0]['Data'])
        self.assertIn('2026-07-27', df.iloc[0]['Data'])

    def test_am_stays_morning(self):
        # 11:50:13AM UTC = 11:50:13 UTC -> 08:50:13 no fuso GMT -03
        content = """Date: 26/07/2026 11:50:13AM (UTC +00)
IP: 203.0.113.45
Event: message_notice_show
Country: Brazil"""
        df = extrair_ips_do_formato_tiktok(content, alvo='test')
        self.assertEqual(len(df), 1)
        self.assertIn('08:50:13', df.iloc[0]['Data'])

    def test_page_break_inside_record(self):
        # Rodapé de página intercalado no meio de um registro não pode quebrá-lo
        content = """Events IP Data
Date: 27/07/2026 03:04:23PM (UTC +00)
1
TikTok Pte. Limited
One Raffles Quay, #26-10, South Tower, Singapore 048583
IP: 203.0.113.45
Event: video_play
Country: Brazil
Date: 27/07/2026 03:04:17PM (UTC +00)
IP: 203.0.113.45
Event: like
Country: Brazil
2
TikTok Pte. Limited
One Raffles Quay, #26-10, South Tower, Singapore 048583"""
        df = extrair_ips_do_formato_tiktok(content, alvo='test')
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]['Evento'], 'video_play')
        self.assertEqual(df.iloc[1]['Evento'], 'like')

    def test_dedup_same_event_keeps_distinct_events(self):
        # Duplicata exata (mesmo IP+data+evento) é removida,
        # mas eventos diferentes no mesmo segundo são mantidos
        content = """Date: 27/07/2026 03:04:31PM (UTC +00)
IP: 203.0.113.45
Event: video_play
Country: Brazil
Date: 27/07/2026 03:04:31PM (UTC +00)
IP: 203.0.113.45
Event: video_play
Country: Brazil
Date: 27/07/2026 03:04:31PM (UTC +00)
IP: 203.0.113.45
Event: like
Country: Brazil"""
        df = extrair_ips_do_formato_tiktok(content, alvo='test')
        self.assertEqual(len(df), 2)
        self.assertEqual(sorted(df['Evento'].tolist()), ['like', 'video_play'])

    def test_periodo_and_iso_date(self):
        content = """Date: 27/07/2026 03:04:43PM (UTC +00)
IP: 203.0.113.45
Event: follow
Country: Brazil"""
        df = extrair_ips_do_formato_tiktok(content, alvo='test')
        self.assertEqual(df.iloc[0]['Periodo'], '☀️ Diurno')
        self.assertIsNotNone(df.iloc[0]['ISO_Date'])
        self.assertEqual(df.iloc[0]['Data_Fuso'], 'GMT -0300')

    def test_empty_content(self):
        df = extrair_ips_do_formato_tiktok("texto sem campos tiktok", alvo='test')
        self.assertEqual(len(df), 0)

    def test_real_pdf_eventsipdata(self):
        # Teste de integração com o PDF real do caso (se presente no repositório)
        pdf_path = os.path.join(ROOT_DIR, 'EventsIPData.pdf')
        if not os.path.exists(pdf_path):
            self.skipTest('EventsIPData.pdf não encontrado')
        try:
            import pdfplumber
        except ImportError:
            self.skipTest('pdfplumber não instalado')
        text_parts = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
        content = '\n'.join(text_parts)
        df = extrair_ips_do_formato_tiktok(content, alvo='caso_real')
        self.assertGreater(len(df), 0)
        self.assertIn('Evento', df.columns)
        for ip in df['Ip']:
            self.assertTrue(is_valid_ip(ip), f'Invalid IP: {ip}')
        # Todos os registros do documento são do mesmo IP
        self.assertIn('203.0.113.45', set(df['Ip']))


class TestGoogleParser(unittest.TestCase):
    def test_basic_parsing(self):
        df = extrair_ips_do_formato_google(FORMATO_4, alvo='google_test')
        self.assertGreater(len(df), 0)
        self.assertEqual(df.iloc[0]['Alvo'], 'google_test')
        for ip in df['Ip']:
            self.assertTrue(is_valid_ip(ip), f'Invalid IP: {ip}')


class TestSimpleParser(unittest.TestCase):
    def test_basic_parsing(self):
        content = "192.168.1.1\n8.8.8.8\n2001:db8:8e90:866e:d4ba:a89a:bcd8:8dc7"
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

    def test_tiktok_has_evento(self):
        self.assertIn('Evento', COLUNAS_EXPORT_TIKTOK)
        self.assertNotIn('Evento', COLUNAS_EXPORT)
        # Evento deve vir logo após Ip, como Porta na Meta
        self.assertEqual(
            COLUNAS_EXPORT_TIKTOK.index('Evento'),
            COLUNAS_EXPORT_TIKTOK.index('Ip') + 1
        )

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

        ip, port = _split_ip_port('198.51.100.19:1135')
        self.assertEqual(ip, '198.51.100.19')
        self.assertEqual(port, '1135')

    def test_split_ip_port_ipv6_with_port(self):
        from html_parser import _split_ip_port

        ip, port = _split_ip_port('[2001:db8:5413:9caf:e130:7b53:f760:b833]:63629')
        self.assertEqual(ip, '2001:db8:5413:9caf:e130:7b53:f760:b833')
        self.assertEqual(port, '63629')

    def test_split_ip_port_ipv4_no_port(self):
        from html_parser import _split_ip_port

        ip, port = _split_ip_port('198.51.100.17')
        self.assertEqual(ip, '198.51.100.17')
        self.assertEqual(port, '')

    def test_parse_google_html(self):
        from html_parser import parse_google_html

        html = """<html><head><title>Google Account</title></head>
        <h2>GOOGLE SUBSCRIBER INFORMATION</h2>
        <h3>IP ACTIVITY</h3>
        <table><tr><th>Timestamp</th><th>IP Address</th><th>Activity Type</th></tr>
        <tr><td>2025-08-19 02:48:23 Z</td><td>198.51.100.11</td><td>Login</td></tr>
        <tr><td>2025-08-18 20:20:20 Z</td><td>198.51.100.11</td><td>Login</td></tr>
        </table></html>"""
        df = parse_google_html(html, alvo='teste')
        self.assertEqual(len(df), 2)
        self.assertIn('Ip', df.columns)
        self.assertEqual(df.iloc[0]['Ip'], '198.51.100.11')
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


class TestQuebraDePaginaMetaWhatsApp(unittest.TestCase):
    """Meta e WhatsApp partem um campo ao meio na virada de página.

    O rótulo fica no fim de uma página com o valor vazio e o valor reaparece
    na página seguinte, num bloco sem rótulo dentro de um invólucro novo. Num
    documento real de 27 IPs isso fazia o parser entregar 25, um deles sem
    data — e o total do artefato não batia com o do documento de origem.
    """

    CAB = ('<html><head><title>Meta Platforms Business Record</title></head><body>'
           '<div id="property-ip_addresses" class="content-pane">')
    RODAPE = '</div></body></html>'

    @staticmethod
    def _campo(rotulo, valor):
        """Bloco normal: rótulo e valor na mesma página."""
        return ('<div class="t o"><div class="t i">%s<div class="m"><div>%s'
                '<div class="p"></div></div></div></div></div>' % (rotulo, valor))

    @staticmethod
    def _rotulo_orfao(rotulo):
        """Rótulo no fim da página, com o valor vazio."""
        return ('<div class="t o"><div class="t i">%s<div class="m"><div>'
                '</div></div></div></div>' % rotulo)

    @staticmethod
    def _valor_orfao(valor):
        """Valor reaberto na página seguinte, sem rótulo."""
        return ('<div class="t o"><div class="t i"><div class="m"><div>%s'
                '<div class="p"></div></div></div></div></div>' % valor)

    @staticmethod
    def _quebra(n, plataforma='Meta Platforms'):
        """A barra de virada de página mais o invólucro que ela abre."""
        return ('<div id="page_%d" class="pageBreak">%s Business Record Page %d</div>'
                '<div class="t o"><div class="t i"><div class="m"><div>' % (n, plataforma, n))

    FECHA_INVOLUCRO = '</div></div></div></div>'

    def test_valor_do_ip_na_pagina_seguinte(self):
        """`IP Address` sem valor, quebra, e o IP sozinho depois."""
        from html_parser import parse_meta_html

        html = (self.CAB
                + self._rotulo_orfao('IP Address')
                + self._quebra(2)
                + self._valor_orfao('198.51.100.1:1000')
                + self._campo('Time', '2026-03-26 12:19:10 UTC')
                + self.FECHA_INVOLUCRO + self.RODAPE)

        df = parse_meta_html(html, alvo='t')
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '198.51.100.1')
        self.assertEqual(df.iloc[0]['Porta'], '1000')
        self.assertEqual(df.iloc[0]['Data'], '2026-03-26 09:19:10')

    def test_valor_do_time_na_pagina_seguinte(self):
        """`Time` sem valor, quebra, e o timestamp sozinho depois.

        Era este o caso que entregava a linha com IP correto e `Data` vazia.
        """
        from html_parser import parse_meta_html

        html = (self.CAB
                + self._campo('IP Address', '203.0.113.5:2002')
                + self._rotulo_orfao('Time')
                + self._quebra(4)
                + self._valor_orfao('2026-03-18 15:45:52 UTC')
                + self.FECHA_INVOLUCRO + self.RODAPE)

        df = parse_meta_html(html, alvo='t')
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '203.0.113.5')
        self.assertEqual(df.iloc[0]['Porta'], '2002')
        self.assertEqual(df.iloc[0]['Data'], '2026-03-18 12:45:52')
        self.assertTrue(df.iloc[0]['ISO_Date'])

    def test_tres_quebras_nao_perdem_registro_nem_deslocam_horario(self):
        """Reproduz a forma do documento real: 5 IPs, 3 deles partidos.

        Perder um registro é grave; parear um IP com o horário de outro é
        pior, porque o artefato sai completo e errado.
        """
        from html_parser import parse_meta_html

        html = (self.CAB
                # 1 — IP partido na virada
                + self._rotulo_orfao('IP Address')
                + self._quebra(2)
                + self._valor_orfao('198.51.100.1:1000')
                + self._campo('Time', '2026-03-26 12:19:10 UTC')
                # 2 — par normal
                + self._campo('IP Address', '198.51.100.2:1001')
                + self._campo('Time', '2026-03-25 09:44:44 UTC')
                # 3 — Time partido na virada
                + self._campo('IP Address', '203.0.113.5:2002')
                + self._rotulo_orfao('Time')
                + self.FECHA_INVOLUCRO
                + self._quebra(3)
                + self._valor_orfao('2026-03-18 15:45:52 UTC')
                # 4 — par normal, IPv6
                + self._campo('IP Address',
                              '[2001:db8:7002:2cc3:1:0:dc0e:6452]:3003')
                + self._campo('Time', '2026-03-10 08:24:09 UTC')
                # 5 — IP partido na virada
                + self._rotulo_orfao('IP Address')
                + self.FECHA_INVOLUCRO
                + self._quebra(4)
                + self._valor_orfao('203.0.113.9:4004')
                + self._campo('Time', '2026-03-06 20:07:58 UTC')
                + self.FECHA_INVOLUCRO + self.RODAPE)

        df = parse_meta_html(html, alvo='t')

        esperado = [
            ('198.51.100.1', '1000', '2026-03-26 09:19:10'),
            ('198.51.100.2', '1001', '2026-03-25 06:44:44'),
            ('203.0.113.5', '2002', '2026-03-18 12:45:52'),
            ('2001:db8:7002:2cc3:1:0:dc0e:6452', '3003', '2026-03-10 05:24:09'),
            ('203.0.113.9', '4004', '2026-03-06 17:07:58'),
        ]
        self.assertEqual(len(df), len(esperado))
        obtido = [(r['Ip'], r['Porta'], r['Data']) for _, r in df.iterrows()]
        self.assertEqual(obtido, esperado)

    def test_documento_sem_quebra_nao_muda(self):
        """Controle: sem quebra, a leitura tem de continuar a mesma."""
        from html_parser import parse_meta_html

        html = (self.CAB
                + self._campo('IP Address', '198.51.100.7:5005')
                + self._campo('Time', '2026-02-27 12:07:28 UTC')
                + self.RODAPE)

        df = parse_meta_html(html, alvo='t')
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '198.51.100.7')
        self.assertEqual(df.iloc[0]['Porta'], '5005')
        self.assertEqual(df.iloc[0]['Data'], '2026-02-27 09:07:28')

    def test_definicao_da_secao_nao_vira_registro(self):
        """O bloco `Ip Addresses Definition` é texto corrido e não pode
        ser confundido com valor de campo nem consumir uma continuação."""
        from html_parser import parse_meta_html

        definicao = ('<div class="t o"><div class="t i">Ip Addresses Definition'
                     '<div class="m"><div>IP Addresses: IP addresses and source '
                     'port numbers.<div class="p"></div>Time: Date and timestamp.'
                     '<div class="p"></div></div></div></div></div>')
        html = (self.CAB + definicao
                + self._rotulo_orfao('IP Address')
                + self._quebra(2)
                + self._valor_orfao('198.51.100.1:1000')
                + self._campo('Time', '2026-03-26 12:19:10 UTC')
                + self.FECHA_INVOLUCRO + self.RODAPE)

        df = parse_meta_html(html, alvo='t')
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '198.51.100.1')

    def test_whatsapp_tambem_remenda_a_quebra(self):
        """Mesma estrutura, ordem invertida (`Time` -> `IP Address`)."""
        from html_parser import parse_whatsapp_html

        html = ('<html><head><title>WhatsApp Business Record</title></head><body>'
                '<div id="property-ip_addresses" class="content-pane">'
                + self._campo('Time', '2026-03-26 12:19:10 UTC')
                + self._rotulo_orfao('IP Address')
                + self._quebra(4, 'WhatsApp')
                + self._valor_orfao('198.51.100.1')
                + self.FECHA_INVOLUCRO + self.RODAPE)

        df = parse_whatsapp_html(html, alvo='t')
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '198.51.100.1')
        self.assertEqual(df.iloc[0]['Data'], '2026-03-26 09:19:10')


class TestWhatsAppPortaLogica(unittest.TestCase):
    """O WhatsApp hoje não entrega porta lógica; a Meta entrega, e a tendência
    é o WhatsApp seguir.

    O parser precisa atravessar essa virada sem perder registro: hoje a saída
    tem de continuar idêntica, e no dia em que a porta aparecer ela tem de ser
    preservada — é ela que identifica o assinante atrás de CGNAT.
    """

    CAB = ('<html><head><title>WhatsApp Business Record</title></head><body>'
           '<div id="property-ip_addresses" class="content-pane">')
    RODAPE = '</div></body></html>'

    @staticmethod
    def _par(ip, quando):
        """Par Time -> IP Address, na ordem em que o WhatsApp emite."""
        campo = ('<div class="t o"><div class="t i">%s<div class="m"><div>%s'
                 '<div class="p"></div></div></div></div></div>')
        return campo % ('Time', quando) + campo % ('IP Address', ip)

    def _parse(self, *pares):
        from html_parser import parse_whatsapp_html
        return parse_whatsapp_html(self.CAB + ''.join(pares) + self.RODAPE, alvo='t')

    # ---------- hoje ----------

    def test_formato_atual_nao_ganha_coluna_porta(self):
        """Sem porta no documento, nenhuma coluna nova pode aparecer: um laudo
        de hoje não pode passar a ter uma coluna vazia."""
        df = self._parse(self._par('198.51.100.1', '2026-03-26 12:19:10 UTC'),
                         self._par('198.51.100.2', '2026-03-25 09:44:44 UTC'))
        self.assertEqual(len(df), 2)
        self.assertNotIn('Porta', df.columns)
        self.assertEqual(list(df['Ip']), ['198.51.100.1', '198.51.100.2'])
        self.assertEqual(df.iloc[0]['Data'], '2026-03-26 09:19:10')

    def test_ipv6_sem_porta_continua_intacto(self):
        df = self._parse(self._par('2001:db8:7002:2cc3::1', '2026-03-25 09:44:44 UTC'))
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '2001:db8:7002:2cc3::1')
        self.assertNotIn('Porta', df.columns)

    # ---------- quando a porta chegar ----------

    def test_ip_com_porta_nao_e_mais_descartado(self):
        """Validar o valor bruto reprovava `IP:porta` e o registro sumia."""
        df = self._parse(self._par('203.0.113.7:12538', '2026-08-24 23:47:25 UTC'))
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '203.0.113.7')
        self.assertEqual(df.iloc[0]['Porta'], '12538')

    def test_ipv6_com_brackets_e_porta(self):
        df = self._parse(self._par('[2001:db8:7003:fe58::6d59:ce7a]:38098',
                                   '2026-03-03 12:26:04 UTC'))
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '2001:db8:7003:fe58::6d59:ce7a')
        self.assertEqual(df.iloc[0]['Porta'], '38098')

    def test_documento_misto_mantem_porta_onde_existe(self):
        """Na transição um mesmo documento pode ter registros dos dois jeitos.
        Nenhum dos dois pode ser perdido."""
        df = self._parse(self._par('198.51.100.1', '2026-03-26 12:19:10 UTC'),
                         self._par('203.0.113.7:12538', '2026-03-25 09:44:44 UTC'))
        self.assertEqual(len(df), 2)
        self.assertEqual(list(df['Ip']), ['198.51.100.1', '203.0.113.7'])
        self.assertEqual(list(df['Porta']), ['', '12538'])

    def test_porta_vem_logo_depois_do_ip_como_na_meta(self):
        """Mesma posição de coluna que o parser da Meta entrega, para os dois
        formatos se lerem igual no artefato final."""
        df = self._parse(self._par('203.0.113.7:12538', '2026-03-26 12:19:10 UTC'))
        colunas = list(df.columns)
        self.assertEqual(colunas[:3], ['Alvo', 'Ip', 'Porta'])

    def test_porta_sobrevive_a_quebra_de_pagina(self):
        """As duas correções têm de compor: o valor remendado da página
        seguinte ainda precisa passar pela separação da porta."""
        campo = ('<div class="t o"><div class="t i">%s<div class="m"><div>%s'
                 '<div class="p"></div></div></div></div></div>')
        rotulo_orfao = ('<div class="t o"><div class="t i">IP Address'
                        '<div class="m"><div></div></div></div></div>')
        quebra = ('<div id="page_4" class="pageBreak">WhatsApp Business Record Page 4</div>'
                  '<div class="t o"><div class="t i"><div class="m"><div>')
        valor_orfao = ('<div class="t o"><div class="t i"><div class="m"><div>'
                       '203.0.113.7:12538<div class="p"></div></div></div></div></div>')

        from html_parser import parse_whatsapp_html
        html = (self.CAB
                + campo % ('Time', '2026-08-24 23:47:25 UTC')
                + rotulo_orfao + quebra + valor_orfao
                + '</div></div></div></div>' + self.RODAPE)
        df = parse_whatsapp_html(html, alvo='t')

        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '203.0.113.7')
        self.assertEqual(df.iloc[0]['Porta'], '12538')
        self.assertEqual(df.iloc[0]['Data'], '2026-08-24 20:47:25')

    def test_ipv6_sem_brackets_nao_vira_porta_inventada(self):
        """`2001:db8:...:37229` é ambíguo: o último grupo tanto pode ser porta
        quanto parte do endereço. Meta e WhatsApp usam brackets quando há
        porta, então o valor inteiro é lido como endereço — chutar aqui
        inventaria dado que o documento não afirma."""
        from html_parser import _split_ip_port

        ip, porta = _split_ip_port('2001:db8:7002:2cc3:1:0:dc0e:6452')
        self.assertEqual(ip, '2001:db8:7002:2cc3:1:0:dc0e:6452')
        self.assertEqual(porta, '')


class TestInterceptacaoMerge(unittest.TestCase):
    """A fusão vetorizada deve ser indistinguível do laço por IP que substituiu."""

    from interception_parser import (  # noqa: E402
        processar_resultados_interceptacao as _merge,
    )
    _merge = staticmethod(_merge)

    COLS = ['Ip_Dono', 'Ip_AS', 'Ip_Regiao', 'Ip_Cidade', 'Ip_Pais', 'Ip_Pais_Codigo',
            'Ip_Movel', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Lat', 'Ip_Lon']

    @staticmethod
    def _reference(df, resultados_api):
        """Implementação anterior (laço + máscara por IP), mantida só no teste."""
        if not resultados_api:
            return df
        for ip, dados in resultados_api.items():
            status = dados.get('status', '')
            if status == 'success' or 'Ip_Dono' in dados:
                mask = df['Sender IP'] == ip
                dono = dados.get('Ip_Dono', dados.get('org', dados.get('isp', '')))
                if dono and not str(dono).startswith('Erro:'):
                    df.loc[mask, 'Ip_Dono'] = dono
                ip_as = dados.get('Ip_AS', dados.get('as', ''))
                if ip_as and ip_as != 'Erro':
                    df.loc[mask, 'Ip_AS'] = ip_as
                regiao = dados.get('Ip_Regiao', dados.get('regionName', ''))
                if regiao and regiao != 'Erro':
                    df.loc[mask, 'Ip_Regiao'] = regiao
                cidade = dados.get('Ip_Cidade', dados.get('city', ''))
                if cidade and cidade != 'Erro':
                    df.loc[mask, 'Ip_Cidade'] = cidade
                pais = dados.get('Ip_Pais', dados.get('country', ''))
                if pais and pais != 'Erro':
                    df.loc[mask, 'Ip_Pais'] = pais
                pais_codigo = dados.get('Ip_Pais_Codigo', dados.get('countryCode', ''))
                if pais_codigo:
                    df.loc[mask, 'Ip_Pais_Codigo'] = pais_codigo
                df.loc[mask, 'Ip_Movel'] = dados.get('Ip_Movel', dados.get('mobile', False))
                df.loc[mask, 'Ip_Proxy'] = dados.get('Ip_Proxy', dados.get('proxy', False))
                df.loc[mask, 'Ip_Hospedagem'] = dados.get('Ip_Hospedagem', dados.get('hosting', False))
                df.loc[mask, 'Ip_Lat'] = dados.get('Ip_Lat', dados.get('lat'))
                df.loc[mask, 'Ip_Lon'] = dados.get('Ip_Lon', dados.get('lon'))
        return df

    def _frame(self, n_ips=6, reps=3):
        ips = ['200.1.0.%d' % i for i in range(n_ips)]
        df = pd.DataFrame({'Sender IP': ips * reps})
        for c in self.COLS:
            df[c] = None
        return df

    def test_matches_reference_implementation(self):
        # Casos-limite: sucesso normal, provedor com prefixo 'Erro:', registro
        # incompleto, status de falha, formato cru vs normalizado, e um IP
        # retornado pela API que não existe no DataFrame.
        api = {
            '200.1.0.0': {'status': 'success', 'org': 'Vivo', 'as': 'AS1',
                          'regionName': 'BA', 'city': 'Salvador', 'country': 'Brazil',
                          'countryCode': 'BR', 'mobile': True, 'proxy': False,
                          'hosting': False, 'lat': -12.97, 'lon': -38.50},
            '200.1.0.1': {'status': 'success', 'Ip_Dono': 'Erro: quota', 'Ip_AS': 'Erro',
                          'Ip_Cidade': 'SP', 'Ip_Movel': False, 'Ip_Proxy': True,
                          'Ip_Hospedagem': False, 'Ip_Lat': -23.5, 'Ip_Lon': -46.6},
            '200.1.0.2': {'status': 'success', 'isp': 'Claro'},
            '200.1.0.3': {'status': 'fail', 'org': 'ignorar'},
            '200.1.0.4': {'Ip_Dono': 'Tim', 'Ip_Movel': False, 'Ip_Proxy': False,
                          'Ip_Hospedagem': False, 'Ip_Lat': None, 'Ip_Lon': None},
            '99.99.99.99': {'status': 'success', 'org': 'AusenteDoDataFrame'},
        }
        esperado = self._reference(self._frame(), api)
        obtido = self._merge(self._frame(), api)
        self.assertTrue(esperado.equals(obtido))

    def test_failed_status_is_skipped(self):
        api = {'200.1.0.0': {'status': 'fail', 'org': 'nao usar'}}
        out = self._merge(self._frame(), api)
        self.assertTrue(out['Ip_Dono'].isna().all())

    def test_empty_results_returns_frame(self):
        df = self._frame()
        self.assertIs(self._merge(df, {}), df)


class TestColunasExtrasProvedor(unittest.TestCase):
    from data_processor import processar_resultados as _proc  # noqa: E402
    _proc = staticmethod(_proc)

    """As colunas específicas de cada provedor (Porta no Meta, Evento no TikTok,
    User_Agent no Preservation Google) devem sobreviver ao merge da API e sair
    logo após 'Ip' — antes só 'Porta' era preservada, por nome fixo."""

    def _frame(self, **extras):
        base = {'Alvo': ['x'], 'Ip': ['8.8.8.8'], 'Data': ['2025-01-01 10:00:00']}
        base.update({k: [v] for k, v in extras.items()})
        return pd.DataFrame(base)

    def test_evento_preservado_e_posicionado(self):
        out = self._proc(self._frame(Evento='video_play'), {})
        self.assertIn('Evento', out.columns)
        cols = list(out.columns)
        self.assertEqual(cols.index('Evento'), cols.index('Ip') + 1)

    def test_porta_continua_preservada(self):
        out = self._proc(self._frame(Porta='443'), {})
        cols = list(out.columns)
        self.assertEqual(cols.index('Porta'), cols.index('Ip') + 1)

    def test_multiplas_extras_mantem_ordem_declarada(self):
        out = self._proc(self._frame(User_Agent='Mozilla', Porta='443'), {})
        cols = list(out.columns)
        # Ordem vem de COLUNAS_EXTRAS_PROVEDOR, não da ordem no DataFrame
        self.assertEqual(cols[cols.index('Ip') + 1], 'Porta')
        self.assertEqual(cols[cols.index('Ip') + 2], 'User_Agent')

    def test_sem_extras_retorna_modelo_padrao(self):
        out = self._proc(self._frame(), {})
        self.assertEqual(list(out.columns), list(COLUNAS_MODELO))
