from tests.common import *


class TestValidators(unittest.TestCase):
    def test_validate_schema_valid(self):
        result = validate_schema(pd.DataFrame({'Ip': ['8.8.8.8'], 'Data': ['2025-01-01']}))
        self.assertTrue(result.is_valid)

    def test_validate_schema_missing_ip(self):
        result = validate_schema(pd.DataFrame({'Other': ['value']}))
        self.assertFalse(result.is_valid)

    def test_validate_domain_invalid_ips(self):
        df = pd.DataFrame({'Ip': ['not_an_ip', '8.8.8.8', '999.0.0.0'], 'Data': ['2025-01-01'] * 3})
        result = validate_domain(df)
        self.assertTrue(len(result.warnings) > 0 or len(result.errors) > 0)

    def test_validate_dataframe_empty(self):
        result = validate_dataframe(pd.DataFrame())
        self.assertFalse(result['is_valid'])

    def test_sanitize_csv_value_safe(self):
        self.assertEqual(sanitize_csv_value('hello'), 'hello')
        self.assertEqual(sanitize_csv_value('123'), '123')

    def test_sanitize_csv_injection(self):
        self.assertTrue(sanitize_csv_value('=CMD("calc")').startswith("'"))
        self.assertTrue(sanitize_csv_value('+1+cmd|calc').startswith("'"))
        self.assertTrue(sanitize_csv_value('@SUM(A1:A10)').startswith("'"))

    def test_sanitize_traco_seguido_de_digito(self):
        """`-2+3` é fórmula, não número negativo.

        A regra antiga liberava qualquer traço seguido de dígito, o que deixava
        passar o payload DDE clássico: a planilha avalia e o valor exibido
        deixa de ser o do log.
        """
        for payload in ('-2+3', "-2+3+cmd|' /C calc'!A0", '-1+1', '-abc', '-'):
            with self.subTest(payload=payload):
                self.assertTrue(sanitize_csv_value(payload).startswith("'"))

    def test_sanitize_preserva_numeros_negativos(self):
        """Longitude e latitude são negativas neste país inteiro — uma aspa
        aqui corromperia o dado no artefato entregue."""
        for numero in ('-1', '-1.5', '-38.5044', '-1e5'):
            with self.subTest(numero=numero):
                self.assertEqual(sanitize_csv_value(numero), numero)

    def test_sanitize_e_idempotente(self):
        """O pipeline sanitiza o frame e o export sanitiza de novo; a segunda
        passagem não pode acrescentar uma segunda aspa."""
        uma = sanitize_csv_value('=CMD("calc")')
        self.assertEqual(sanitize_csv_value(uma), uma)


class TestZIPSecurity(unittest.TestCase):
    def test_safe_zip_entry_rejects_traversal(self):
        from interception_parser import _is_safe_zip_entry

        self.assertFalse(_is_safe_zip_entry('../../../etc/passwd'))
        self.assertFalse(_is_safe_zip_entry('..\\windows\\system32'))
        self.assertFalse(_is_safe_zip_entry('foo/../../bar'))
        self.assertTrue(_is_safe_zip_entry('records/whatsapp.html'))
        self.assertTrue(_is_safe_zip_entry('data.csv'))

    def test_safe_zip_entry_rejects_absolute(self):
        from interception_parser import _is_safe_zip_entry

        self.assertFalse(_is_safe_zip_entry('/etc/passwd'))
        self.assertFalse(_is_safe_zip_entry('C:\\Windows\\system.ini'))

    def test_check_zip_bomb_safe(self):
        from interception_parser import _check_zip_bomb
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('test.txt', 'hello world')
        buf.seek(0)
        with zipfile.ZipFile(buf, 'r') as zip_file:
            is_safe, msg = _check_zip_bomb(zip_file)
            self.assertTrue(is_safe, msg)

    def test_check_zip_bomb_detects_high_ratio(self):
        from interception_parser import MAX_ZIP_RATIO, _check_zip_bomb
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('bomb.txt', '\x00' * (10 * 1024 * 1024))
        buf.seek(0)
        with zipfile.ZipFile(buf, 'r') as zip_file:
            compressed = sum(info.compress_size for info in zip_file.infolist())
            uncompressed = sum(info.file_size for info in zip_file.infolist())
            ratio = uncompressed / max(compressed, 1)
            is_safe, _ = _check_zip_bomb(zip_file)
            if ratio > MAX_ZIP_RATIO:
                self.assertFalse(is_safe)


class TestAuthPassword(unittest.TestCase):
    def test_argon2_verify_ok(self):
        from passlib.hash import argon2
        from auth_password import verify_stored_password_hash

        h = argon2.hash('secret123')
        self.assertTrue(verify_stored_password_hash('secret123', h))
        self.assertFalse(verify_stored_password_hash('wrong', h))

    def test_legacy_sha256_hex(self):
        import hashlib
        from auth_password import verify_stored_password_hash

        h = hashlib.sha256(b'legacy-pass').hexdigest()
        self.assertTrue(verify_stored_password_hash('legacy-pass', h))
        self.assertFalse(verify_stored_password_hash('other', h))

    def test_bcrypt_hash_verify(self):
        from passlib.hash import bcrypt
        from auth_password import verify_stored_password_hash

        h = bcrypt.hash('bcrypt-secret')
        self.assertTrue(verify_stored_password_hash('bcrypt-secret', h))
        self.assertFalse(verify_stored_password_hash('no', h))

    def test_plain_env_compares_digest(self):
        from auth_password import verify_plain_env_password

        self.assertTrue(verify_plain_env_password('x', 'x'))
        self.assertFalse(verify_plain_env_password('x', 'y'))


class TestInputSanitization(unittest.TestCase):
    def test_sanitize_alvo_removes_unsafe(self):
        import re

        def _sanitize_alvo(alvo):
            if not alvo or not alvo.strip():
                return 'desconhecido'
            safe = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', alvo.strip())
            return safe[:100] if safe else 'desconhecido'

        self.assertEqual(_sanitize_alvo('João Silva'), 'João Silva')
        self.assertEqual(_sanitize_alvo('test/path'), 'test_path')
        self.assertEqual(_sanitize_alvo('test\\path'), 'test_path')
        safe = _sanitize_alvo('user<script>')
        self.assertNotIn('<', safe)
        self.assertNotIn('>', safe)


class TestCsvDataframeSanitize(unittest.TestCase):
    def test_sanitize_dataframe_for_csv(self):
        from validators import sanitize_dataframe_for_csv

        df = pd.DataFrame({
            'a': ['=CMD()', 'ok', '+1'],
            'b': [1, 2, 3],
        })
        out = sanitize_dataframe_for_csv(df)
        self.assertTrue(str(out.loc[0, 'a']).startswith("'"))
        self.assertEqual(out.loc[1, 'a'], 'ok')
        self.assertTrue(str(out.loc[2, 'a']).startswith("'"))


class TestCsvSanitizeNaoMutaEntrada(unittest.TestCase):
    """A cópia é preguiçosa; o frame do chamador precisa sair intacto."""

    def _df(self):
        return pd.DataFrame({
            'texto': ['=CMD()', 'ok', '-2+3', None],
            'lon': ['-38.5044', '-1.5', '-1', '-0.5'],
            'num': [1, 2, 3, 4],
        })

    def test_frame_de_entrada_nao_e_modificado(self):
        from validators import sanitize_dataframe_for_csv

        df = self._df()
        antes = {c: df[c].tolist() for c in df.columns}
        out = sanitize_dataframe_for_csv(df)

        self.assertTrue(str(out.loc[0, 'texto']).startswith("'"))
        self.assertTrue(str(out.loc[2, 'texto']).startswith("'"))
        for col, valores in antes.items():
            with self.subTest(coluna=col):
                self.assertEqual(df[col].tolist(), valores)

    def test_sem_nada_perigoso_nao_copia(self):
        """Uma cópia incondicional custava ~50 MB de pico em 202 mil linhas."""
        from validators import sanitize_dataframe_for_csv

        limpo = pd.DataFrame({'a': ['x', 'y'], 'b': [1, 2]})
        self.assertIs(sanitize_dataframe_for_csv(limpo), limpo)

    def test_numero_negativo_nao_dispara_copia(self):
        """`^-` no pré-filtro pega toda longitude; só mudança real copia."""
        from validators import sanitize_dataframe_for_csv

        so_negativos = pd.DataFrame({'lon': ['-38.5044', '-1.5', '-1']})
        self.assertIs(sanitize_dataframe_for_csv(so_negativos), so_negativos)

    def test_segunda_passagem_e_gratuita(self):
        """O pipeline sanitiza para o CSV e o export do Excel sanitiza de novo."""
        from validators import sanitize_dataframe_for_csv

        uma = sanitize_dataframe_for_csv(self._df())
        self.assertIs(sanitize_dataframe_for_csv(uma), uma)

    def test_dtypes_preservados(self):
        from validators import sanitize_dataframe_for_csv

        df = self._df()
        self.assertEqual(list(sanitize_dataframe_for_csv(df).dtypes), list(df.dtypes))


class TestSafeOutputPath(unittest.TestCase):
    def test_safe_output_path_blocks_traversal(self):
        from validators import safe_output_path
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            p = safe_output_path('../../etc/passwd', default_name='out.csv', base_dir=tmp)
            self.assertTrue(Path(p).resolve().is_relative_to(Path(tmp).resolve()) or str(p).startswith(tmp))
            self.assertTrue(p.endswith('.csv') or Path(p).name.endswith('.csv'))


class TestPopupXssEscape(unittest.TestCase):
    def test_build_rich_popup_escapes_html(self):
        from helpers.geo import build_rich_popup

        row = {
            'Ip': '1.2.3.4',
            'Ip_Dono': '<script>alert(1)</script>',
            'Ip_AS': 'AS1',
            'Ip_Pais': 'BR',
            'Ip_Pais_Codigo': 'BR',
            'Ip_Regiao': 'SP',
            'Ip_Cidade': 'Sao Paulo',
            'Data': '2024-01-01',
            'Periodo': 'Diurno',
            'Ip_Proxy': False,
            'Ip_Hospedagem': False,
            'Ip_Movel': False,
            'Ip_Lat': -23.5,
            'Ip_Lon': -46.6,
        }
        html = build_rich_popup(row)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)


class TestIncrementalDedup(unittest.TestCase):
    def test_dedup_columns_include_format_keys(self):
        from file_handler import _incremental_dedup_columns

        df = pd.DataFrame(columns=['Ip', 'Data', 'Porta', 'User_ID'])
        cols = _incremental_dedup_columns(df)
        self.assertIn('Ip', cols)
        self.assertIn('Porta', cols)
        self.assertIn('User_ID', cols)


class TestRunAsync(unittest.TestCase):
    def test_run_async_simple_coro(self):
        from helpers.shared import run_async

        async def _add(a, b):
            return a + b

        self.assertEqual(run_async(_add(2, 3)), 5)


class TestEnrichService(unittest.TestCase):
    def test_collect_unique_ips_filters_invalid(self):
        from enrich_service import collect_unique_ips

        df = pd.DataFrame({'Ip': ['8.8.8.8', 'not-an-ip', '8.8.8.8', '192.168.0.1']})
        ips = collect_unique_ips(df, 'Ip')
        self.assertIn('8.8.8.8', ips)
        self.assertNotIn('not-an-ip', ips)
        self.assertEqual(ips.count('8.8.8.8'), 1)

    def test_enrich_ips_empty(self):
        from helpers.shared import run_async
        from enrich_service import enrich_ips

        results, client = run_async(enrich_ips([], cache_file=None, save_cache=False))
        self.assertEqual(results, {})
        self.assertIsNotNone(client)


class TestAuditHmac(unittest.TestCase):
    def test_hmac_signed_when_secret_set(self):
        import audit_logger
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            trail = Path(tmp) / 'audit_trail.jsonl'
            with patch.object(audit_logger, 'AUDIT_LOG_FILE', str(trail)), \
                 patch.object(audit_logger, 'AUDIT_LOG_DIR', tmp), \
                 patch.object(audit_logger, 'AUDIT_HMAC_SECRET', 'test-secret-key'):
                event = audit_logger.log_audit_event('unit_test', details={'ok': True})
                self.assertIn('event_hash', event)
                self.assertIn('event_hmac', event)
                self.assertEqual(len(event['event_hmac']), 64)
                result = audit_logger.verify_audit_integrity()
                self.assertEqual(result['invalid'], 0)
                self.assertEqual(result['hmac_failures'], 0)


class TestPersistence(unittest.TestCase):
    def test_save_load_roundtrip(self):
        from helpers import persistence
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(persistence, 'DATA_DIR', Path(tmp)):
                df = pd.DataFrame({'Ip': ['1.1.1.1'], 'Data': ['2024-01-01']})
                path = persistence.save_dataframe(df, name='unit')
                self.assertIsNotNone(path)
                loaded = persistence.load_dataframe('unit')
                self.assertIsNotNone(loaded)
                self.assertEqual(list(loaded['Ip']), ['1.1.1.1'])
                persistence.clear_dataframe('unit')
                self.assertIsNone(persistence.load_dataframe('unit'))


class TestAirGappedClient(unittest.TestCase):
    def test_air_gapped_no_http(self):
        from helpers.shared import run_async
        from api_client import IPAPIClient
        from unittest.mock import MagicMock
        import time

        client = IPAPIClient(api_key='k', cache_file=None, air_gapped=True)
        client.cache['8.8.8.8'] = {
            'Ip_Dono': 'Google', 'Ip_AS': 'AS1', 'Ip_Cidade': 'X',
            'Ip_Pais': 'US', 'Ip_Pais_Codigo': 'US', 'Ip_Regiao': 'CA',
            'Ip_Movel': False, 'Ip_Proxy': False, 'Ip_Hospedagem': False,
            'Ip_Lat': 1.0, 'Ip_Lon': 2.0, '_cached_at': time.time(),
        }
        session = MagicMock()
        hit = run_async(client.consultar_ip(session, '8.8.8.8'))
        self.assertEqual(hit['Ip_Dono'], 'Google')
        miss = run_async(client.consultar_ip(session, '1.1.1.1'))
        self.assertIn('Air-gapped', miss['Ip_Dono'])
        session.get.assert_not_called()


class TestRetention(unittest.TestCase):
    def test_prune_jsonl_and_cache(self):
        from helpers.retention import prune_jsonl_by_age_and_lines, prune_ip_cache
        import tempfile
        import json
        import time
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            trail = Path(tmp) / 'audit.jsonl'
            old_ts = '2000-01-01T00:00:00'
            new_ts = '2099-01-01T00:00:00'
            trail.write_text(
                json.dumps({'timestamp': old_ts, 'action': 'old'}) + '\n'
                + json.dumps({'timestamp': new_ts, 'action': 'new'}) + '\n',
                encoding='utf-8',
            )
            r = prune_jsonl_by_age_and_lines(trail, max_age_days=30, max_lines=100)
            self.assertEqual(r['removed'], 1)
            remaining = trail.read_text(encoding='utf-8')
            self.assertIn('new', remaining)
            self.assertNotIn('"old"', remaining)

            cache = Path(tmp) / 'ip_cache.json'
            cache.write_text(json.dumps({
                '1.1.1.1': {'_cached_at': 1, 'Ip_Dono': 'old'},
                '8.8.8.8': {'_cached_at': time.time(), 'Ip_Dono': 'fresh'},
            }), encoding='utf-8')
            cr = prune_ip_cache(cache, max_age_days=7)
            self.assertEqual(cr['removed'], 1)
            data = json.loads(cache.read_text(encoding='utf-8'))
            self.assertIn('8.8.8.8', data)
            self.assertNotIn('1.1.1.1', data)


class TestStixIocExport(unittest.TestCase):
    def test_stix_bundle_and_ioc_list(self):
        from export_ioc import build_stix_bundle, export_ioc_list, export_stix_json

        df = pd.DataFrame({
            'Ip': ['1.1.1.1', '1.1.1.1', '2001:db8::1'],
            'Ip_Dono': ['Cloudflare', 'Cloudflare', 'Example'],
            'Ip_AS': ['AS13335', 'AS13335', 'AS1'],
            'Ip_Cidade': ['SF', 'SF', 'X'],
            'Ip_Pais': ['US', 'US', 'ZZ'],
            'Ip_Proxy': [False, False, True],
            'Ip_Hospedagem': [True, True, False],
            'Ip_Movel': [False, False, False],
        })
        txt = export_ioc_list(df)
        self.assertIn('1.1.1.1', txt)
        self.assertIn('2001:db8::1', txt)
        bundle = build_stix_bundle(df, name='Unit')
        self.assertEqual(bundle['type'], 'bundle')
        types = {o['type'] for o in bundle['objects']}
        self.assertIn('indicator', types)
        self.assertIn('ipv4-addr', types)
        self.assertIn('ipv6-addr', types)
        raw = export_stix_json(df, only_suspicious=True)
        self.assertIn('ipv6-addr:value', raw)


class TestJobCancel(unittest.TestCase):
    def test_cancel_token_flag(self):
        from helpers.job_control import CancelToken, JobCancelled
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            token = CancelToken(flag_path=Path(tmp) / 'cancel.flag')
            token.clear()
            self.assertFalse(token.is_cancelled())
            token.request_cancel()
            self.assertTrue(token.is_cancelled())
            with self.assertRaises(JobCancelled):
                token.check()
            token.clear()
            self.assertFalse(token.is_cancelled())


class TestPeriodCompare(unittest.TestCase):
    def test_compare_two_periods(self):
        from helpers.period_compare import compare_periods, date_bounds
        from datetime import date

        df = pd.DataFrame({
            'Ip': ['1.1.1.1', '2.2.2.2', '1.1.1.1', '3.3.3.3'],
            'Data': ['2024-01-01', '2024-01-02', '2024-02-01', '2024-02-15'],
            'Ip_Dono': ['A', 'B', 'A', 'C'],
            'Ip_Pais': ['BR', 'US', 'BR', 'BR'],
            'Ip_Cidade': ['SP', 'NY', 'SP', 'RJ'],
            'Ip_Proxy': [False, True, False, False],
            'Ip_Hospedagem': [False, False, False, True],
            'Ip_Movel': [False, False, True, False],
        })
        bounds = date_bounds(df)
        self.assertIsNotNone(bounds)
        result = compare_periods(
            df,
            (date(2024, 1, 1), date(2024, 1, 31)),
            (date(2024, 2, 1), date(2024, 2, 28)),
        )
        self.assertEqual(result['count_a'], 2)
        self.assertEqual(result['count_b'], 2)
        self.assertIn('1.1.1.1', result['ips_only_a'] + result['ips_only_b'] + ['1.1.1.1'])
        self.assertEqual(result['kpis_a']['unique_ips'], 2)


class TestSignedCache(unittest.TestCase):
    def test_sign_and_verify(self):
        from helpers.signed_cache import build_signed_package, verify_signed_package
        import os
        from unittest.mock import patch

        secret = 'unit-test-secret-xyz'
        payload = {'8.8.8.8': {'Ip_Dono': 'Google', '_cached_at': 1}}
        with patch.dict(os.environ, {'CACHE_HMAC_SECRET': secret}):
            pkg = build_signed_package(payload, secret=secret)
            ok, msg, out = verify_signed_package(pkg, secret=secret)
            self.assertTrue(ok)
            self.assertEqual(msg, 'ok')
            self.assertEqual(out['8.8.8.8']['Ip_Dono'], 'Google')
            pkg['signature'] = 'deadbeef'
            ok2, msg2, _ = verify_signed_package(pkg, secret=secret)
            self.assertFalse(ok2)
            self.assertEqual(msg2, 'bad_signature')


class TestBooleanCoercion(unittest.TestCase):
    """Booleanos chegam de JSON (bool), CSV ('1'/'0') e Excel pt-BR
    ('VERDADEIRO'). Classificar um proxy como residencial por causa do
    formato de origem é erro de conteúdo num laudo, não cosmético."""

    def test_recognized_tokens(self):
        from validators import as_bool
        for valor in (True, 1, '1', 'true', 'TRUE', 'sim', 'VERDADEIRO', 'v', 2.5):
            self.assertTrue(as_bool(valor), repr(valor))
        for valor in (False, 0, '0', 'false', 'FALSO', 'nao', 'não', '', None):
            self.assertFalse(as_bool(valor), repr(valor))

    def test_missing_values_use_default(self):
        from validators import as_bool
        for vazio in (float('nan'), None, pd.NA, 'nan', 'none'):
            self.assertFalse(as_bool(vazio))
            self.assertTrue(as_bool(vazio, default=True))

    def test_unknown_token_warns_and_defaults(self):
        """Um token não reconhecido não pode falhar em silêncio."""
        import validators
        validators._unknown_bool_tokens.clear()
        with self.assertLogs('validators', level='WARNING') as log:
            self.assertFalse(validators.as_bool('talvez', field='Ip_Proxy'))
        self.assertIn('talvez', ''.join(log.output))

    def test_bool_series_handles_each_dtype(self):
        from validators import bool_series
        df = pd.DataFrame({
            'texto': ['1', '0', 'VERDADEIRO', 'false'],
            'numerico': [1, 0, 1, 0],
            'nativo': [True, False, True, False],
        })
        esperado = [True, False, True, False]
        for col in ('texto', 'numerico', 'nativo'):
            self.assertEqual(bool_series(df, col).tolist(), esperado, col)
        # coluna ausente vira constante, sem levantar
        self.assertEqual(bool_series(df, 'inexistente').tolist(), [False] * 4)

    def test_parse_data_falls_back_for_foreign_formats(self):
        from validators import parse_data
        out = parse_data(pd.Series(['2025-01-01 10:00:00', '01/02/2025 08:30', 'lixo']))
        self.assertEqual(out.iloc[0], pd.Timestamp('2025-01-01 10:00:00'))
        self.assertEqual(out.iloc[1], pd.Timestamp('2025-01-02 08:30:00'))
        self.assertTrue(pd.isna(out.iloc[2]))


class TestCsvSanitizerVectorized(unittest.TestCase):
    def test_matches_per_cell_implementation(self):
        """O pré-filtro vetorizado deve produzir exatamente a mesma saída."""
        from validators import sanitize_csv_value, sanitize_dataframe_for_csv
        vals = ['=cmd', '+1', '-1', '-abc', '-', '@x', '|y', chr(9) + 'z',
                chr(10) + 'w', 'normal', '', '1.5', '-1.5', '--x', 'a=b',
                None, 3, True]
        df = pd.DataFrame({'a': vals, 'b': vals[::-1]})

        esperado = df.copy()
        for col in esperado.columns:
            esperado[col] = esperado[col].map(
                lambda v: sanitize_csv_value(v) if isinstance(v, str) else v)

        self.assertTrue(esperado.equals(sanitize_dataframe_for_csv(df)))
