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
