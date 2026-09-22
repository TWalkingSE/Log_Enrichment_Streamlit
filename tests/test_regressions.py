"""Regressões dos defeitos encontrados na auditoria técnica.

Cada classe cobre um bug confirmado em revisão de código — a suíte anterior
passava porque os caminhos defeituosos ficam em fallbacks e tipos mistos que
as fixtures não exercitavam.
"""
from tests.common import *
from unittest.mock import patch
from datetime import date

import file_handler
from export_ioc import build_stix_bundle, export_ioc_csv, export_ioc_list
from helpers.period_compare import period_kpis, slice_period
from validators import bool_series


class TestCsvEncodingFallback(unittest.TestCase):
    """`pd.read_csv(errors='replace')` lança TypeError no pandas 2.x — o
    parâmetro correto é `encoding_errors`. O fallback só roda quando os três
    encodings tentados falham, então fixtures UTF-8/Latin-1 nunca o atingiam.
    """

    def test_fallback_input_csv(self):
        real_read_csv = pd.read_csv
        calls = []

        def fake_read_csv(*args, **kwargs):
            calls.append(kwargs)
            if 'encoding_errors' not in kwargs:
                raise UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'simulado')
            kwargs = dict(kwargs)
            kwargs.pop('encoding_errors')
            return real_read_csv(*args, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, 'caso.csv')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('Ip,Data\n8.8.8.8,2025-01-01 10:00:00\n')
            with patch.object(pd, 'read_csv', side_effect=fake_read_csv):
                df = file_handler.carregar_arquivo_log(path)

        self.assertTrue(any('encoding_errors' in kw for kw in calls))
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Ip'], '8.8.8.8')


class TestPeriodoNaoFabricado(unittest.TestCase):
    """Registros sem data parseável ficavam rotulados '☀️ Diurno' — dado
    inventado num laudo. Agora `Periodo` fica vazio quando não há como
    derivar de `Data`."""

    def test_periodo_derivado_de_data(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, 'caso.csv')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('Ip,Data\n'
                         '8.8.8.8,2025-01-01 10:00:00\n'
                         '1.1.1.1,2025-01-01 23:00:00\n'
                         '9.9.9.9,data-invalida\n')
            df = file_handler.carregar_arquivo_log(path)

        self.assertEqual(len(df), 3)
        por_ip = dict(zip(df['Ip'], df['Periodo']))
        self.assertEqual(por_ip['8.8.8.8'], '☀️ Diurno')
        self.assertEqual(por_ip['1.1.1.1'], '🌙 Noturno')
        self.assertIsNone(por_ip['9.9.9.9'])


class TestCoercaoBooleana(unittest.TestCase):
    """`.astype(bool)`/`bool(x)` tratam '0', 'False' e 'FALSO' como True —
    um proxy real de CSV aparecia como residencial e vice-versa."""

    def _df_flags(self, proxy, hosting='0', movel='0'):
        return pd.DataFrame({
            'Ip': ['8.8.8.8'],
            'Data': ['2025-01-01 10:00:00'],
            'Ip_Proxy': [proxy],
            'Ip_Hospedagem': [hosting],
            'Ip_Movel': [movel],
        })

    def test_period_kpis_strings_falsas(self):
        df = pd.concat([self._df_flags('0'), self._df_flags('False'),
                        self._df_flags('FALSO'), self._df_flags('1')],
                       ignore_index=True)
        kpis = period_kpis(df)
        self.assertEqual(kpis['proxy_pct'], 25.0)
        self.assertEqual(kpis['hosting_pct'], 0.0)
        self.assertEqual(kpis['mobile_pct'], 0.0)

    def test_ioc_only_suspicious_strings(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
            'Ip_Proxy': ['0', '1', 'False'],
            'Ip_Hospedagem': ['0', '0', '0'],
        })
        suspeitos = export_ioc_list(df, only_suspicious=True).split()
        self.assertEqual(suspeitos, ['1.1.1.1'])

    def test_ioc_csv_flags_strings(self):
        df = self._df_flags('False')
        csv = export_ioc_csv(df)
        linha = [ln for ln in csv.strip().split('\n') if ln.startswith('8.8.8.8')][0]
        # proxy, hosting, mobile = últimas três colunas
        self.assertTrue(linha.endswith(',False,False,False'))

    def test_stix_labels_respeitam_strings_falsas(self):
        bundle = build_stix_bundle(self._df_flags('0'))
        indicator = next(o for o in bundle['objects'] if o['type'] == 'indicator')
        self.assertNotIn('proxy', indicator['labels'])
        self.assertIn('observed', indicator['labels'])

    def test_risk_score_string_false_nao_soma_40(self):
        # 1 ocorrência → +10 de baixa frequência; proxy NÃO pode somar 40.
        score = calculate_risk_scores(self._df_flags('False'))
        self.assertEqual(score.iloc[0]['Score'], 10)

    def test_risk_score_string_verdadeira_soma_40(self):
        score = calculate_risk_scores(self._df_flags('VERDADEIRO'))
        self.assertEqual(score.iloc[0]['Score'], 50)


class TestStixPatternEscape(unittest.TestCase):
    """IOC com aspa quebrava o literal do pattern STIX — indicadores
    malformados são preservados de propósito, então o escape é obrigatório."""

    def test_pattern_escapa_aspa(self):
        df = pd.DataFrame({'Ip': ["8.8.8.8' OR '1'='1"]})
        bundle = build_stix_bundle(df)
        indicator = next(o for o in bundle['objects'] if o['type'] == 'indicator')
        self.assertIn("\\'", indicator['pattern'])


class TestPeriodCompareDatas(unittest.TestCase):
    """slice_period usava format='mixed' (parser por elemento). Com
    parse_data, o formato canônico e os fora-de-padrão convivem."""

    def test_slice_period_formato_canonico(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8'] * 3,
            'Data': ['2025-01-01 10:00:00', '2025-06-15 10:00:00',
                     '15/07/2025 10:00:00'],
        })
        fatia = slice_period(df, date(2025, 6, 1), date(2025, 7, 31))
        self.assertEqual(len(fatia), 2)


if __name__ == '__main__':
    unittest.main()
