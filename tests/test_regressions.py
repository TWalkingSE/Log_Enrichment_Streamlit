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


class TestLaudoContaProxyEHostingUmaVez(unittest.TestCase):
    """Uma linha pode ser proxy e hosting ao mesmo tempo (ex.: 8.8.8.8).

    Somar as duas contagens fez um arquivo de 6 registros sair no laudo com
    "9 conexões via proxy/hosting".
    """

    @staticmethod
    def _df(proxy, hosting, movel=None):
        return pd.DataFrame({
            'Ip_Proxy': proxy, 'Ip_Hospedagem': hosting,
            'Ip_Movel': movel if movel is not None else [False] * len(proxy),
        })

    def test_achado_nao_passa_do_total_de_linhas(self):
        from html_report_generator import _build_findings
        df = self._df([True] * 3 + [False] * 3, [True] * 6)
        achados, proxy_n, hosting_n, _ = _build_findings(df, {}, 6)
        # As métricas individuais continuam contando cada categoria inteira.
        self.assertEqual((proxy_n, hosting_n), (3, 6))
        self.assertIn('Alto uso de anonimização (6 conexões via proxy/hosting)', achados)

    def test_achado_de_formato_agregado(self):
        from html_report_generator import _build_findings
        df = self._df([True] * 3 + [False] * 3, [True] * 6)
        achados, *_ = _build_findings(df, {}, 6, agregado='google_atividades')
        self.assertIn('Alto uso de anonimização (6 de 6 linhas com IP de proxy/hosting)', achados)

    def test_sobreposicao_nao_dispara_o_limite(self):
        from html_report_generator import _build_findings
        # 2 de 10 linhas (20%): a soma dava 40% e passava do limite de 30%.
        df = self._df([True] * 2 + [False] * 8, [True] * 2 + [False] * 8)
        achados, *_ = _build_findings(df, {}, 10)
        self.assertFalse([a for a in achados if 'anonimização' in a], achados)

    def test_valores_de_csv_e_excel(self):
        from html_report_generator import _build_findings
        df = self._df(['1', 'VERDADEIRO', '0', '0'], ['1', '0', 'FALSO', '0'])
        achados, *_ = _build_findings(df, {}, 4)
        self.assertIn('Alto uso de anonimização (2 conexões via proxy/hosting)', achados)

    @staticmethod
    def _fatias(df):
        from html_report_generator import _generate_connection_plot
        with patch('html_report_generator._plotly_to_div', side_effect=lambda fig, **_: fig):
            fig = _generate_connection_plot(df)
        return dict(zip(fig.data[0].labels, fig.data[0].values))

    def test_grafico_tem_uma_fatia_por_linha(self):
        df = self._df(
            [True, True, False, False, True] + [False] * 5,
            [True, True, True, False, False] + [False] * 5,
            [False, False, False, True, True] + [False] * 5,
        )
        self.assertEqual(self._fatias(df),
                         {'Residencial': 5, 'Móvel': 1, 'Proxy/VPN': 3, 'Hosting': 1})

    def test_grafico_nao_reduz_residencial_por_sobreposicao(self):
        df = self._df([True] * 4 + [False] * 6, [True] * 4 + [False] * 6)
        fatias = self._fatias(df)
        self.assertEqual(fatias['Residencial'], 6)
        self.assertEqual(sum(fatias.values()), len(df))

    def test_laudo_gerado_declara_a_contagem_correta(self):
        df = self._df([True] * 3 + [False] * 3, [True] * 6).assign(
            Ip=['198.51.100.1'] * 3 + ['203.0.113.1'] * 3,
            Data=[f'2025-09-2{i} 10:00:00' for i in range(6)],
            Ip_Pais='US', Ip_Regiao='CA', Ip_Cidade='LA', Ip_Dono='Provedor', Periodo='Diurno',
        )
        html = generate_html_report(df, 'alvo').decode('utf-8')
        self.assertIn('Alto uso de anonimização (6 conexões via proxy/hosting)', html)
        self.assertNotIn('9 conexões', html)

    def test_grafico_sem_classificacao_nao_afirma_residencial(self):
        from html_report_generator import _generate_connection_plot
        self.assertEqual(_generate_connection_plot(pd.DataFrame({'Ip': ['198.51.100.1']})), '')


if __name__ == '__main__':
    unittest.main()
