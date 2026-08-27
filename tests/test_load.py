"""
Teste de carga: exercita o caminho completo (análises -> relatório -> exports)
sobre um DataFrame do tamanho real dos casos que quebraram em produção.

Todo defeito corrigido na campanha de endurecimento — o `bad allocation` do
DBSCAN, os exports que estouravam a memória, o grafo com centenas de milhares
de arestas duplicadas — teria sido detectado aqui. Testes com 3 linhas não
detectam complexidade O(n^2).

Marcado como `slow`: roda no CI e localmente com `pytest -m slow`.
Para pular durante o desenvolvimento: `pytest -m "not slow"`.
"""

import time
import unittest

import numpy as np
import pandas as pd
import pytest

from analysis import (
    analyze_provider_timing,
    analyze_subnet_patterns,
    calculate_risk_scores,
    classify_dataframe,
    compute_ip_confidence,
    detect_base_locations,
    detect_digital_silence,
    detect_impossible_jumps,
    detect_life_patterns,
    detect_vpn_heuristics,
    generate_behavioral_profile,
    validate_timezone_consistency,
)

# Tamanho do caso real que motivou a correção.
N_LINHAS = 202_128
# Geolocalização por IP produz poucas coordenadas distintas mesmo com
# milhares de IPs — é exatamente essa razão que torna o DBSCAN tratável.
N_COORDS = 59
N_IPS = 4_319

# Teto de tempo por etapa. Generoso o bastante para não falhar por variação de
# máquina, apertado o bastante para pegar uma regressão de complexidade: a
# versão com bug levava minutos e então esgotava a memória.
LIMITE_SEGUNDOS = 120


def _frame_grande(n=N_LINHAS, seed=11):
    """DataFrame com o formato e a cardinalidade dos dados reais."""
    rng = np.random.default_rng(seed)
    lats = -12.97 + rng.normal(0, 0.3, N_COORDS).round(4)
    lons = -38.50 + rng.normal(0, 0.3, N_COORDS).round(4)
    idx_coord = rng.integers(0, N_COORDS, n)
    idx_ip = rng.integers(0, N_IPS, n)
    return pd.DataFrame({
        'Alvo': 'alvo_teste',
        'Ip': ['200.%d.%d.%d' % (i // 65536 % 256, i // 256 % 256, i % 256)
               for i in idx_ip],
        'Ip_Lat': lats[idx_coord],
        'Ip_Lon': lons[idx_coord],
        'Ip_Cidade': ['Cidade%d' % (i % 12) for i in idx_coord],
        'Ip_Regiao': 'BA',
        'Ip_Pais': 'Brazil',
        'Ip_Dono': ['Provedor%d' % (i % 38) for i in idx_ip],
        'Ip_AS': ['AS%d' % (i % 38) for i in idx_ip],
        'Data': pd.date_range('2025-01-01', periods=n,
                              freq='2min').strftime('%Y-%m-%d %H:%M:%S'),
        # Booleanos como string: o formato que vem de CSV/Excel e que a
        # coerção antiga classificava erroneamente como residencial.
        'Ip_Proxy': ['1' if i % 17 == 0 else '0' for i in range(n)],
        'Ip_Hospedagem': ['VERDADEIRO' if i % 31 == 0 else 'FALSO' for i in range(n)],
        'Ip_Movel': ['1' if i % 3 == 0 else '0' for i in range(n)],
    })


@pytest.mark.slow
class TestCargaAnalises(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = _frame_grande()

    def _cronometrar(self, nome, fn, *args, **kwargs):
        inicio = time.perf_counter()
        resultado = fn(*args, **kwargs)
        decorrido = time.perf_counter() - inicio
        self.assertLess(
            decorrido, LIMITE_SEGUNDOS,
            "%s levou %.1fs em %d linhas — provável regressão de complexidade"
            % (nome, decorrido, len(self.df)))
        return resultado

    def test_life_patterns_nao_estoura_memoria(self):
        """Regressão do `bad allocation`: DBSCAN haversine sobre as linhas
        brutas tem custo de memória O(n^2) e derrubava o processo."""
        r = self._cronometrar('detect_life_patterns', detect_life_patterns, self.df)
        self.assertTrue(r['has_data'])
        self.assertEqual(r['n_unique_coords'], N_COORDS)
        # Nenhum registro pode desaparecer entre clusters e ruído.
        total = sum(c['count'] for c in r['clusters']) + r['routine_deviations_total']
        self.assertEqual(total, len(self.df))

    def test_analises_do_relatorio(self):
        """As sete análises que rodavam sem proteção na página de relatório."""
        for nome, fn, kwargs in (
            ('calculate_risk_scores', calculate_risk_scores, {'ip_col': 'Ip'}),
            ('detect_impossible_jumps', detect_impossible_jumps, {}),
            ('detect_base_locations', detect_base_locations, {}),
            ('generate_behavioral_profile', generate_behavioral_profile, {'alvo': 'x'}),
            ('detect_vpn_heuristics', detect_vpn_heuristics, {}),
            ('compute_ip_confidence', compute_ip_confidence, {}),
            ('detect_digital_silence', detect_digital_silence, {}),
            ('analyze_subnet_patterns', analyze_subnet_patterns, {}),
            ('validate_timezone_consistency', validate_timezone_consistency, {}),
            ('analyze_provider_timing', analyze_provider_timing, {}),
        ):
            with self.subTest(analise=nome):
                self._cronometrar(nome, fn, self.df, **kwargs)

    def test_classify_dataframe(self):
        out = self._cronometrar('classify_dataframe', classify_dataframe, self.df)
        self.assertIn('_infra_label', out.columns)
        self.assertEqual(len(out), len(self.df))

    def test_booleanos_string_sao_contados(self):
        """Regressão da coerção: '1' e 'VERDADEIRO' precisam contar como True.
        A versão anterior reportava zero proxies num dataset cheio deles."""
        from validators import bool_series
        esperado = int((self.df['Ip_Proxy'] == '1').sum())
        self.assertGreater(esperado, 0)
        self.assertEqual(int(bool_series(self.df, 'Ip_Proxy').sum()), esperado)
        self.assertEqual(
            int(bool_series(self.df, 'Ip_Hospedagem').sum()),
            int((self.df['Ip_Hospedagem'] == 'VERDADEIRO').sum()))


@pytest.mark.slow
class TestCargaRelatorioEExports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = _frame_grande()

    def test_relatorio_html_completo(self):
        """Caminho exato que falhou em produção com `bad allocation`."""
        from html_report_generator import generate_html_report

        inicio = time.perf_counter()
        html = generate_html_report(
            self.df, 'alvo_teste',
            config={'title': 'Carga', 'organization': 'Org', 'case_number': 'X',
                    'analyst': 'A', 'classification': 'RESTRITO',
                    'include_raw_data': True, 'branding': {}, 'signatures': [],
                    'coc': {}},
            analyses={'life_patterns': detect_life_patterns(self.df)},
            audit_hash='HASH_TESTE')
        decorrido = time.perf_counter() - inicio

        self.assertLess(decorrido, LIMITE_SEGUNDOS)
        texto = html.decode('utf-8') if isinstance(html, bytes) else html
        # O audit_hash saía vazio porque a chave lida não existia no recibo.
        self.assertIn('HASH_TESTE', texto)

    def test_hash_de_integridade_em_blocos(self):
        """O hash entra na cadeia de custódia: a versão em blocos precisa ser
        idêntica à de passagem única, ou relatórios já emitidos não conferem."""
        import hashlib
        from html_report_generator import _hash_dataframe_csv
        esperado = hashlib.sha256(
            self.df.to_csv(index=False).encode('utf-8')).hexdigest()
        self.assertEqual(_hash_dataframe_csv(self.df), esperado)

    def test_export_xlsx_grande_nao_estoura_memoria(self):
        """O Excel colorido precisa sair inteiro em 202.128 linhas.

        A implementação antiga mantinha um objeto Cell por célula — 622 MB de
        heap só em 100 mil linhas — e por isso recusava o caso real. No modo
        write_only cada linha é serializada no `append` e descartada, então o
        consumo não acompanha o número de linhas.
        """
        import os
        import tempfile
        import tracemalloc

        from openpyxl import load_workbook
        from file_handler import export_xlsx_colored

        # A coluna Reputação é o que aciona o caminho caro — o das linhas
        # pintadas. Sem ela o teste passaria pelo atalho de tupla crua e não
        # cobriria o risco de memória que motivou a mudança.
        df = self.df.assign(
            Reputação=['🛡️ Proxy / VPN / Tor' if p == '1' else '🏠 Residencial'
                       for p in self.df['Ip_Proxy']])

        destino = os.path.join(tempfile.mkdtemp(), 'carga.xlsx')
        tracemalloc.start()
        try:
            inicio = time.perf_counter()
            resumo = export_xlsx_colored(df, destino)
            decorrido = time.perf_counter() - inicio
            _, pico = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        # 202.128 linhas cabem numa aba só; a divisão só entra acima de 1.048.575.
        self.assertEqual(resumo, {'linhas': len(df), 'abas': 1})
        self.assertLess(pico, 100 * 1024 * 1024,
                        'pico de %.0f MB — provável volta ao Workbook não-streaming'
                        % (pico / 1024 / 1024))
        # Generoso: só pega regressão de ordem de grandeza, não variação de máquina.
        self.assertLess(decorrido, 10 * LIMITE_SEGUNDOS)

        # Nenhuma linha pode desaparecer entre o DataFrame e o artefato entregue.
        # O modo write_only não grava a tag <dimension>, então `ws.max_row` vem
        # vazio e a contagem tem que ser por varredura — que também prova que o
        # arquivo é legível de ponta a ponta.
        wb = load_workbook(destino, read_only=True)
        try:
            self.assertEqual(sum(1 for _ in wb.active.rows), len(df) + 1)
        finally:
            wb.close()
        os.remove(destino)

    def test_grafo_deduplica_arestas(self):
        """Com poucos IPs únicos o corte de nós nunca disparava e centenas de
        milhares de arestas duplicadas iam para o navegador."""
        import components.graph_view as gv

        capturado = {}
        originais = (gv.st.warning, gv.st.caption, gv.components.html)
        gv.st.warning = lambda m: capturado.setdefault('aviso', m)
        gv.st.caption = lambda m: capturado.setdefault('legenda', m)
        gv.components.html = lambda html, **kw: capturado.__setitem__('tam', len(html))
        try:
            gv.render_ip_network_graph(self.df)
        finally:
            gv.st.warning, gv.st.caption, gv.components.html = originais

        # Payload precisa ficar na ordem de centenas de KB, não de dezenas de MB.
        self.assertLess(capturado.get('tam', 0), 5_000_000)


if __name__ == '__main__':
    unittest.main()
