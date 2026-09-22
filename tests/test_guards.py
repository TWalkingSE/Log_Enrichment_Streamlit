"""Regressões das guardas de dados grandes e da persistência de sessão.

Cobre o que não é exercitado pela suíte funcional: portões (`gate`),
invalidação por versão do dataset, legendas de truncagem, e o comportamento
do carregamento diante de arquivos corrompidos ou de esquema antigo.
"""
from tests.common import *
from pathlib import Path

import helpers.persistence as persistence
from api_client import summarize_ip_cache
from export_ioc import (
    build_stix_bundle, export_ioc_csv, export_ioc_list, validate_stix_bundle,
)
from helpers.large_data import (
    bump_data_version, cache_key, data_version, gate, is_large,
    row_count, show_truncation, truncation_notice,
)
from validators import as_bool


def _fresh_state():
    """Limpa a session_state compartilhada entre testes (modo bare)."""
    import streamlit as st
    for k in [k for k in st.session_state if isinstance(k, str)]:
        del st.session_state[k]


class TestGatesEVersao(unittest.TestCase):
    """Análise pesada não roda implicitamente em dataset grande, e trocar de
    alvo não pode reutilizar o portão liberado do alvo anterior."""

    def setUp(self):
        _fresh_state()

    def test_dataset_pequeno_roda_sem_clique(self):
        df = pd.DataFrame({'a': range(10)})
        self.assertTrue(gate('Analisar', df, 'g1'))

    def test_dataset_grande_exige_clique(self):
        df = pd.DataFrame({'a': range(60_000)})
        self.assertFalse(gate('Analisar', df, 'g1'))

    def test_gate_liberado_persiste_ate_bump(self):
        import streamlit as st
        df = pd.DataFrame({'a': range(60_000)})
        st.session_state['_gate_g1'] = True
        self.assertTrue(gate('Analisar', df, 'g1'))
        bump_data_version()
        self.assertFalse(gate('Analisar', df, 'g1'))

    def test_bump_limpa_gates_e_preparos(self):
        import streamlit as st
        st.session_state['_gate_a'] = True
        st.session_state['_prep_b'] = True
        st.session_state['outra_coisa'] = 'fica'
        bump_data_version()
        self.assertIsNone(st.session_state.get('_gate_a'))
        self.assertIsNone(st.session_state.get('_prep_b'))
        self.assertEqual(st.session_state.get('outra_coisa'), 'fica')

    def test_bump_incrementa_versao(self):
        antes = data_version()
        bump_data_version()
        self.assertEqual(data_version(), antes + 1)

    def test_cache_key_muda_com_a_versao(self):
        k1 = cache_key('risk', 100)
        bump_data_version()
        self.assertNotEqual(k1, cache_key('risk', 100))

    def test_cache_key_estavel_mesma_versao(self):
        self.assertEqual(cache_key('risk', 100), cache_key('risk', 100))


class TestTruncagemVisivel(unittest.TestCase):
    """A legenda sempre declara o total — nunca a fatia como se fosse tudo."""

    def test_notice_contem_total(self):
        self.assertEqual(truncation_notice(20, 202128, 'linhas'),
                         'Exibindo 20 de 202.128 linhas.')

    def test_show_truncation_chama_caption_com_total(self):
        chamadas = []
        with patch('helpers.large_data.st.caption', side_effect=chamadas.append):
            show_truncation(20, 100, 'registros')
        self.assertEqual(len(chamadas), 1)
        self.assertIn('100', chamadas[0])

    def test_show_truncation_total_completo_marca_total(self):
        chamadas = []
        with patch('helpers.large_data.st.caption', side_effect=chamadas.append):
            show_truncation(50, 50)
        self.assertIn('total', chamadas[0])

    def test_is_large_e_row_count(self):
        self.assertFalse(is_large(pd.DataFrame({'a': range(10)})))
        self.assertTrue(is_large(pd.DataFrame({'a': range(60_000)})))
        self.assertEqual(row_count(None), 0)


class TestPersistenciaResistente(unittest.TestCase):
    """Arquivo corrompido nunca é servido como dado atual, e o parquet não
    cai silenciosamente para um pickle que pode ser de outro alvo."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self._old_data_dir = persistence.DATA_DIR
        persistence.DATA_DIR = Path(self._dir.name)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        persistence.DATA_DIR = self._old_data_dir
        self._dir.cleanup()

    def _df(self):
        return pd.DataFrame({'Ip': ['8.8.8.8'], 'Data': ['2025-01-01 10:00:00']})

    def test_roundtrip_grava_meta(self):
        path = persistence.save_dataframe(self._df(), name='alvo1')
        self.assertTrue(os.path.exists(path))
        loaded = persistence.load_dataframe('alvo1')
        self.assertEqual(len(loaded), 1)
        meta = persistence.read_meta('alvo1')
        self.assertEqual(meta['schema_version'], persistence.SCHEMA_VERSION)
        self.assertEqual(meta['rows'], 1)

    def test_parquet_corrompido_nao_cai_para_pickle_antigo(self):
        # Cenário real: parquet truncado por falha de gravação + um .pkl de
        # uma execução anterior ao lado. Servir o pkl seria dado obsoleto
        # apresentado como atual — o load precisa falhar alto.
        paths = persistence.session_paths('alvo2')
        paths['parquet'].write_bytes(b'lixo')
        self._df().to_pickle(paths['pickle'])
        with self.assertRaises(Exception):
            persistence.load_dataframe('alvo2')

    def test_pickle_corrompido_retorna_none(self):
        paths = persistence.session_paths('alvo3')
        paths['pickle'].write_bytes(b'lixo')
        self.assertIsNone(persistence.load_dataframe('alvo3'))

    def test_schema_antigo_carrega_mas_avisa(self):
        persistence.save_dataframe(self._df(), name='alvo4')
        meta_path = persistence.session_paths('alvo4')['meta']
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        meta['schema_version'] = 1
        meta_path.write_text(json.dumps(meta), encoding='utf-8')
        with self.assertLogs('helpers.persistence', level='WARNING') as cm:
            loaded = persistence.load_dataframe('alvo4')
        self.assertIsNotNone(loaded)
        self.assertTrue(any('schema' in m.lower() for m in cm.output))

    def test_meta_ilegivel_retorna_none(self):
        paths = persistence.session_paths('alvo5')
        paths['meta'].write_text('{json quebrado', encoding='utf-8')
        self.assertIsNone(persistence.read_meta('alvo5'))

    def test_save_pickle_atomico_sem_part(self):
        # Força o caminho pickle (sem parquet) e exige o padrão .part+replace.
        df = self._df()
        paths = persistence.session_paths('alvo6')

        def _falha(*a, **k):
            raise RuntimeError('pyarrow indisponível')

        with patch.object(pd.DataFrame, 'to_parquet', _falha):
            path = persistence.save_dataframe(df, name='alvo6')
        self.assertEqual(path, str(paths['pickle']))
        self.assertTrue(paths['pickle'].exists())
        self.assertFalse(paths['pickle'].with_suffix('.pkl.part').exists())
        loaded = persistence.load_dataframe('alvo6')
        self.assertEqual(len(loaded), 1)

    def test_meta_contem_sha256_e_detecta_arquivo_trocado(self):
        persistence.save_dataframe(self._df(), name='alvo7')
        meta = persistence.read_meta('alvo7')
        self.assertTrue(meta.get('sha256'))
        # Troca o arquivo de dados por outro parquet — o manifesto deixa de
        # corresponder e a divergência precisa aparecer no log.
        paths = persistence.session_paths('alvo7')
        pd.DataFrame({'Ip': ['9.9.9.9']}).to_parquet(paths['parquet'], index=False)
        with self.assertLogs('helpers.persistence', level='WARNING') as cm:
            persistence.load_dataframe('alvo7')
        self.assertTrue(any('sha256' in m for m in cm.output))


class TestCacheFreshness(unittest.TestCase):
    """summarize_ip_cache alimenta o aviso de frescor da interface."""

    def test_resumo_conta_expirados_e_sem_data(self):
        import time
        agora = time.time()
        cache = {
            '8.8.8.8': {'Ip_Dono': 'X', '_cached_at': agora - 100},
            '1.1.1.1': {'Ip_Dono': 'Y', '_cached_at': agora - 40 * 86400},
            '9.9.9.9': {'Ip_Dono': 'Z'},  # sem carimbo
        }
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, 'ip_cache.json')
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(cache, fh)
            stats = summarize_ip_cache(path)
        self.assertEqual(stats['total'], 3)
        self.assertEqual(stats['expirados'], 1)
        self.assertEqual(stats['sem_data'], 1)
        self.assertGreater(stats['mais_antigo_dias'], 39)

    def test_cache_inexistente_retorna_none(self):
        self.assertIsNone(summarize_ip_cache('caminho/que/nao/existe.json'))


class TestStixValidacao(unittest.TestCase):
    """O bundle emitido precisa passar na validação estrutural — e a
    validação precisa flagrar patterns quebrados."""

    def test_bundle_valido_sem_erros(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8', '2001:db8::1', "9.9.9.9' aspas"],
            'Ip_Proxy': [True, False, False],
        })
        erros = validate_stix_bundle(build_stix_bundle(df))
        self.assertEqual(erros, [])

    def test_flagra_pattern_quebrado(self):
        bundle = build_stix_bundle(pd.DataFrame({'Ip': ['8.8.8.8']}))
        ind = next(o for o in bundle['objects'] if o['type'] == 'indicator')
        ind['pattern'] = "[ipv4-addr:value = '8.8.8.8'"  # colchete aberto
        erros = validate_stix_bundle(bundle)
        self.assertTrue(erros)

    def test_flagra_relacionamento_orfao(self):
        bundle = build_stix_bundle(pd.DataFrame({'Ip': ['8.8.8.8']}))
        rel = next(o for o in bundle['objects'] if o['type'] == 'relationship')
        rel['target_ref'] = 'ipv4-addr--nao-existe'
        erros = validate_stix_bundle(bundle)
        self.assertTrue(any('órfão' in e or 'rfão' in e for e in erros))


class TestIocDedup(unittest.TestCase):
    """IPs repetidos no frame aparecem uma vez no IOC — e indicadores
    malformados continuam preservados."""

    def test_list_dedup(self):
        df = pd.DataFrame({'Ip': ['8.8.8.8', '8.8.8.8', '1.1.1.1', '8.8.8.8']})
        self.assertEqual(sorted(export_ioc_list(df).split()), ['1.1.1.1', '8.8.8.8'])

    def test_csv_dedup(self):
        df = pd.DataFrame({'Ip': ['8.8.8.8', '8.8.8.8', '1.1.1.1']})
        linhas = export_ioc_csv(df).strip().split('\n')
        self.assertEqual(len(linhas), 3)  # header + 2 IPs

    def test_malformado_preservado(self):
        df = pd.DataFrame({'Ip': ["8.8.8.8' OR '1'='1", '8.8.8.8']})
        saida = export_ioc_list(df).split('\n')
        self.assertIn("8.8.8.8' OR '1'='1", saida)


class TestRiskScoresMultiplosIps(unittest.TestCase):
    """A versão vetorizada precisa dar os mesmos scores da agregação por IP —
    validado contra o cálculo de referência linha a linha (a implementação
    antiga, O(n·u)) sobre fixture mista."""

    def _score_naive(self, df):
        ip_col = 'Ip'
        main_city = ''
        if 'Ip_Cidade' in df.columns:
            cities = df['Ip_Cidade'].value_counts()
            if len(cities) > 0:
                main_city = cities.index[0]
        out = {}
        for ip in df[ip_col].dropna().unique():
            sub = df[df[ip_col] == ip]
            first = sub.iloc[0]
            score = 0
            if as_bool(first.get('Ip_Proxy')):
                score += 40
            if as_bool(first.get('Ip_Hospedagem')):
                score += 25
            city = first.get('Ip_Cidade', '')
            if main_city and pd.notna(city) and city != main_city:
                score += 20
            if len(sub) <= 2:
                score += 10
            if as_bool(first.get('Ip_Movel')):
                score -= 5
            out[ip] = max(0, min(100, score))
        return out

    def test_equivalencia(self):
        df = pd.DataFrame({
            'Ip': ['8.8.8.8', '8.8.8.8', '1.1.1.1', '9.9.9.9', '1.1.1.1', '9.9.9.9', '9.9.9.9'],
            'Ip_Proxy': [True, True, False, '1', False, '1', '1'],
            'Ip_Hospedagem': [False, False, 'VERDADEIRO', False, 'VERDADEIRO', False, False],
            'Ip_Movel': [False, False, True, False, True, False, False],
            'Ip_Cidade': ['X', 'X', 'X', 'Y', 'X', 'Y', 'Y'],
        })
        esperado = self._score_naive(df)
        got = calculate_risk_scores(df)
        obtido = dict(zip(got['IP'], got['Score']))
        self.assertEqual(obtido, esperado)


class TestSubnetAgrupamento(unittest.TestCase):
    """subnet por valor distinto: /24 para IPv4, contagens e provedores."""

    def test_ipv4_24(self):
        df = pd.DataFrame({
            'Ip': ['10.0.0.1', '10.0.0.2', '10.0.0.1', '192.168.1.5'],
            'Ip_Dono': ['A', 'A', 'A', 'B'],
        })
        res = analyze_subnet_patterns(df)
        subs = {s['subnet']: s for s in res['subnets']}
        self.assertIn('10.0.0.0/24', subs)
        self.assertEqual(subs['10.0.0.0/24']['record_count'], 3)
        self.assertEqual(subs['10.0.0.0/24']['ip_count'], 2)
        self.assertEqual(subs['10.0.0.0/24']['providers'], ['A'])

    def test_ip_invalido_contado_e_ignorado(self):
        df = pd.DataFrame({'Ip': ['10.0.0.1', 'nao-e-ip', '10.0.0.2']})
        with self.assertLogs('analysis.subnet', level='WARNING'):
            res = analyze_subnet_patterns(df)
        self.assertEqual(res['total_subnets'], 1)


if __name__ == '__main__':
    unittest.main()
