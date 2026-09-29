"""Fluxos de ponta a ponta pela interface (`streamlit.testing.AppTest`).

Os testes de unidade provam que `cache_key` difere entre filtros e que
`bump_data_version` apaga `_RESULT_KEYS`. Aqui a prova é pelo caminho que o
analista usa: a página monta a chave, o `st.cache_data` responde, o botão de
download recebe os bytes; o clique troca o alvo e a tela deixa de ter o
resultado do alvo anterior.

Os scripts do AppTest rodam no processo do teste: diretório de sessões e
audit trail são desviados para um temporário e restaurados no `finally` —
nunca tocam `data/sessions/` nem `logs/` reais.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd


def _rotulo(secao, chave):
    with open(os.path.join('locales', 'pt.json'), encoding='utf-8') as fh:
        return json.load(fh)[secao][chave]


def _pagina_resultados_gravando_downloads():
    # Sem acentos neste corpo: no Windows o AppTest grava o script em cp1252
    # e o Streamlit o le como UTF-8 - o script falharia sem erro visivel.
    import os
    import sys
    sys.path.insert(0, os.getcwd())
    import pandas as pd
    import streamlit as st
    n = 40
    if st.session_state.get('df_resultado') is None:
        # Quatro provedores com 10 linhas cada: filtros diferentes, mesmo tamanho.
        st.session_state['df_resultado'] = pd.DataFrame({
            'Alvo': ['teste'] * n,
            'Ip': [f'8.8.{i // 10}.{i % 10}' for i in range(n)],
            'Data': [f'2024-03-{1 + i % 28:02d} {i % 24:02d}:10:00' for i in range(n)],
            'Data_Fuso': ['GMT -0300'] * n,
            'Ip_Dono': ['Prov A', 'Prov B', 'Prov C', 'Prov D'] * (n // 4),
            'Ip_AS': ['AS1 Teste'] * n,
            'Ip_Regiao': ['SP'] * n,
            'Ip_Cidade': ['Sao Paulo'] * n,
            'Ip_Pais': ['Brazil'] * n,
            'Ip_Pais_Codigo': ['BR'] * n,
            'Ip_Movel': [False] * n,
            'Ip_Proxy': [False] * n,
            'Ip_Hospedagem': [False] * n,
            'Ip_Lat': [-23.5] * n,
            'Ip_Lon': [-46.6] * n,
            'Periodo': ['Diurno'] * n,
        })
    defaults = {'alvo': 'teste', 'processing': False, 'log_messages': [], 'history': [],
                'output_file': os.path.join(os.environ['LE_TEST_TMP'], 'inexistente.csv'),
                'lang': 'pt'}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)

    original = st.download_button

    def gravar(label, data=None, file_name=None, *args, **kwargs):
        if isinstance(data, (bytes, str)):
            st.session_state.setdefault('_downloads', {})[file_name] = data
        return False

    st.download_button = gravar
    try:
        from pages_app.resultados import page_resultados
        page_resultados()
    finally:
        st.download_button = original


def _pagina_entrada_isolada():
    # Sem acentos neste corpo (ver acima).
    import os
    import sys
    from pathlib import Path
    sys.path.insert(0, os.getcwd())
    import streamlit as st
    import helpers.persistence as persistence
    import audit_logger
    tmp = os.environ['LE_TEST_TMP']
    anteriores = (persistence.DATA_DIR, audit_logger.AUDIT_LOG_DIR, audit_logger.AUDIT_LOG_FILE)
    persistence.DATA_DIR = Path(tmp) / 'sessions'
    audit_logger.AUDIT_LOG_DIR = tmp
    audit_logger.AUDIT_LOG_FILE = os.path.join(tmp, 'audit.jsonl')
    try:
        defaults = {'df_resultado': None, 'alvo': '', 'processing': False,
                    'output_file': os.path.join(tmp, 'inexistente.csv'),
                    'log_messages': [], 'history': [], 'batch_size': 500, 'period': 0,
                    'use_cache': True, 'incremental': True, 'api_key': '', 'lang': 'pt'}
        for k, v in defaults.items():
            st.session_state.setdefault(k, v)
        from pages_app.entrada import page_entrada
        page_entrada()
    finally:
        persistence.DATA_DIR, audit_logger.AUDIT_LOG_DIR, audit_logger.AUDIT_LOG_FILE = anteriores


def _resultados_do_alvo_anterior():
    """O que a sessão guarda depois de analisar o alvo A (IA, VirusTotal...)."""
    return {
        'ai_result': {'success': True, 'data': {'resumo_narrativo': 'alvo A'}},
        'inv_ai_result': {'success': True, 'data': {'resumo_narrativo': 'alvo A'}},
        'vt_scores': pd.DataFrame({'IP': ['8.8.8.8'], 'Score': [90]}),
        'inv_result': {'alvo': 'A'},
    }


def _df_do_alvo(alvo, n):
    return pd.DataFrame({
        'Alvo': [alvo] * n,
        'Ip': [f'9.9.9.{i}' for i in range(n)],
        'Data': ['2024-01-01 10:00:00'] * n,
    })


class TestExportFiltradoPelaPagina(unittest.TestCase):
    """Dois filtros com o mesmo número de linhas recebiam os mesmos bytes de CSV."""

    def test_filtros_do_mesmo_tamanho_exportam_csvs_diferentes(self):
        from streamlit.testing.v1 import AppTest
        rotulo_provedor = _rotulo('resultados', 'provider')
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LE_TEST_TMP': tmp}):
            at = AppTest.from_function(_pagina_resultados_gravando_downloads,
                                       default_timeout=90).run()
            self.assertFalse(at.exception, [e.value for e in at.exception])
            baixados = {}
            for provedor in ('Prov A', 'Prov B'):
                seletor = [s for s in at.selectbox if s.label == rotulo_provedor]
                self.assertEqual(len(seletor), 1)
                at = seletor[0].select(provedor).run()
                self.assertFalse(at.exception, [e.value for e in at.exception])
                csv = at.session_state['_downloads']['resultado_filtrado.csv']
                baixados[provedor] = csv.decode('utf-8-sig')

        linhas_a = baixados['Prov A'].strip().splitlines()
        linhas_b = baixados['Prov B'].strip().splitlines()
        # Mesmo tamanho (cabeçalho + 10), que era a condição do defeito.
        self.assertEqual(len(linhas_a), 11)
        self.assertEqual(len(linhas_b), 11)
        self.assertNotEqual(baixados['Prov A'], baixados['Prov B'])
        self.assertIn('Prov A', baixados['Prov A'])
        self.assertNotIn('Prov B', baixados['Prov A'])
        self.assertIn('Prov B', baixados['Prov B'])
        self.assertNotIn('Prov A', baixados['Prov B'])


class TestTrocaDeAlvoPelaPagina(unittest.TestCase):
    """Resultado de IA/VirusTotal do alvo anterior sobrevivia à troca de alvo."""

    def _app(self, tmp, estado):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_function(_pagina_entrada_isolada, default_timeout=60)
        for chave, valor in estado.items():
            at.session_state[chave] = valor
        return at

    def test_limpar_apaga_os_resultados_do_alvo_anterior(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LE_TEST_TMP': tmp}):
            estado = {'df_resultado': _df_do_alvo('A', 3), 'alvo': 'A',
                      **_resultados_do_alvo_anterior()}
            at = self._app(tmp, estado).run()
            self.assertFalse(at.exception, [e.value for e in at.exception])
            self.assertIn('ai_result', at.session_state)

            limpar = [b for b in at.button if b.label == _rotulo('entrada', 'clear_btn')]
            self.assertEqual(len(limpar), 1)
            at = limpar[0].click().run()
            self.assertFalse(at.exception, [e.value for e in at.exception])

            self.assertIsNone(at.session_state['df_resultado'])
            for chave in _resultados_do_alvo_anterior():
                self.assertNotIn(chave, at.session_state, chave)

    def test_restaurar_outro_alvo_apaga_os_resultados_do_anterior(self):
        import helpers.persistence as persistence
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LE_TEST_TMP': tmp}):
            with patch.object(persistence, 'DATA_DIR', Path(tmp) / 'sessions'):
                persistence.save_dataframe(_df_do_alvo('B', 5), name='current', alvo='B')
            at = self._app(tmp, _resultados_do_alvo_anterior()).run()
            self.assertFalse(at.exception, [e.value for e in at.exception])

            restaurar = [b for b in at.button if b.key == 'btn_restore_session']
            self.assertEqual(len(restaurar), 1)
            at = restaurar[0].click().run()
            self.assertFalse(at.exception, [e.value for e in at.exception])

            self.assertEqual(list(at.session_state['df_resultado']['Alvo'].unique()), ['B'])
            for chave in _resultados_do_alvo_anterior():
                self.assertNotIn(chave, at.session_state, chave)
            # O evento foi para o audit trail temporário, não para logs/.
            self.assertTrue(os.path.exists(os.path.join(tmp, 'audit.jsonl')))


if __name__ == '__main__':
    unittest.main()
