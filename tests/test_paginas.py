"""Smoke test das páginas: cada uma renderiza nos três idiomas sem exceção.

Roda cada página com `streamlit.testing.AppTest` sobre um dataset sintético
pequeno (com coordenadas, datas e flags). Pega o que os testes de unidade não
veem: import quebrado na página, chave de tradução com placeholder errado,
coluna renomeada que a página ainda procura.

Nenhuma página faz chamada externa sem clique; o teste não clica em nada.
"""
import os
import unittest

import pytest

PAGINAS = [
    ('pages_app.entrada', 'page_entrada'),
    ('pages_app.resultados', 'page_resultados'),
    ('pages_app.estatisticas', 'page_estatisticas'),
    ('pages_app.mapa', 'page_mapa'),
    ('pages_app.analise.overview', 'page_overview'),
    ('pages_app.analise.risco', 'page_risco'),
    ('pages_app.analise.temporal', 'page_temporal'),
    ('pages_app.analise.comparacao', 'page_comparacao'),
    ('pages_app.analise.geo', 'page_geo'),
    ('pages_app.analise.correlacao', 'page_correlacao'),
    ('pages_app.analise.comportamento', 'page_comportamento'),
    ('pages_app.analise.operacional', 'page_operacional'),
    ('pages_app.interceptacao', 'page_interceptacao'),
    ('pages_app.relatorio', 'page_relatorio'),
    ('pages_app.configuracoes', 'page_configuracoes'),
]


def _script_da_pagina():
    # Sem acentos neste corpo: no Windows o AppTest grava o script em cp1252
    # e o Streamlit o le como UTF-8 - o script falharia sem erro visivel.
    import importlib
    import os
    import sys
    sys.path.insert(0, os.getcwd())
    import pandas as pd
    import streamlit as st
    n = 40
    if st.session_state.get('df_resultado') is None:
        st.session_state['df_resultado'] = pd.DataFrame({
            'Alvo': ['teste'] * n,
            'Ip': [f'8.8.{i // 10}.{i % 10}' for i in range(n)],
            'Data': [f'2024-03-{1 + i % 28:02d} {i % 24:02d}:10:00' for i in range(n)],
            'Data_Fuso': ['GMT -0300'] * n,
            'Ip_Dono': ['Prov A', 'Prov B', 'Prov C', 'Prov D'] * (n // 4),
            'Ip_AS': ['AS1 Teste'] * n,
            'Ip_Regiao': ['SP', 'RJ'] * (n // 2),
            'Ip_Cidade': ['Sao Paulo', 'Rio de Janeiro', 'Campinas', 'Santos'] * (n // 4),
            'Ip_Pais': ['Brazil'] * n,
            'Ip_Pais_Codigo': ['BR'] * n,
            'Ip_Movel': [i % 3 == 0 for i in range(n)],
            'Ip_Proxy': [i % 7 == 0 for i in range(n)],
            'Ip_Hospedagem': [i % 11 == 0 for i in range(n)],
            'Ip_Tor': [False] * n,
            'Ip_Lat': [-23.5 + (i % 5) for i in range(n)],
            'Ip_Lon': [-46.6 + (i % 5) for i in range(n)],
            'Periodo': ['Diurno'] * n,
            'ISO_Date': [None] * n,
        })
    defaults = {'alvo': 'teste', 'output_file': 'resultado_logs.csv', 'processing': False,
                'log_messages': [], 'history': [], 'batch_size': 500, 'period': 0,
                'use_cache': True, 'incremental': True, 'api_key': '', 'stored_targets': {},
                'ai_tier': 'lite', 'ai_ollama_url': 'http://127.0.0.1:9', 'air_gapped': True}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)
    st.session_state['lang'] = os.environ['LE_TEST_LANG']
    modulo = importlib.import_module(os.environ['LE_TEST_PAGE_MODULE'])
    getattr(modulo, os.environ['LE_TEST_PAGE_FUNC'])()


def _textos(at):
    textos = []
    for tipo in ('markdown', 'caption', 'info', 'warning', 'error', 'success', 'subheader',
                 'header', 'title'):
        for elemento in getattr(at, tipo, []):
            valor = getattr(elemento, 'value', '')
            if isinstance(valor, str):
                textos.append(valor)
    return textos


@pytest.mark.parametrize('modulo,funcao', PAGINAS)
@pytest.mark.parametrize('lang', ['pt', 'en', 'es'])
def test_pagina_renderiza(modulo, funcao, lang):
    from unittest.mock import patch
    from streamlit.testing.v1 import AppTest
    env = {'LE_TEST_LANG': lang, 'LE_TEST_PAGE_MODULE': modulo, 'LE_TEST_PAGE_FUNC': funcao,
           'AIR_GAPPED': '1'}
    with patch.dict(os.environ, env):
        at = AppTest.from_function(_script_da_pagina, default_timeout=90).run()
    assert not at.exception, [e.value for e in at.exception]
    # Script que falha antes de renderizar (ex.: erro de codificação) não gera
    # exceção visível — só uma página vazia.
    assert len(at.main.children) > 0, 'página não renderizou nada'
    # Uma chave sem tradução aparece crua na tela ("mapa.no_route").
    import re
    cruas = [s for s in _textos(at)
             if re.fullmatch(r'[a-z_]+\.[a-z_.]+', s.strip())]
    assert not cruas, cruas


if __name__ == '__main__':
    unittest.main()
