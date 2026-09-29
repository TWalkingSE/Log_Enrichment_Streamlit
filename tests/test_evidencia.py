"""Regressões dos defeitos que produziam prova errada ou quebravam a custódia.

Cada classe cobre um defeito encontrado na auditoria de 2026-09: o nome do
teste diz o que o laudo mostrava de errado antes da correção.
"""
from tests.common import *
import asyncio
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import audit_logger
from api_client import (
    IPAPIClient, InvalidApiKeyError, SignedCacheError, filter_fresh_cache,
    read_ip_cache,
)
from helpers.large_data import _RESULT_KEYS, bump_data_version, cache_key
from helpers.retention import prune_ip_cache
from helpers.runtime_flags import AirGappedError
from export_ioc import export_ioc_csv
from helpers.signed_cache import build_signed_package
from validators import infer_dayfirst, parse_data


def _fresh_state():
    import streamlit as st
    for k in [k for k in st.session_state if isinstance(k, str)]:
        del st.session_state[k]


class TestChavesDeCache(unittest.TestCase):
    """Filtros diferentes com o mesmo número de linhas recebiam o mesmo export."""

    def setUp(self):
        _fresh_state()

    def test_filtros_diferentes_geram_chaves_diferentes(self):
        k_a = cache_key('exp', 10, ('Ip',), ('', 'Claro', 'Todos', 'Todos'))
        k_b = cache_key('exp', 10, ('Ip',), ('', 'Vivo', 'Todos', 'Todos'))
        self.assertNotEqual(k_a, k_b)

    def test_sessoes_diferentes_nao_compartilham_chave(self):
        import streamlit as st
        k_sessao_1 = cache_key('exp', 10)
        # Nova sessão: session_state vazio, versão volta a 0.
        _fresh_state()
        k_sessao_2 = cache_key('exp', 10)
        self.assertEqual(st.session_state.get('_data_version', 0), 0)
        self.assertNotEqual(k_sessao_1, k_sessao_2)

    def test_bump_apaga_resultados_do_alvo_anterior(self):
        import streamlit as st
        for k in _RESULT_KEYS:
            st.session_state[k] = 'alvo anterior'
        bump_data_version()
        for k in _RESULT_KEYS:
            self.assertNotIn(k, st.session_state, k)


class TestDatasBrasileiras(unittest.TestCase):
    """`05/03/2024` era lido como 3 de maio."""

    def test_ambigua_e_dia_primeiro(self):
        out = parse_data(pd.Series(['05/03/2024 10:00:00']))
        self.assertEqual(out.iloc[0], pd.Timestamp('2024-03-05 10:00:00'))

    def test_coluna_inteira_decide_a_ordem(self):
        self.assertTrue(infer_dayfirst(pd.Series(['05/03/2024', '13/03/2024'])))
        self.assertFalse(infer_dayfirst(pd.Series(['05/03/2024', '03/13/2024'])))
        out = parse_data(pd.Series(['05/03/2024 10:00', '03/13/2024 10:00']))
        self.assertEqual(out.iloc[0], pd.Timestamp('2024-05-03 10:00:00'))

    def test_iso_nao_e_afetada(self):
        self.assertTrue(infer_dayfirst(pd.Series(['2024-03-05'])))
        out = parse_data(pd.Series(['2024-03-05T10:00:00', '05/03/2024 10:00']))
        self.assertEqual(out.iloc[0], pd.Timestamp('2024-03-05 10:00:00'))

    def test_loader_generico_converte_coluna_inteira(self):
        from file_handler import carregar_arquivo_log
        with tempfile.TemporaryDirectory() as tmp:
            csv = Path(tmp) / 'log.csv'
            csv.write_text('IP Address;Horario\n'
                           '8.8.8.8;05/03/2024 22:10:00\n'
                           '1.1.1.1;13/03/2024 08:00:00\n', encoding='utf-8')
            df = carregar_arquivo_log(str(csv))
        self.assertEqual(df['Data'].tolist(),
                         ['2024-03-05 22:10:00', '2024-03-13 08:00:00'])
        self.assertTrue(df['Periodo'].notna().all())


class TestBooleanosNaDeteccaoDeVpn(unittest.TestCase):
    """Proxy vindo como '1'/'VERDADEIRO' era tomado por residencial."""

    def test_proxy_textual_nao_e_residencial(self):
        from analysis import detect_vpn_timing
        for token in ('1', 'VERDADEIRO', 'true'):
            df = pd.DataFrame({
                'Ip': ['10.0.0.1', '10.0.0.2'],
                'Data': ['2024-01-01 10:00:00', '2024-01-01 10:00:02'],
                'Ip_Hospedagem': [token, token],
                'Ip_Proxy': ['0', '0'],
            })
            self.assertEqual(detect_vpn_timing(df)['pairs'], [], token)


class TestFaixasDeRisco(unittest.TestCase):
    """A página usava 50/20 e o relatório 70/40 para o mesmo Score."""

    def test_faixas_unicas(self):
        from analysis.risk import RISK_HIGH, RISK_MEDIUM, risk_level_counts
        scores = pd.DataFrame({'Score': [RISK_HIGH, RISK_HIGH - 1, RISK_MEDIUM, RISK_MEDIUM - 1]})
        self.assertEqual(risk_level_counts(scores), (1, 2, 1))


class TestLeitorDoCache(unittest.TestCase):
    """Páginas recebiam o envelope assinado no lugar das entradas."""

    def _entradas(self):
        return {'8.8.8.8': {'Ip_Lat': 1.0, 'Ip_Lon': 2.0, '_cached_at': time_now()},
                '1.1.1.1': {'Ip_Lat': 3.0, 'Ip_Lon': 4.0, '_cached_at': 1}}

    def test_envelope_valido_e_desembrulhado(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {'CACHE_HMAC_SECRET': 'segredo'}):
            path = Path(tmp) / 'ip_cache.json'
            path.write_text(json.dumps(build_signed_package(self._entradas())), encoding='utf-8')
            self.assertEqual(set(read_ip_cache(str(path))), {'8.8.8.8', '1.1.1.1'})

    def test_assinatura_invalida_falha_fechado(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {'CACHE_HMAC_SECRET': 'segredo'}):
            pkg = build_signed_package(self._entradas())
            pkg['payload']['8.8.8.8']['Ip_Lat'] = 99.0  # adulterado
            path = Path(tmp) / 'ip_cache.json'
            path.write_text(json.dumps(pkg), encoding='utf-8')
            with self.assertRaises(SignedCacheError):
                read_ip_cache(str(path))

    def test_ttl_descarta_expiradas(self):
        frescas, descartadas = filter_fresh_cache(self._entradas())
        self.assertEqual(set(frescas), {'8.8.8.8'})
        self.assertEqual(descartadas, 1)


def time_now():
    import time
    return time.time()


class TestChaveRecusada(unittest.TestCase):
    """403 da chave paga rebaixava o job para HTTP em claro."""

    def test_403_interrompe_sem_trocar_de_endpoint(self):
        from helpers.shared import run_async
        client = IPAPIClient(api_key='chave-ruim', cache_file=None, air_gapped=False)
        response = AsyncMock()
        response.status = 403
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=response)
        cm.__aexit__ = AsyncMock(return_value=None)
        session = MagicMock()
        session.get = MagicMock(return_value=cm)
        with self.assertRaises(InvalidApiKeyError):
            run_async(client.consultar_ip(session, '8.8.8.8'))
        self.assertTrue(client.API_URL.startswith('https://'))
        self.assertEqual(client.api_key, 'chave-ruim')


class TestAirGapped(unittest.TestCase):
    """Só o IP-API respeitava o modo air-gapped."""

    def test_servicos_externos_bloqueados(self):
        from advanced_analysis import (
            batch_check_abuseipdb, batch_check_virustotal, fetch_tor_exit_nodes,
        )
        with patch.dict(os.environ, {'AIR_GAPPED': '1'}):
            with self.assertRaises(AirGappedError):
                asyncio.run(batch_check_virustotal(['8.8.8.8'], 'k'))
            with self.assertRaises(AirGappedError):
                asyncio.run(batch_check_abuseipdb(['8.8.8.8'], 'k'))
            with self.assertRaises(AirGappedError):
                asyncio.run(batch_check_shodan(['8.8.8.8'], 'k'))
            nodes, erro = fetch_tor_exit_nodes(return_error=True)
            self.assertEqual(nodes, set())
            self.assertIn('air-gapped', erro)


class TestOllamaRemoto(unittest.TestCase):
    """O prompt da IA leva IPs e datas do caso: fora do loopback, eles saem da máquina."""

    def test_so_loopback_literal_conta_como_local(self):
        from ai_assistant import ollama_remote_host
        for url in ('http://localhost:11434', 'http://127.0.0.1:11434', 'http://127.8.9.1',
                    'http://[::1]:11434', 'http://LOCALHOST:11434', 'http://ollama.localhost'):
            self.assertIsNone(ollama_remote_host(url), url)
        self.assertEqual(ollama_remote_host('http://192.168.0.10:11434'), '192.168.0.10')
        self.assertEqual(ollama_remote_host('https://gpu.exemplo.org'), 'gpu.exemplo.org')
        self.assertEqual(ollama_remote_host('http://0.0.0.0:11434'), '0.0.0.0')
        # Sem esquema o host não é legível: tratado como remoto, não como local.
        self.assertIsNotNone(ollama_remote_host('localhost:11434'))
        self.assertEqual(ollama_remote_host(''), '?')

    def test_air_gapped_bloqueia_ollama_remoto_sem_tocar_a_rede(self):
        from ai_assistant import check_ollama_status, query_ollama
        with patch.dict(os.environ, {'AIR_GAPPED': '1'}), \
                patch('ai_assistant.requests.get') as get, \
                patch('ai_assistant.requests.post') as post:
            status = check_ollama_status('http://10.0.0.5:11434')
            resposta, erro = query_ollama('s', 'u', 'm', {}, base_url='http://10.0.0.5:11434')
        get.assert_not_called()
        post.assert_not_called()
        self.assertFalse(status['online'])
        self.assertIn('air-gapped', status['error'])
        self.assertIsNone(resposta)
        self.assertIn('air-gapped', erro)

    def test_air_gapped_nao_bloqueia_ollama_local(self):
        from ai_assistant import check_ollama_status
        resp = MagicMock()
        resp.json.return_value = {'models': [{'name': 'qwen3.5:4b'}]}
        with patch.dict(os.environ, {'AIR_GAPPED': '1'}), \
                patch('ai_assistant.requests.get', return_value=resp) as get:
            status = check_ollama_status('http://localhost:11434')
        get.assert_called_once()
        self.assertTrue(status['online'])


class TestZipDeInterceptacao(unittest.TestCase):
    """`RECORDS.HTML` e `x.ZIP` eram descartados em silêncio."""

    def _zip(self, entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_nomes_em_maiusculas_sao_lidos_e_ignorados_sao_declarados(self):
        from interception_parser import parse_zip_interception
        interno = self._zip({'RECORDS.HTML': '<html><body></body></html>',
                             'nested.zip': self._zip({'a.txt': 'x'})})
        externo = self._zip({'CASO.ZIP': interno})
        msgs = []
        with patch('interception_parser.parse_html_records', return_value=[]) as parse:
            parse_zip_interception(externo, update_callback=msgs.append)
        self.assertEqual(parse.call_count, 1)
        self.assertTrue(any('ZIP aninhado' in m for m in msgs), msgs)
        self.assertTrue(any('1 entrada(s) do ZIP ignorada(s)' in m for m in msgs), msgs)


class TestRetencaoPreservaCadeia(unittest.TestCase):
    """A retenção reescrevia o audit trail e a verificação acusava adulteração."""

    def _com_trail(self, tmp):
        trail = str(Path(tmp) / 'audit_trail.jsonl')
        return (patch.object(audit_logger, 'AUDIT_LOG_FILE', trail),
                patch.object(audit_logger, 'AUDIT_LOG_DIR', tmp),
                patch.object(audit_logger, 'AUDIT_HMAC_SECRET', ''))

    def test_arquiva_ancora_e_verifica_sem_quebra(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1, p2, p3 = self._com_trail(tmp)
            with p1, p2, p3:
                for i in range(10):
                    audit_logger.log_audit_event('evento', details={'i': i})
                linhas_antes = Path(audit_logger.AUDIT_LOG_FILE).read_text(
                    encoding='utf-8').splitlines()
                r = audit_logger.archive_old_events(max_age_days=0, max_lines=4)
                self.assertEqual(r['removed'], 6)
                self.assertTrue(r['checkpoint_persisted'])
                # Os arquivados estão intactos, byte a byte.
                arquivados = Path(r['archive']).read_text(encoding='utf-8').splitlines()
                self.assertEqual(arquivados, linhas_antes[:6])
                ativos = Path(audit_logger.AUDIT_LOG_FILE).read_text(
                    encoding='utf-8').splitlines()
                self.assertEqual(ativos[:4], linhas_antes[6:])
                res = audit_logger.verify_audit_integrity()
                self.assertEqual(res['chain_breaks'], 0, res)
                self.assertEqual(res['invalid'], 0, res)
                self.assertEqual(res['checkpoints'], 1)

    def test_primeiro_evento_sem_ancora_e_quebra(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1, p2, p3 = self._com_trail(tmp)
            with p1, p2, p3:
                for i in range(5):
                    audit_logger.log_audit_event('evento', details={'i': i})
                trail = Path(audit_logger.AUDIT_LOG_FILE)
                linhas = trail.read_text(encoding='utf-8').splitlines()
                trail.write_text('\n'.join(linhas[2:]) + '\n', encoding='utf-8')
                self.assertEqual(audit_logger.verify_audit_integrity()['chain_breaks'], 1)

    def test_arquivamento_adulterado_e_detectado(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1, p2, p3 = self._com_trail(tmp)
            with p1, p2, p3:
                for i in range(6):
                    audit_logger.log_audit_event('evento', details={'i': i})
                r = audit_logger.archive_old_events(max_age_days=0, max_lines=2)
                with open(r['archive'], 'a', encoding='utf-8') as fh:
                    fh.write('{"forjado": true}\n')
                res = audit_logger.verify_audit_integrity()
                self.assertEqual(res['archive_failures'], 1)
                self.assertGreater(res['invalid'], 0)


class TestVerificacaoCompleta(unittest.TestCase):

    def test_acima_de_10_mil_eventos_sem_quebra_falsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            trail = Path(tmp) / 'audit_trail.jsonl'
            prev = None
            linhas = []
            for i in range(10_050):
                ev = {'timestamp': f'2024-01-01T00:00:{i % 60:02d}', 'action': 'x',
                      'prev_hash': prev, 'details': {'i': i}}
                ev['event_hash'] = audit_logger._compute_hash(ev)
                prev = ev['event_hash']
                linhas.append(json.dumps(ev))
            trail.write_text('\n'.join(linhas) + '\n', encoding='utf-8')
            with patch.object(audit_logger, 'AUDIT_LOG_FILE', str(trail)), \
                    patch.object(audit_logger, 'AUDIT_LOG_DIR', tmp), \
                    patch.object(audit_logger, 'AUDIT_HMAC_SECRET', ''):
                res = audit_logger.verify_audit_integrity()
        self.assertEqual(res['total'], 10_050)
        self.assertEqual(res['chain_breaks'], 0)
        self.assertEqual(res['invalid'], 0)

    def test_linha_corrompida_conta_como_invalida(self):
        with tempfile.TemporaryDirectory() as tmp:
            trail = Path(tmp) / 'audit_trail.jsonl'
            with patch.object(audit_logger, 'AUDIT_LOG_FILE', str(trail)), \
                    patch.object(audit_logger, 'AUDIT_LOG_DIR', tmp), \
                    patch.object(audit_logger, 'AUDIT_HMAC_SECRET', ''):
                audit_logger.log_audit_event('a')
                with open(trail, 'a', encoding='utf-8') as fh:
                    fh.write('{isto não é json\n')
                res = audit_logger.verify_audit_integrity()
        self.assertEqual(res['total'], 2)
        self.assertEqual(res['invalid'], 1)

    def test_falha_de_escrita_e_sinalizada(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / 'sou_um_diretorio'
            destino.mkdir()
            with patch.object(audit_logger, 'AUDIT_LOG_FILE', str(destino)), \
                    patch.object(audit_logger, 'AUDIT_LOG_DIR', tmp):
                ev = audit_logger.log_audit_event('a')
        self.assertFalse(ev['_persisted'])


class TestRetencaoDoCacheAssinado(unittest.TestCase):
    """A poda tratava as chaves do envelope como IPs e destruía a assinatura."""

    def test_envelope_assinado_nao_e_podado(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {'CACHE_HMAC_SECRET': 'segredo'}):
            pkg = build_signed_package({'8.8.8.8': {'_cached_at': 1}})
            path = Path(tmp) / 'ip_cache.json'
            path.write_text(json.dumps(pkg), encoding='utf-8')
            r = prune_ip_cache(path, max_age_days=7)
            self.assertEqual(r.get('skipped'), 'signed')
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), pkg)


class TestExportsSanitizados(unittest.TestCase):
    """CSV de interceptação e IOC saíam sem neutralizar fórmulas."""

    def test_csv_da_interceptacao(self):
        from pages_app.interceptacao import _csv_interceptacao
        df = pd.DataFrame({'Sender IP': ['8.8.8.8'], 'Ip_Dono': ['=cmd|calc']})
        csv = _csv_interceptacao(df, ('teste-sanitizacao',)).decode('utf-8-sig')
        self.assertIn("'=cmd|calc", csv)

    def test_csv_de_ioc(self):
        df = pd.DataFrame({'Ip': ['8.8.8.8'], 'Ip_Dono': ['=HYPERLINK("x")'],
                           'Ip_Cidade': ['+1'], 'Ip_Proxy': [True]})
        csv = export_ioc_csv(df)
        self.assertIn("'=HYPERLINK", csv)


class TestRelatorioHtml(unittest.TestCase):

    def _df(self, dono):
        n = 30
        return pd.DataFrame({
            'Ip': [f'8.8.8.{i}' for i in range(n)], 'Data': ['2024-03-05 10:00:00'] * n,
            'Ip_Dono': [dono] * 10 + [f'P{i}' for i in range(n - 10)],
            'Ip_Pais': ['Brasil'] * n, 'Ip_Cidade': ['SP'] * n, 'Ip_Regiao': ['SP'] * n,
            'Ip_Lat': [-23.5] * n, 'Ip_Lon': [-46.6] * n,
            'Ip_Proxy': [False] * n, 'Ip_Hospedagem': [False] * n, 'Ip_Movel': [False] * n,
        })

    def test_script_em_campo_de_dado_sai_escapado(self):
        from html_report_generator import generate_html_report
        html = generate_html_report(self._df('<script>alert(1)</script>'), 'alvo').decode('utf-8')
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)', html)

    def test_tabela_truncada_declara_total_e_secao_omitida_aparece(self):
        from html_report_generator import generate_html_report
        html = generate_html_report(
            self._df('Claro'), 'alvo',
            config={'secoes_omitidas': ['Silêncio digital (erro: teste)']}).decode('utf-8')
        self.assertIn('Exibindo 15 de 21 provedores', html)
        self.assertIn('Silêncio digital (erro: teste)', html)



def _pagina_resultados_em_ingles():
    """Script do AppTest: roda autocontido, sem acesso ao escopo do teste."""
    import os
    import sys
    sys.path.insert(0, os.getcwd())
    import pandas as pd
    import streamlit as st
    from pages_app.resultados import page_resultados
    st.session_state['lang'] = 'en'
    if st.session_state.get('df_resultado') is None:
        st.session_state['df_resultado'] = pd.DataFrame({
            'Ip': ['8.8.8.8', '1.1.1.1'], 'Data': ['2024-01-01 10:00:00'] * 2,
            'Ip_Dono': ['Google', 'Cloudflare'], 'Ip_Regiao': ['CA', 'CA'],
            'Ip_Proxy': [False, False], 'Ip_Hospedagem': [False, False],
            'Ip_Movel': [False, False]})
    st.session_state.setdefault('output_file', '')
    st.session_state.setdefault('alvo', '')
    page_resultados()


class TestFiltroTodosEmIngles(unittest.TestCase):
    """Em inglês o filtro padrão buscava Ip_Dono == 'Todos': tabela vazia."""

    def test_filtro_padrao_mostra_tudo(self):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_function(_pagina_resultados_em_ingles, default_timeout=60).run()
        self.assertFalse(at.exception, [e.value for e in at.exception])
        self.assertEqual(at.selectbox[0].value, 'All')
        self.assertIn('2 of 2 records', [c.value for c in at.caption])


def _pagina_entrada_com_sessao_gravada():
    # Sem acentos neste corpo: no Windows o AppTest grava o script em cp1252 e
    # o Streamlit o le como UTF-8 - o script falha sem erro visivel.
    """Script do AppTest: sessao gravada num diretorio temporario (via env)."""
    import os
    import sys
    from pathlib import Path
    sys.path.insert(0, os.getcwd())
    import streamlit as st
    import helpers.persistence as persistence
    import audit_logger
    # O script roda no processo do teste: sem restaurar, os caminhos
    # temporarios (ja apagados) valeriam para os testes seguintes.
    anteriores = (persistence.DATA_DIR, audit_logger.AUDIT_LOG_DIR, audit_logger.AUDIT_LOG_FILE)
    persistence.DATA_DIR = Path(os.environ['LE_TEST_SESSIONS'])
    audit_logger.AUDIT_LOG_DIR = os.environ['LE_TEST_SESSIONS']
    audit_logger.AUDIT_LOG_FILE = os.path.join(os.environ['LE_TEST_SESSIONS'], 'audit.jsonl')
    try:
        from pages_app.entrada import page_entrada
        defaults = {'df_resultado': None, 'alvo': '', 'output_file': 'resultado_logs.csv',
                    'processing': False, 'log_messages': [], 'history': [], 'batch_size': 500,
                    'period': 0, 'use_cache': True, 'incremental': True, 'api_key': ''}
        for k, v in defaults.items():
            st.session_state.setdefault(k, v)
        page_entrada()
    finally:
        persistence.DATA_DIR, audit_logger.AUDIT_LOG_DIR, audit_logger.AUDIT_LOG_FILE = anteriores


class TestRestauracaoSoComClique(unittest.TestCase):
    """Abrir o app restaurava o último alvo processado por qualquer pessoa."""

    def test_nada_e_carregado_sem_clique(self):
        from streamlit.testing.v1 import AppTest
        import helpers.persistence as persistence
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(persistence, 'DATA_DIR', Path(tmp)):
                persistence.save_dataframe(
                    pd.DataFrame({'Ip': ['8.8.8.8'], 'Data': ['2024-01-01 10:00:00']}),
                    name='current', alvo='alvo-de-outra-pessoa')
            with patch.dict(os.environ, {'LE_TEST_SESSIONS': tmp}):
                at = AppTest.from_function(_pagina_entrada_com_sessao_gravada,
                                           default_timeout=60).run()
                self.assertFalse(at.exception, [e.value for e in at.exception])
                self.assertIsNone(at.session_state['df_resultado'])
                self.assertTrue(any('alvo-de-outra-pessoa' in m.value for m in at.markdown))
                botao = [b for b in at.button if b.key == 'btn_restore_session']
                self.assertEqual(len(botao), 1)
                at = botao[0].click().run()
                self.assertFalse(at.exception, [e.value for e in at.exception])
                self.assertEqual(len(at.session_state['df_resultado']), 1)

if __name__ == '__main__':
    unittest.main()
