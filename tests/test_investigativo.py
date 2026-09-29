"""Análise investigativa (`ip_investigativo`): score, seleção e resumo narrativo.

O resumo narrativo é copiado para o laudo; os testes de `TestResumoNarrativo`
fixam que ele só afirma o que os dados mostram.
"""
import unittest
from datetime import datetime

import pandas as pd

from ip_investigativo import (
    agrupar_ipv6_por_prefixo, calcular_score, detectar_cgnat, detectar_ips_atencao,
    detectar_usuario_unico, gerar_resumo_narrativo, selecionar_provedores,
    sugerir_ips_investigativos,
)

FATO = datetime(2024, 3, 10, 14, 0, 0)


def _df(linhas):
    """linhas: (ip, data, provedor, proxy, hosting, periodo)."""
    return pd.DataFrame([{
        'Ip': ip, 'Data': data, 'Ip_Dono': prov, 'Ip_Proxy': proxy, 'Ip_Hospedagem': host,
        'Periodo': periodo, 'Ip_Cidade': 'Sao Paulo', 'Ip_AS': 'AS1 Teste',
    } for ip, data, prov, proxy, host, periodo in linhas])


def _caso_tipico():
    """Três provedores residenciais + um de hospedagem, IPv6 e IPv4, antes/no dia/depois."""
    linhas = []
    for i in range(6):  # Claro: IPv6, antes, no dia e depois do fato
        linhas.append((f'2001:db8:1:1::{i + 1}', f'2024-03-{5 + i * 2:02d} 1{i}:00:00',
                       'Claro', False, False, '☀️ Diurno'))
    for i in range(3):  # Vivo: IPv4, noite
        linhas.append((f'200.1.1.{i + 1}', f'2024-03-{8 + i:02d} 23:00:00', 'Vivo', False, False, '🌙 Noturno'))
    for i in range(2):  # Tim
        linhas.append((f'189.1.1.{i + 1}', f'2024-03-{9 + i:02d} 09:00:00', 'Tim', False, False, '☀️ Diurno'))
    for i in range(4):  # hospedagem: não entra na seleção de provedores
        linhas.append((f'52.1.1.{i + 1}', f'2024-03-{9 + i:02d} 03:00:00', 'Amazon', False, '1', '🌙 Noturno'))
    return _df(linhas)


class TestSelecionarProvedores(unittest.TestCase):

    def test_top3_sem_proxy_e_hospedagem(self):
        provs, contagem, pct = selecionar_provedores(_caso_tipico())
        self.assertEqual(provs, ['Claro', 'Vivo', 'Tim'])
        self.assertNotIn('Amazon', contagem)
        self.assertEqual(pct, 100.0)

    def test_so_proxy_cai_para_todos(self):
        df = _df([('52.1.1.1', '2024-03-09 03:00:00', 'Amazon', True, False, '')])
        provs, _, _ = selecionar_provedores(df)
        self.assertEqual(provs, ['Amazon'])

    def test_sem_coluna_de_provedor(self):
        self.assertEqual(selecionar_provedores(pd.DataFrame({'Ip': ['1.1.1.1']})), ([], {}, 0.0))


class TestCalcularScore(unittest.TestCase):

    def test_componentes_somam_como_documentado(self):
        # No horário do fato (40) + provedor mais frequente (20) + período igual
        # (15) + registros antes e depois do mesmo provedor (15) + IPv6 (5) = 95.
        df = _df([
            ('2001:db8::1', '2024-03-10 14:00:00', 'Claro', False, False, '☀️ Diurno'),
            ('2001:db8::2', '2024-03-09 10:00:00', 'Claro', False, False, '☀️ Diurno'),
            ('2001:db8::3', '2024-03-11 10:00:00', 'Claro', False, False, '☀️ Diurno'),
        ])
        _, contagem, _ = selecionar_provedores(df)
        out = calcular_score(df, FATO, 'Diurno', contagem, janela_horas_max=72)
        self.assertEqual(out.loc[0, 'Score'], 95.0)
        self.assertEqual(out.attrs['score_falhas'], 0)

    def test_proxy_textual_penaliza(self):
        base = ('2001:db8::1', '2024-03-10 14:00:00', 'Claro', False, False, '☀️ Diurno')
        df = _df([base, base[:3] + ('VERDADEIRO', False, '☀️ Diurno')])
        _, contagem, _ = selecionar_provedores(df)
        out = calcular_score(df, FATO, 'Diurno', contagem)
        self.assertEqual(out.loc[0, 'Score'] - out.loc[1, 'Score'], 10.0)

    def test_fora_da_janela_nao_ganha_proximidade(self):
        df = _df([('200.1.1.1', '2024-01-01 14:00:00', 'Claro', False, False, '')])
        out = calcular_score(df, FATO, 'Diurno', {'Claro': 1}, janela_horas_max=72)
        # Recorrência do provedor (20) + continuidade parcial, só "antes" (7);
        # nada de proximidade temporal.
        self.assertEqual(out.loc[0, 'Score'], 27.0)

    def test_sem_coluna_de_provedor_nao_quebra(self):
        df = pd.DataFrame({'Ip': ['200.1.1.1'], 'Data': ['2024-03-10 14:00:00']})
        out = calcular_score(df, FATO, 'Diurno', {})
        self.assertEqual(out.loc[0, 'Score'], 40.0)

    def test_data_brasileira_e_dia_mes(self):
        # 10/03/2024 é 10 de março (o dia do fato), não 3 de outubro.
        df = pd.DataFrame({'Ip': ['200.1.1.1'], 'Data': ['10/03/2024 14:00:00'], 'Ip_Dono': ['X']})
        out = calcular_score(df, FATO, 'Diurno', {'X': 1})
        self.assertGreaterEqual(out.loc[0, 'Score'], 40.0)


class TestUsuarioUnico(unittest.TestCase):

    def test_indicadores(self):
        df = _df([
            ('200.1.1.1', '2024-03-09 10:00:00', 'Claro', '0', False, '☀️ Diurno'),
            ('200.1.1.1', '2024-03-11 10:00:00', 'Claro', '0', False, '☀️ Diurno'),
        ])
        r = detectar_usuario_unico(df, FATO)
        # provedor único 30 + antes e depois 25 + 100% num período 20 + IP
        # repetido 15 + nenhum proxy 10.
        self.assertEqual(r['score'], 100)

    def test_proxy_textual_conta(self):
        df = _df([('200.1.1.1', '2024-03-09 10:00:00', 'Claro', '1', False, '☀️ Diurno')])
        self.assertIn('❌', detectar_usuario_unico(df, FATO)['indicadores']['Proxy'])


class TestSugerirIps(unittest.TestCase):

    def setUp(self):
        self.df = _caso_tipico()
        self.provs, self.contagem, _ = selecionar_provedores(self.df)
        self.scored = calcular_score(self.df, FATO, 'Diurno', self.contagem)

    def test_respeita_limite_por_provedor(self):
        sel = sugerir_ips_investigativos(self.scored, FATO, self.provs, self.contagem, ips_por_provedor=3)
        self.assertTrue((sel.groupby('Provedor_Selecionado').size() <= 3).all())
        self.assertEqual(set(sel['Provedor_Selecionado']), set(self.provs))

    def test_ipv6_tem_prioridade_e_ancoras_nas_pontas(self):
        sel = sugerir_ips_investigativos(self.scored, FATO, ['Claro'], self.contagem, ips_por_provedor=3)
        self.assertTrue(sel['Ip'].str.contains(':').all())
        claro = self.df[self.df['Ip_Dono'] == 'Claro'].sort_values('Data')
        self.assertIn(claro['Ip'].iloc[0], sel['Ip'].tolist())
        self.assertIn(claro['Ip'].iloc[-1], sel['Ip'].tolist())

    def test_sem_provedor_devolve_vazio(self):
        self.assertTrue(sugerir_ips_investigativos(self.scored, FATO, [], {}).empty)


class TestIpsDeAtencao(unittest.TestCase):

    def test_proxy_e_hospedagem_sem_corte_e_um_por_ip(self):
        linhas = [(f'52.1.1.{i}', '2024-03-01 03:00:00', 'Amazon', False, '1', '') for i in range(12)]
        linhas += [('52.1.1.0', '2024-03-02 03:00:00', 'Amazon', False, '1', '')]  # repetido
        df = _df(linhas)
        df['Score'] = 0.0
        out = detectar_ips_atencao(df, FATO, ['Claro'])
        # Antes a lista parava em 5 sem dizer quantos havia.
        self.assertEqual(len(out), 12)
        self.assertEqual(out['Ip'].nunique(), 12)

    def test_ip_do_dia_do_fato_fora_do_top3(self):
        df = _df([('8.8.8.8', '2024-03-10 09:00:00', 'Outro', False, False, '')])
        df['Score'] = 10.0
        out = detectar_ips_atencao(df, FATO, ['Claro'])
        self.assertIn('8.8.8.8', out['Ip'].tolist())


class TestIpv6ECgnat(unittest.TestCase):

    def test_agrupa_por_prefixo_64(self):
        df = pd.DataFrame({'Ip': ['2001:db8:1:1::1', '2001:db8:1:1::2', '2001:db8:1:1::2',
                                  '2001:db8:9:9::1', '200.1.1.1'],
                           'Ip_Dono': ['A'] * 5, 'Ip_Cidade': ['X'] * 5})
        g = agrupar_ipv6_por_prefixo(df).set_index('Prefixo_64')
        self.assertEqual(g.loc['2001:0db8:0001:0001::/64', 'Qtd_IPs'], 2)
        self.assertEqual(g.loc['2001:0db8:0001:0001::/64', 'Qtd_Registros'], 3)
        self.assertEqual(len(g), 2)

    def test_cgnat(self):
        r = detectar_cgnat(pd.DataFrame({'Ip': ['100.64.0.1', '100.127.255.1', '8.8.8.8']}))
        self.assertEqual(r['count'], 2)


class TestResumoNarrativo(unittest.TestCase):

    def _resumo(self, df, provs=None):
        _, contagem, _ = selecionar_provedores(df)
        provs = provs if provs is not None else list(contagem)[:3]
        scored = calcular_score(df, FATO, 'Diurno', contagem)
        sel = sugerir_ips_investigativos(scored, FATO, provs, contagem)
        return gerar_resumo_narrativo(scored, sel, provs, contagem, FATO, alvo='teste')

    def test_contagem_ipv4_ipv6_sobre_ips_unicos(self):
        # 1 IPv6 repetido 5x + 2 IPv4: antes saía "3 únicos (5 IPv6, -2 IPv4)".
        linhas = [('2001:db8::1', f'2024-03-0{i + 1} 10:00:00', 'Claro', False, False, '') for i in range(5)]
        linhas += [('200.1.1.1', '2024-03-09 10:00:00', 'Claro', False, False, ''),
                   ('200.1.1.2', '2024-03-11 10:00:00', 'Claro', False, False, '')]
        texto = self._resumo(_df(linhas))
        self.assertIn('3 endereços IP únicos (1 IPv6, 2 IPv4)', texto)

    def test_nao_afirma_ipv6_nem_depois_do_fato_sem_dados(self):
        # Só IPv4, todos antes do fato, todos à noite.
        linhas = [(f'200.1.1.{i}', f'2024-03-0{i + 1} 23:00:00', 'Claro', False, False, '') for i in range(4)]
        texto = self._resumo(_df(linhas))
        conclusao = texto.split('CONCLUSÃO:')[1]
        self.assertNotIn('predominância de endereços IPv6', conclusao)
        self.assertIn('Não há endereços IPv6', conclusao)
        self.assertIn('registros antes da data do fato', conclusao)
        self.assertIn('nem depois', conclusao)
        self.assertIn('apenas em horário noturno', conclusao)
        self.assertNotIn('uso continuado', conclusao)

    def test_proxy_selecionado_e_declarado(self):
        linhas = [(f'52.1.1.{i}', f'2024-03-{8 + i:02d} 10:00:00', 'Amazon', '1', False, '') for i in range(4)]
        texto = self._resumo(_df(linhas), provs=['Amazon'])
        self.assertIn('classificados como proxy/VPN ou hospedagem', texto)
        self.assertNotIn('Nenhum dos endereços selecionados', texto)

    def test_caso_completo_afirma_o_que_os_dados_sustentam(self):
        conclusao = self._resumo(_caso_tipico()).split('CONCLUSÃO:')[1]
        self.assertIn('antes, no dia, depois', conclusao)
        self.assertIn('diurno e noturno', conclusao)
        self.assertIn('uso continuado', conclusao)


if __name__ == '__main__':
    unittest.main()
