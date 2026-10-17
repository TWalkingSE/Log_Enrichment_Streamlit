"""Modo incremental de `processar_log_acesso_async`: a saída já existe e o
log novo é mesclado a ela.

IP já enriquecido não volta à API. Antes, as linhas dele no log novo saíam
sem enriquecimento — com os booleanos no default, um proxy virava "não
proxy" — e o dedup com keep='last' as punha no lugar das antigas,
enriquecidas. Sem nenhum IP novo, os registros novos nem entravam.
"""
from tests.common import *

from data_processor import FORMATO_DISCORD

PROXY = '198.51.100.16'
IP_NOVO = '203.0.113.77'
LINHA_IP_NOVO = f'2025-05-10 08:00:00    {IP_NOVO}\n'
# O exemplo sem a última sessão (198.51.100.16 em 2025-05-11 13:56:56):
# IP já conhecido, data nova.
SEM_ULTIMA = '\n'.join(FORMATO_DISCORD.splitlines()[:-1]) + '\n'
# Só o cabeçalho da conta e uma sessão de IP novo.
SO_IP_NOVO = FORMATO_DISCORD.split('Session Start')[0] + 'Session Start (UTC)    IP Address\n' + LINHA_IP_NOVO


class _EnrichSimulado:
    """`enrich_ips` sem rede: registra os IPs pedidos, um provedor por IP."""

    def __init__(self):
        self.pedidos = []
        self.falham = set()

    async def __call__(self, ips, **_kwargs):
        self.pedidos.append(sorted(ips))
        return ({ip: self._falha() if ip in self.falham else self._sucesso(ip) for ip in ips},
                None)

    @staticmethod
    def _sucesso(ip):
        return {'Ip_Dono': f'Prov {ip}', 'Ip_AS': f'AS {ip}', 'Ip_Cidade': f'Cidade {ip}',
                'Ip_Proxy': ip == PROXY, 'Ip_Lat': -23.5, 'Ip_Lon': -46.6, 'status': 'success'}

    @staticmethod
    def _falha():
        # Forma do erro de `IPAPIClient`: os valores `Erro` não entram no frame.
        return {'Ip_Dono': 'Erro: timeout', 'Ip_AS': 'Erro', 'Ip_Cidade': 'Erro',
                'Ip_Proxy': False, 'Ip_Lat': None, 'Ip_Lon': None, 'status': 'fail'}


class TestIncremental(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.saida = os.path.join(self._tmp.name, 'resultado.csv')
        self.enrich = _EnrichSimulado()
        self.mensagens = []

    def tearDown(self):
        self._tmp.cleanup()

    def _processar(self, conteudo):
        from file_handler import processar_log_acesso_async
        from helpers.shared import run_async
        with patch('enrich_service.enrich_ips', new=self.enrich):
            return run_async(processar_log_acesso_async(
                conteudo, self.saida, is_file=False,
                cache_file=os.path.join(self._tmp.name, 'cache.json'),
                update_callback=self.mensagens.append))

    def _csv(self):
        return pd.read_csv(self.saida, sep=';', encoding='utf-8-sig', dtype=str,
                           keep_default_na=False)

    def _gravar_csv(self, df):
        df.to_csv(self.saida, sep=';', encoding='utf-8-sig', index=False)

    def _assert_enriquecido(self, df):
        """Toda linha traz o enriquecimento do próprio IP."""
        self.assertEqual(list(df['Ip_Dono']), [f'Prov {ip}' for ip in df['Ip']])
        self.assertEqual(list(df['Ip_Cidade']), [f'Cidade {ip}' for ip in df['Ip']])
        self.assertEqual([str(v) for v in df['Ip_Proxy']], [str(ip == PROXY) for ip in df['Ip']])
        self.assertEqual([float(v) for v in df['Ip_Lat']], [-23.5] * len(df))
        self.assertTrue(df['Reputação'].astype(str).str.strip().ne('').all())
        self.assertFalse(df['Reputação'].isna().any())

    def test_ip_novo_nao_apaga_o_enriquecimento_dos_conhecidos(self):
        self._processar(SEM_ULTIMA)
        df = self._processar(FORMATO_DISCORD + LINHA_IP_NOVO)

        # Só o IP novo foi à API; os conhecidos vieram do arquivo.
        self.assertEqual(self.enrich.pedidos[1], [IP_NOVO])
        self.assertEqual(len(df), 6)
        self._assert_enriquecido(df)
        self._assert_enriquecido(self._csv())
        # O proxy continua proxy em todas as linhas, inclusive na nova.
        proxy = df[df['Ip'] == PROXY]
        self.assertEqual(len(proxy), 3)
        self.assertTrue(proxy['Reputação'].str.contains('Proxy').all())

    def test_sem_ip_novo_o_registro_novo_entra_enriquecido(self):
        self._processar(SEM_ULTIMA)
        df = self._processar(FORMATO_DISCORD)

        self.assertEqual(len(self.enrich.pedidos), 1)  # nenhuma consulta nova
        self.assertEqual(len(df), 5)
        self._assert_enriquecido(df)
        csv = self._csv()
        self.assertEqual(len(csv), 5)
        self._assert_enriquecido(csv)

    def test_linha_antiga_sem_enriquecimento_e_reparada_e_declarada(self):
        # Saída como a versão anterior deixava: uma linha do proxy vazia,
        # com o booleano no default.
        self._processar(FORMATO_DISCORD)
        csv = self._csv()
        vazia = csv.index[csv['Ip'] == PROXY][-1]
        for col in ('Ip_Dono', 'Ip_AS', 'Ip_Cidade', 'Ip_Lat', 'Ip_Lon'):
            csv.loc[vazia, col] = ''
        csv.loc[vazia, 'Ip_Proxy'] = 'False'
        self._gravar_csv(csv)

        df = self._processar(SO_IP_NOVO)

        self.assertEqual(self.enrich.pedidos[1], [IP_NOVO])
        self.assertEqual(len(df), 6)
        self._assert_enriquecido(df)
        self._assert_enriquecido(self._csv())
        self.assertTrue(any('1 registros do arquivo existente' in m for m in self.mensagens),
                        self.mensagens)

    def test_ip_com_enriquecimento_divergente_nao_e_escolhido(self):
        self._processar(SEM_ULTIMA)
        csv = self._csv()
        csv.loc[csv.index[csv['Ip'] == PROXY][0], 'Ip_Dono'] = 'Outro provedor'
        self._gravar_csv(csv)

        df = self._processar(FORMATO_DISCORD)

        self.assertEqual(len(self.enrich.pedidos), 1)
        nova = df[(df['Ip'] == PROXY) & ~df['Data'].isin(csv['Data'])]
        self.assertEqual(len(nova), 1)
        self.assertTrue(pd.isna(nova['Ip_Dono'].iloc[0]))
        self.assertTrue(any('mais de um enriquecimento' in m for m in self.mensagens),
                        self.mensagens)
        # As linhas antigas ficam como estavam.
        antigas = df[df['Data'].isin(csv['Data'])].set_index('Data')['Ip_Dono']
        self.assertEqual(antigas.to_dict(), csv.set_index('Data')['Ip_Dono'].to_dict())


    def test_ip_que_falhou_antes_continua_vazio_e_nao_quebra_a_mescla(self):
        # O Ip_AS vazio volta do CSV como NaN, e a Reputação é recalculada
        # para todas as linhas: a combinação com NaN dava KeyError.
        falhou = '198.51.100.12'
        self.enrich.falham.add(falhou)
        self._processar(FORMATO_DISCORD)
        self.assertEqual(self._csv().loc[lambda d: d['Ip'] == falhou, 'Ip_AS'].tolist(), [''])

        df = self._processar(SO_IP_NOVO)

        # Fora do log novo ele não é consultado, e sem enriquecimento no
        # arquivo o registro antigo não é preenchido com nada.
        self.assertEqual(self.enrich.pedidos[1], [IP_NOVO])
        self.assertEqual(len(df), 6)
        vazio = df[df['Ip'] == falhou]
        self.assertEqual(len(vazio), 1)
        self.assertTrue(pd.isna(vazio['Ip_Dono'].iloc[0]))
        self._assert_enriquecido(df[df['Ip'] != falhou])
        self.assertFalse(df['Reputação'].isna().any())

if __name__ == '__main__':
    unittest.main()
