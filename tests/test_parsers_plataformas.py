"""Parsers do Discord, do Preservation Google e do texto livre.

Os dois primeiros não tinham nenhum teste. Os exemplos são os mesmos que a
página de Entrada oferece em "Carregar exemplo" (`FORMATO_*`), mais variações
das armadilhas de cada formato.
"""
from tests.common import *
from datetime import datetime as _dt
from pathlib import Path

from data_processor import (
    COLUNAS_EXPORT_DISCORD, COLUNAS_EXPORT_PRESERVATION_GOOGLE,
    FORMATO_DISCORD, FORMATO_PRESERVATION_GOOGLE, TZ_OFFSET_HOURS,
    convert_utc_to_local, detectar_formato_log, extrair_ips_de_texto,
    extrair_ips_do_formato_discord, extrair_ips_do_formato_preservation_google,
    extrair_ips_texto_simples,
)


def _local(utc_str):
    """Mesmo cálculo do parser: UTC -> fuso configurado (TZ_OFFSET_HOURS)."""
    return convert_utc_to_local(_dt.strptime(utc_str, '%Y-%m-%d %H:%M:%S')).strftime(
        '%Y-%m-%d %H:%M:%S')


class TestDiscord(unittest.TestCase):

    def test_detecta_formato(self):
        self.assertEqual(detectar_formato_log(FORMATO_DISCORD), 'discord')

    def test_sessoes_convertidas_de_utc(self):
        df = extrair_ips_do_formato_discord(FORMATO_DISCORD)
        self.assertEqual(len(df), 5)
        self.assertEqual(df['Ip'].tolist()[0], '198.51.100.13')
        self.assertEqual(df['Data'].tolist()[0], _local('2025-05-14 00:47:29'))
        self.assertTrue(df['ISO_Date'].iloc[0].endswith(f"{TZ_OFFSET_HOURS:+03d}:00"))

    def test_metadados_do_usuario_em_todas_as_linhas(self):
        df = extrair_ips_do_formato_discord(FORMATO_DISCORD)
        self.assertEqual(set(df['User_ID']), {'1234567890123456789'})
        self.assertEqual(set(df['Username']), {'usuario_exemplo#0'})
        self.assertEqual(set(df['Email']), {'usuario@example.com'})
        # Sem alvo informado, o email identifica o alvo.
        self.assertEqual(set(df['Alvo']), {'usuario@example.com'})
        for col in ('User_ID', 'Username', 'Email'):
            self.assertIn(col, COLUNAS_EXPORT_DISCORD)

    def test_alvo_informado_prevalece(self):
        df = extrair_ips_do_formato_discord(FORMATO_DISCORD, alvo='caso-42')
        self.assertEqual(set(df['Alvo']), {'caso-42'})

    def test_registration_ip_entra_quando_valido(self):
        txt = FORMATO_DISCORD.replace('Registration IP:             Not found',
                                      'Registration IP:             203.0.113.9')
        df = extrair_ips_do_formato_discord(txt)
        self.assertEqual(len(df), 6)
        reg = df[df['Ip'] == '203.0.113.9']
        self.assertEqual(reg['Data'].tolist(), [_local('2025-04-29 18:00:50')])

    def test_ip_invalido_e_cabecalho_repetido_sao_ignorados(self):
        txt = FORMATO_DISCORD + ('\nSession Start (UTC)    IP Address\n'
                                 '2025-05-10 10:00:00    999.1.1.1\n'
                                 '2025-05-10 11:00:00    2001:db8::1\n')
        df = extrair_ips_do_formato_discord(txt)
        self.assertNotIn('999.1.1.1', df['Ip'].tolist())
        self.assertIn('2001:db8::1', df['Ip'].tolist())

    def test_sem_sessoes_devolve_colunas_do_modelo(self):
        df = extrair_ips_do_formato_discord('User ID: 1\nUsername: x\n')
        self.assertTrue(df.empty)
        self.assertIn('Ip', df.columns)

    def test_roteado_pelo_extrator_de_texto(self):
        df = extrair_ips_de_texto(FORMATO_DISCORD, is_file=False)
        self.assertIn('User_ID', df.columns)
        self.assertEqual(len(df), 5)


class TestPreservationGoogle(unittest.TestCase):

    def test_detecta_formato(self):
        self.assertEqual(detectar_formato_log(FORMATO_PRESERVATION_GOOGLE), 'preservation_google')

    def test_linhas_convertidas_com_user_agent(self):
        df = extrair_ips_do_formato_preservation_google(FORMATO_PRESERVATION_GOOGLE)
        self.assertEqual(len(df), 3)
        self.assertEqual(df['Data'].tolist()[0], _local('2026-03-11 02:49:39'))
        self.assertTrue(df['User_Agent'].iloc[0].startswith('App : YOUTUBE_APP'))
        self.assertIn('User_Agent', COLUNAS_EXPORT_PRESERVATION_GOOGLE)
        # User_Agent logo depois de Ip, como no export.
        cols = list(df.columns)
        self.assertEqual(cols.index('User_Agent'), cols.index('Ip') + 1)

    def test_nao_roteavel_e_excluido_em_qualquer_grafia(self):
        cab = FORMATO_PRESERVATION_GOOGLE.splitlines()[0]
        for token in ('Yes', 'yes', 'TRUE', '1'):
            linha = (f'1,2026-03-11 01:00:00 UTC,10.0.0.1,,{token},UA,Gmail')
            df = extrair_ips_do_formato_preservation_google(cab + '\n' + linha + '\n'
                                                            + FORMATO_PRESERVATION_GOOGLE.splitlines()[1])
            self.assertNotIn('10.0.0.1', df['Ip'].tolist(), token)
            self.assertEqual(len(df), 1, token)

    def test_aceita_dataframe_pre_parseado(self):
        src = pd.read_csv(io.StringIO(FORMATO_PRESERVATION_GOOGLE))
        df = extrair_ips_do_formato_preservation_google(src)
        self.assertEqual(len(df), 3)

    def test_colunas_obrigatorias_ausentes(self):
        df = extrair_ips_do_formato_preservation_google('a,b\n1,2\n')
        self.assertTrue(df.empty)

    def test_csv_pelo_loader_de_arquivos(self):
        from file_handler import carregar_arquivo_log
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'preservation.csv'
            path.write_text(FORMATO_PRESERVATION_GOOGLE, encoding='utf-8')
            df = carregar_arquivo_log(str(path), alvo='caso')
        self.assertEqual(len(df), 3)
        self.assertIn('User_Agent', df.columns)
        self.assertEqual(set(df['Alvo']), {'caso'})


class TestTextoLivre(unittest.TestCase):
    """A data vale para os IPs da mesma linha — nunca por posição no texto."""

    TEXTO = ('Log do alvo\n'
             '8.8.8.8 05/03/2024 22:10:00\n'
             'linha sem data 9.9.9.9\n'
             '1.1.1.1 13/03/2024 08:00\n'
             '2.2.2.2 01/01/2024 10:00 e 02/01/2024 11:00\n')

    def test_data_da_propria_linha(self):
        df = extrair_ips_de_texto(self.TEXTO, is_file=False).set_index('Ip')
        self.assertEqual(df.loc['8.8.8.8', 'Data'], '2024-03-05 22:10:00')
        self.assertEqual(df.loc['1.1.1.1', 'Data'], '2024-03-13 08:00:00')
        # Linha sem data não herda a data da vizinha.
        self.assertIsNone(df.loc['9.9.9.9', 'Data'])
        # Duas datas na linha: ambíguo, sem data.
        self.assertIsNone(df.loc['2.2.2.2', 'Data'])

    def test_marcador_utc_na_linha_converte(self):
        df = extrair_ips_de_texto('2001:db8::5 2024-03-14T14:30:00Z\n', is_file=False)
        self.assertEqual(df['Data'].iloc[0], _local('2024-03-14 14:30:00'))

    def test_metodo_alternativo_usa_data_do_arquivo_so_nas_linhas_sem_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'export_20250310123909.txt'
            path.write_text('8.8.8.8 05/03/2024 22:10:00\n9.9.9.9 sem data\n', encoding='utf-8')
            df = extrair_ips_texto_simples(str(path)).set_index('Ip')
        self.assertEqual(df.loc['8.8.8.8', 'Data'], '2024-03-05 22:10:00')
        self.assertEqual(df.loc['9.9.9.9', 'Data'], '2025-03-10 12:39:09')

    def test_repetidos_sao_mantidos(self):
        df = extrair_ips_de_texto('8.8.8.8\n8.8.8.8\n', is_file=False)
        self.assertEqual(len(df), 2)


if __name__ == '__main__':
    unittest.main()
