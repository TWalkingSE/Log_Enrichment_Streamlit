"""Parsers do Discord, do Preservation Google, do Google Aggregated
Activities e do texto livre.

Os dois primeiros não tinham nenhum teste. Os exemplos são os mesmos que a
página de Entrada oferece em "Carregar exemplo" (`FORMATO_*`), mais variações
das armadilhas de cada formato.
"""
from tests.common import *
from datetime import datetime as _dt
from pathlib import Path

from data_processor import (
    COLUNAS_EXPORT, COLUNAS_EXPORT_DISCORD, COLUNAS_EXPORT_GOOGLE_ATIVIDADES,
    COLUNAS_EXPORT_GOOGLE_CONEXOES, COLUNAS_EXPORT_META, COLUNAS_EXPORT_PRESERVATION_GOOGLE,
    COLUNAS_EXPORT_TIKTOK, FORMATO_DISCORD, FORMATO_GOOGLE_ATIVIDADES, FORMATO_GOOGLE_CONEXOES,
    FORMATO_PRESERVATION_GOOGLE, TZ_LABEL, TZ_OFFSET_HOURS, colunas_export_para,
    convert_utc_to_local, detectar_formato_log, extrair_ips_de_texto,
    extrair_ips_do_formato_discord, extrair_ips_do_formato_google_atividades,
    extrair_ips_do_formato_google_conexoes, extrair_ips_do_formato_preservation_google,
    extrair_ips_texto_simples, familia_formato, formato_google_agregado, processar_resultados,
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


class TestGoogleAgregadoDeteccao(unittest.TestCase):
    """Os dois CSVs "Aggregated Activities" se reconhecem pelo cabeçalho."""

    def test_detecta_os_dois_formatos(self):
        self.assertEqual(detectar_formato_log(FORMATO_GOOGLE_ATIVIDADES), 'google_atividades')
        self.assertEqual(detectar_formato_log(FORMATO_GOOGLE_CONEXOES), 'google_conexoes')

    def test_nao_confunde_com_preservation(self):
        # 'Activity Timestamp' do Preservation está contido em
        # 'Last Activity Timestamp': por substring, um casaria com o outro.
        self.assertEqual(detectar_formato_log(FORMATO_PRESERVATION_GOOGLE), 'preservation_google')
        self.assertIsNone(formato_google_agregado(
            FORMATO_PRESERVATION_GOOGLE.splitlines()[0].split(',')))

    def test_cabecalho_com_bom_e_ponto_e_virgula(self):
        # CSV regravado pelo Excel pt-BR: BOM e `;`.
        texto = '﻿' + FORMATO_GOOGLE_ATIVIDADES.replace(',', ';')
        self.assertEqual(detectar_formato_log(texto), 'google_atividades')

    def test_cabecalho_incompleto_nao_e_detectado(self):
        self.assertNotIn(detectar_formato_log('GAIA ID,Identifier Type,ID\n1,IP address,198.51.100.1\n'),
                         ('google_atividades', 'google_conexoes'))


class TestGoogleAtividades(unittest.TestCase):
    """CSV de serviços: uma linha por IP com o intervalo agregado pelo Google."""

    def _df(self, texto=FORMATO_GOOGLE_ATIVIDADES, **kw):
        return extrair_ips_do_formato_google_atividades(texto, **kw)

    def _com_linhas(self, *linhas):
        return FORMATO_GOOGLE_ATIVIDADES + ''.join(f'{linha}\n' for linha in linhas)

    def test_so_linhas_de_ip_e_o_resto_declarado(self):
        df = self._df()
        self.assertEqual(df['Ip'].tolist(), [
            '2001:db8:5a1e:6400:1:2:3:aa55', '198.51.100.20', '198.51.100.21',
            '2001:db8:93f7:c75b:1:2:3:f652'])
        resumo = df.attrs['google_agregado']
        self.assertEqual((resumo['linhas'], resumo['importadas'], resumo['sem_ip']), (7, 4, 3))
        self.assertEqual(resumo['ignoradas_por_tipo'],
                         {'User agent': 1, 'WebGL renderer name': 1, 'Product': 1})

    def test_datas_locais_e_data_igual_ao_ultimo_uso(self):
        df = self._df()
        self.assertEqual(df['Primeiro_Uso'].iloc[0], _local('2025-10-15 12:00:00'))
        self.assertEqual(df['Ultimo_Uso'].iloc[0], _local('2025-11-03 01:40:10'))
        self.assertEqual(df['Data'].tolist(), df['Ultimo_Uso'].tolist())
        self.assertEqual(set(df['Data_Fuso']), {TZ_LABEL})
        self.assertTrue(df['ISO_Date'].iloc[0].endswith(f"{TZ_OFFSET_HOURS:+03d}:00"))

    def test_dias_corridos_contados_em_utc(self):
        # 15/10 12:00 UTC -> 03/11 01:40 UTC: 20 dias de calendário UTC. No
        # fuso local o último uso cai em 02/11 e daria 19 — mas o Google conta
        # `Days Active` em UTC, e as duas colunas precisam ser comparáveis.
        df = self._df()
        self.assertEqual(df['Dias_Corridos'].iloc[0], 20)
        self.assertEqual(df['Dias_Ativos_Google'].iloc[0], 15)
        esperado = (_dt(2025, 11, 1) - _dt(2019, 1, 20)).days + 1
        self.assertEqual(df['Dias_Corridos'].iloc[1], esperado)

    def test_dias_ativos_do_google_preservado_mesmo_acima_do_intervalo(self):
        # O Google às vezes informa 2 dias ativos para um único instante.
        linha = self._df().iloc[3]
        self.assertEqual((linha['Dias_Ativos_Google'], linha['Dias_Corridos']), (2, 1))
        self.assertEqual(self._df().attrs['google_agregado']['dias_ativos_acima_do_periodo'], 1)

    def test_canal_de_autenticacao_e_multilogin_crus(self):
        df = self._df()
        self.assertEqual(df['Canal_Autenticacao'].tolist(),
                         ['', 'PASSWORD + PASSWORD', 'OAUTH + PASSWORD', ''])
        self.assertEqual(set(df['Multilogin']), {'NO'})

    def test_alvo_vira_gaia_id_de_21_digitos_intacto(self):
        self.assertEqual(set(self._df()['Alvo']), {'100000000000000000001'})
        self.assertEqual(set(self._df(alvo='caso-42')['Alvo']), {'caso-42'})

    def test_ip_invalido_descartado_e_contado(self):
        df = self._df(self._com_linhas(
            '1,2025-10-01 10:00:00 UTC,2025-10-01 09:00:00 UTC,1,IP address,999.1.1.1,NO,'))
        self.assertNotIn('999.1.1.1', df['Ip'].tolist())
        self.assertEqual(df.attrs['google_agregado']['ips_invalidos'], 1)

    def test_data_invalida_mantida_como_no_original(self):
        df = self._df(self._com_linhas('1,ontem,2025-10-01 09:00:00 UTC,1,IP address,198.51.100.30,NO,'))
        linha = df[df['Ip'] == '198.51.100.30'].iloc[0]
        self.assertEqual(linha['Ultimo_Uso'], 'ontem')
        self.assertEqual(linha['Data'], 'ontem')
        self.assertIsNone(linha['Dias_Corridos'])
        self.assertIsNone(linha['Data_Fuso'])
        self.assertIsNone(linha['Periodo'])
        self.assertEqual(df.attrs['google_agregado']['datas_invalidas'], 1)

    def test_linha_malformada_contada(self):
        df = self._df(self._com_linhas(
            '1,2025-10-01 10:00:00 UTC,2025-10-01 09:00:00 UTC,1,IP address,198.51.100.31,NO,,sobra'))
        self.assertEqual(len(df), 4)
        self.assertEqual(df.attrs['google_agregado']['linhas_malformadas'], 1)

    def test_colunas_extras_logo_apos_ip(self):
        cols = list(self._df().columns)
        i = cols.index('Ip')
        extras = ['Primeiro_Uso', 'Ultimo_Uso', 'Dias_Ativos_Google', 'Dias_Corridos',
                  'Canal_Autenticacao', 'Multilogin']
        self.assertEqual(cols[i + 1:i + 1 + len(extras)], extras)
        for col in extras:
            self.assertIn(col, COLUNAS_EXPORT_GOOGLE_ATIVIDADES)

    def test_aceita_dataframe_lido_como_texto(self):
        src = pd.read_csv(io.StringIO(FORMATO_GOOGLE_ATIVIDADES), dtype=str, keep_default_na=False)
        pd.testing.assert_frame_equal(extrair_ips_do_formato_google_atividades(src), self._df())

    def test_sem_ip_volta_vazio_com_resumo(self):
        cab, *linhas = FORMATO_GOOGLE_ATIVIDADES.splitlines()
        texto = '\n'.join([cab] + [linha for linha in linhas if ',IP address,' not in linha]) + '\n'
        df = extrair_ips_de_texto(texto, is_file=False)
        # Não cai no extrator genérico, que acharia "IPs" fora da coluna de IP.
        self.assertTrue(df.empty)
        self.assertEqual(df.attrs['google_agregado']['sem_ip'], 3)

    def test_roteado_pelo_extrator_de_texto(self):
        df = extrair_ips_de_texto(FORMATO_GOOGLE_ATIVIDADES, is_file=False)
        self.assertIn('Dias_Ativos_Google', df.columns)
        self.assertEqual(len(df), 4)

    def test_csv_pelo_loader_de_arquivos(self):
        from file_handler import carregar_arquivo_log
        variantes = {
            'virgula.csv': FORMATO_GOOGLE_ATIVIDADES,
            'excel_ptbr.csv': '﻿' + FORMATO_GOOGLE_ATIVIDADES.replace(',', ';'),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for nome, texto in variantes.items():
                path = Path(tmp) / nome
                path.write_text(texto, encoding='utf-8')
                df = carregar_arquivo_log(str(path))
                self.assertEqual(len(df), 4, nome)
                self.assertEqual(set(df['Alvo']), {'100000000000000000001'}, nome)
                self.assertEqual(df['Dias_Corridos'].iloc[0], 20, nome)


class TestGoogleConexoes(unittest.TestCase):
    """CSV de conexões: uma linha por par IP <-> identificador, como no arquivo."""

    def _df(self, texto=FORMATO_GOOGLE_CONEXOES, **kw):
        return extrair_ips_do_formato_google_conexoes(texto, **kw)

    def test_ip_em_qualquer_lado_do_par(self):
        df = self._df()
        self.assertEqual(len(df), 6)
        # IP no lado 1: o vinculado é o lado 2 ...
        self.assertEqual(df[['Vinculado_Tipo', 'Vinculado_Valor']].iloc[0].tolist(),
                         ['SID cookie authentication time', '2025-08-02 15:16:39 UTC'])
        # ... e no lado 2: o vinculado é o lado 1.
        self.assertEqual(df[['Vinculado_Tipo', 'Vinculado_Valor']].iloc[1].tolist(),
                         ['Font fingerprint', '1234567890123456789'])
        self.assertEqual(df['Ip'].iloc[1], '2001:db8:5a1e:6400:1:2:3:aa55')

    def test_par_sem_ip_fica_de_fora_e_e_contado(self):
        df = self._df()
        self.assertNotIn('OAuth login ID', df['Vinculado_Tipo'].tolist())
        resumo = df.attrs['google_agregado']
        self.assertEqual((resumo['linhas'], resumo['importadas'], resumo['sem_ip']), (7, 6, 1))

    def test_pares_do_mesmo_ip_e_mesmo_ultimo_uso_preservados(self):
        df = self._df()
        mesmos = df[(df['Ip'] == '2001:db8:5a1e:6400:1:2:3:aa55')
                    & (df['Data'] == _local('2025-11-02 21:38:11'))]
        self.assertEqual(mesmos['Vinculado_Tipo'].tolist(),
                         ['Font fingerprint', 'WebGL renderer name', 'Screen resolution'])

    def test_valor_com_virgula_entre_aspas(self):
        self.assertIn('ANGLE (Exemplo, Placa de Video Exemplo Direct3D11 vs_5_0 ps_5_0, D3D11)',
                      self._df()['Vinculado_Valor'].tolist())

    def test_janela_e_dias_corridos_do_par(self):
        linha = self._df().iloc[0]
        self.assertEqual(linha['Primeiro_Uso'], _local('2025-10-15 20:16:56'))
        self.assertEqual(linha['Ultimo_Uso'], _local('2025-11-03 01:25:51'))
        self.assertEqual(linha['Data'], linha['Ultimo_Uso'])
        self.assertEqual(linha['Dias_Corridos'], 20)
        self.assertNotIn('Dias_Ativos_Google', self._df().columns)

    def test_par_com_ip_dos_dois_lados_vira_duas_linhas(self):
        texto = FORMATO_GOOGLE_CONEXOES.splitlines()[0] + (
            '\n1,2025-10-02 10:00:00 UTC,2025-10-01 10:00:00 UTC,'
            'IP address,198.51.100.40,IP address,198.51.100.41\n')
        df = self._df(texto)
        self.assertEqual(df['Ip'].tolist(), ['198.51.100.40', '198.51.100.41'])
        self.assertEqual(df['Vinculado_Valor'].tolist(), ['198.51.100.41', '198.51.100.40'])
        self.assertEqual(df['Dias_Corridos'].tolist(), [2, 2])

    def test_colunas_extras_logo_apos_ip(self):
        cols = list(self._df().columns)
        i = cols.index('Ip')
        extras = ['Vinculado_Tipo', 'Vinculado_Valor', 'Primeiro_Uso', 'Ultimo_Uso', 'Dias_Corridos']
        self.assertEqual(cols[i + 1:i + 1 + len(extras)], extras)
        for col in extras:
            self.assertIn(col, COLUNAS_EXPORT_GOOGLE_CONEXOES)

    def test_csv_pelo_loader_de_arquivos(self):
        from file_handler import carregar_arquivo_log
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'conexoes.csv'
            path.write_text(FORMATO_GOOGLE_CONEXOES, encoding='utf-8')
            df = carregar_arquivo_log(str(path), alvo='caso')
        self.assertEqual(len(df), 6)
        self.assertEqual(set(df['Alvo']), {'caso'})


class TestGoogleAgregadoPipeline(unittest.TestCase):
    """Do parser ao CSV exportado, sem rede (enriquecimento simulado)."""

    def _processar(self, conteudo, saida, incremental=True):
        from unittest.mock import AsyncMock
        from file_handler import processar_log_acesso_async
        from helpers.shared import run_async
        with patch('enrich_service.enrich_ips', new=AsyncMock(return_value=({}, None))) as enrich:
            df = run_async(processar_log_acesso_async(
                conteudo, saida, is_file=False, incremental=incremental,
                cache_file=os.path.join(os.path.dirname(saida), 'cache.json')))
        return df, enrich

    def test_extras_sobrevivem_ao_merge_na_ordem(self):
        for texto, extras in (
                (FORMATO_GOOGLE_ATIVIDADES, ['Primeiro_Uso', 'Ultimo_Uso', 'Dias_Ativos_Google',
                                             'Dias_Corridos', 'Canal_Autenticacao', 'Multilogin']),
                (FORMATO_GOOGLE_CONEXOES, ['Vinculado_Tipo', 'Vinculado_Valor', 'Primeiro_Uso',
                                           'Ultimo_Uso', 'Dias_Corridos'])):
            cols = list(processar_resultados(extrair_ips_de_texto(texto, is_file=False), {}).columns)
            i = cols.index('Ip')
            self.assertEqual(cols[i + 1:i + 1 + len(extras)], extras)

    def test_colunas_de_export_por_formato(self):
        casos = {
            'google_atividades': (['Dias_Ativos_Google'], COLUNAS_EXPORT_GOOGLE_ATIVIDADES),
            'google_conexoes': (['Vinculado_Tipo'], COLUNAS_EXPORT_GOOGLE_CONEXOES),
            'discord': (['User_ID'], COLUNAS_EXPORT_DISCORD),
            'preservation_google': (['User_Agent'], COLUNAS_EXPORT_PRESERVATION_GOOGLE),
            'tiktok': (['Evento'], COLUNAS_EXPORT_TIKTOK),
            'meta': (['Porta'], COLUNAS_EXPORT_META),
            'padrao': ([], COLUNAS_EXPORT),
        }
        for familia, (extras, export) in casos.items():
            colunas = ['Ip', 'Data', *extras]
            self.assertEqual(familia_formato(colunas), familia)
            self.assertEqual(colunas_export_para(colunas), export)

    def test_ponta_a_ponta_exporta_as_colunas_do_formato(self):
        with tempfile.TemporaryDirectory() as tmp:
            saida = os.path.join(tmp, 'resultado.csv')
            self._processar(FORMATO_GOOGLE_CONEXOES, saida)
            csv_df = pd.read_csv(saida, sep=';', encoding='utf-8-sig', dtype=str)
        self.assertEqual(list(csv_df.columns), COLUNAS_EXPORT_GOOGLE_CONEXOES)
        self.assertEqual(len(csv_df), 6)

    def test_incremental_nao_colapsa_os_pares(self):
        sem_ultimo = '\n'.join(FORMATO_GOOGLE_CONEXOES.splitlines()[:-1]) + '\n'
        with tempfile.TemporaryDirectory() as tmp:
            saida = os.path.join(tmp, 'resultado.csv')
            self._processar(sem_ultimo, saida)
            # Segunda passada com um IP novo: relê a saída, concatena e deduplica.
            df, _ = self._processar(FORMATO_GOOGLE_CONEXOES, saida)
        self.assertEqual(len(df), 6)
        mesmos = df[df['Data'] == _local('2025-11-02 21:38:11')]
        self.assertEqual(sorted(mesmos['Vinculado_Tipo']),
                         ['Font fingerprint', 'Screen resolution', 'WebGL renderer name'])

    def test_saida_de_outro_formato_e_recusada_sem_tocar_no_arquivo(self):
        from file_handler import FormatoSaidaIncompativel
        with tempfile.TemporaryDirectory() as tmp:
            saida = os.path.join(tmp, 'resultado.csv')
            self._processar(FORMATO_GOOGLE_ATIVIDADES, saida)
            antes = Path(saida).read_bytes()
            with self.assertRaises(FormatoSaidaIncompativel) as ctx:
                self._processar(FORMATO_GOOGLE_CONEXOES, saida)
            self.assertEqual(Path(saida).read_bytes(), antes)
        self.assertEqual((ctx.exception.existente, ctx.exception.novo),
                         ('google_atividades', 'google_conexoes'))

    def test_recusa_vale_tambem_contra_outra_plataforma(self):
        from file_handler import FormatoSaidaIncompativel
        with tempfile.TemporaryDirectory() as tmp:
            saida = os.path.join(tmp, 'resultado.csv')
            self._processar(FORMATO_DISCORD, saida)
            with self.assertRaises(FormatoSaidaIncompativel):
                self._processar(FORMATO_GOOGLE_ATIVIDADES, saida)

    def test_sem_incremental_nao_ha_recusa(self):
        with tempfile.TemporaryDirectory() as tmp:
            saida = os.path.join(tmp, 'resultado.csv')
            self._processar(FORMATO_GOOGLE_ATIVIDADES, saida)
            df, _ = self._processar(FORMATO_GOOGLE_CONEXOES, saida, incremental=False)
        self.assertEqual(familia_formato(df), 'google_conexoes')


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
