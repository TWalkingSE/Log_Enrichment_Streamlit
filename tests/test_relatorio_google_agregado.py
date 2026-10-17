"""Ressalva dos formatos Google Aggregated Activities no laudo HTML.

A linha desses formatos é um intervalo agregado (serviços) ou um par IP ↔
identificador (conexões), não um acesso, e `Data` é só o último uso. A tela de
Resultados já dizia isso; o laudo — o que vai para o processo — contava linhas
como acessos: "IPs Mais Recorrentes" com N=1 para todos, "Acessos noturnos",
silêncio digital entre últimos usos de IPs diferentes e "IP apareceu apenas 1x"
no score de risco de um IP que o Google diz ter sido usado em 800 dias.

Os demais formatos não podem mudar: o laudo entregue é conferido pelo hash.
Dados sintéticos dos `FORMATO_*`, geolocalização fixa por IP — sem rede.
"""
import hashlib
import unittest
from html import unescape

import pandas as pd

from data_processor import (
    FORMATO_1, FORMATO_2, FORMATO_3, FORMATO_4, FORMATO_DISCORD,
    FORMATO_GOOGLE_ATIVIDADES, FORMATO_GOOGLE_CONEXOES,
    FORMATO_PRESERVATION_GOOGLE, FORMATO_TIKTOK, extrair_ips_de_texto,
    extrair_ips_do_formato_google_atividades, extrair_ips_do_formato_google_conexoes,
)
from html_report_generator import (
    ANALISES_NAO_APLICAVEIS_AGREGADO, RESSALVA_AGREGADO, generate_html_report,
)

# (cidade, região, país, código, lat, lon, provedor, proxy, hosting, móvel)
_LOCAIS = [
    ('Salvador', 'BA', 'Brazil', 'BR', -12.97, -38.50, 'Prov A', False, False, True),
    ('Lisboa', 'Lisboa', 'Portugal', 'PT', 38.72, -9.14, 'Prov B', False, True, False),
    ('Miami', 'FL', 'United States', 'US', 25.76, -80.19, 'Prov C', True, False, False),
]
_COLUNAS_GEO = ('Ip_Cidade', 'Ip_Regiao', 'Ip_Pais', 'Ip_Pais_Codigo', 'Ip_Lat', 'Ip_Lon',
                'Ip_Dono', 'Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel')

# Colunas exclusivas dos formatos agregados — sem elas o frame é 'padrao'.
_COLUNAS_AGREGADO = ['Vinculado_Tipo', 'Vinculado_Valor', 'Primeiro_Uso', 'Ultimo_Uso',
                     'Dias_Ativos_Google', 'Dias_Corridos', 'Canal_Autenticacao', 'Multilogin']

# Seções (pelo título — "Critérios & Thresholds" cita algumas como referência)
# e rótulos que só fazem sentido com uma linha por acesso.
_TRECHOS_POR_ACESSO = [
    'Perfil Comportamental</h2>', 'Locais Base Estimados</h2>', 'Acessos noturnos',
    'Padrões de Vida (Clustering)</h2>', 'Silêncio Digital</h2>', 'Confianca de IPs</h2>',
    'Análise Heurística de VPN</h2>', 'Padrão Temporal por Provedor</h2>',
    'Validação de Fuso Horário</h2>', 'IPs Mais Recorrentes</h2>', 'Dias com Atividade',
    'Acessos', 'apareceu apenas',
]

_FORMATOS_DE_ACESSO = {
    'simples': FORMATO_1, 'formato_2': FORMATO_2, 'formato_3': FORMATO_3,
    'google_ip_activity': FORMATO_4, 'discord': FORMATO_DISCORD,
    'preservation': FORMATO_PRESERVATION_GOOGLE, 'tiktok': FORMATO_TIKTOK,
}


def _enriquecer(df):
    """Geolocalização sintética e fixa por IP: o laudo só precisa das colunas."""
    df = df.copy()
    local = {ip: _LOCAIS[i % len(_LOCAIS)] for i, ip in enumerate(sorted(df['Ip'].unique()))}
    for pos, col in enumerate(_COLUNAS_GEO):
        df[col] = df['Ip'].map(lambda ip, p=pos: local[ip][p])
    return df


def _servicos():
    return _enriquecer(extrair_ips_do_formato_google_atividades(FORMATO_GOOGLE_ATIVIDADES, alvo='alvo'))


def _conexoes():
    return _enriquecer(extrair_ips_do_formato_google_conexoes(FORMATO_GOOGLE_CONEXOES, alvo='alvo'))


def _todas_as_analises(df):
    """Tudo o que a página calculava antes — inclusive o que supõe uma linha por
    acesso e o risco com o fator de frequência. O gerador tem de se defender
    sozinho: depender do chamador é como o export sem sanitizar aconteceu."""
    from analysis import (
        analyze_provider_timing, analyze_subnet_patterns, calculate_risk_scores,
        compute_ip_confidence, detect_base_locations, detect_digital_silence,
        detect_impossible_jumps, detect_life_patterns, detect_vpn_heuristics,
        generate_behavioral_profile, validate_timezone_consistency,
    )
    return {
        'risk_scores': calculate_risk_scores(df),
        'impossible_jumps': detect_impossible_jumps(df),
        'base_locations': detect_base_locations(df),
        'behavioral_profile': generate_behavioral_profile(df, alvo='alvo'),
        'vpn_heuristics': detect_vpn_heuristics(df),
        'ip_confidence': compute_ip_confidence(df),
        'life_patterns': detect_life_patterns(df),
        'digital_silence': detect_digital_silence(df),
        'subnet_patterns': analyze_subnet_patterns(df),
        'timezone_consistency': validate_timezone_consistency(df),
        'provider_timing': analyze_provider_timing(df),
    }


def _laudo(df, analyses=None):
    html = generate_html_report(df, 'alvo', config={'include_raw_data': True}, analyses=analyses)
    return unescape(html.decode('utf-8'))


class TestRessalvaNoLaudo(unittest.TestCase):

    def _confere_ressalva(self, html, familia):
        ressalva = RESSALVA_AGREGADO[familia]
        self.assertIn(f"Formato do documento: {ressalva['titulo']}", html)
        for paragrafo in ressalva['paragrafos']:
            self.assertIn(paragrafo, html)
        self.assertIn('Análises não aplicáveis a este formato', html)
        for rotulo, motivo in ANALISES_NAO_APLICAVEIS_AGREGADO.values():
            self.assertIn(f'<strong>{rotulo}</strong>: {motivo}.', html)
        self.assertIn('Linhas agregadas', html)

    def test_servicos(self):
        html = _laudo(_servicos())
        self._confere_ressalva(html, 'google_atividades')
        self.assertIn('Dias_Ativos_Google é a contagem informada pelo Google', html)

    def test_conexoes(self):
        html = _laudo(_conexoes())
        self._confere_ressalva(html, 'google_conexoes')
        self.assertIn('Cada linha é um par IP ↔ identificador', html)

    def test_demais_formatos_sem_ressalva(self):
        for nome, texto in _FORMATOS_DE_ACESSO.items():
            with self.subTest(formato=nome):
                df = _enriquecer(extrair_ips_de_texto(texto, is_file=False, alvo='alvo'))
                self.assertFalse(df.empty)
                html = _laudo(df, _todas_as_analises(df))
                for trecho in ('Google Aggregated Activities', 'Formato do documento',
                               'Análises não aplicáveis', 'Linhas agregadas',
                               'Período coberto', 'último uso', 'Último uso'):
                    self.assertNotIn(trecho, html)
                self.assertIn('IPs Mais Recorrentes', html)


class TestLinhaNaoViraAcesso(unittest.TestCase):

    def test_nenhum_trecho_conta_linha_como_acesso(self):
        for nome, fabrica in (('servicos', _servicos), ('conexoes', _conexoes)):
            with self.subTest(formato=nome):
                df = fabrica()
                html = _laudo(df, _todas_as_analises(df))
                for trecho in _TRECHOS_POR_ACESSO:
                    self.assertNotIn(trecho, html)
                # Controle: as mesmas linhas, sem as colunas do formato
                # agregado, trazem essas seções — então a ausência acima é da
                # ressalva, não de falta de dados.
                controle = df.drop(columns=[c for c in _COLUNAS_AGREGADO if c in df.columns])
                html_controle = _laudo(controle, _todas_as_analises(controle))
                presentes = [t for t in _TRECHOS_POR_ACESSO if t in html_controle]
                self.assertGreaterEqual(len(presentes), 6, presentes)

    def test_rotulos_dizem_que_e_o_ultimo_uso(self):
        html = _laudo(_servicos())
        for trecho in ('Período do Dia do Último Uso', 'Linha do Tempo do Último Uso',
                       'Heatmap do Último Uso', 'Último uso por hora × dia da semana',
                       'Cada linha entra uma vez, pelo horário do seu último uso'):
            self.assertIn(trecho, html)
        # Mapa: o tamanho do ponto conta linhas.
        self.assertIn('Tamanho ∝ linhas', html)
        self.assertNotIn('Tamanho ∝ ocorrências', html)

    def test_risco_sem_fator_de_frequencia(self):
        from analysis import calculate_risk_scores
        df = _servicos()
        # A razão do parâmetro: uma linha por IP, então todos teriam o fator.
        com = calculate_risk_scores(df)
        self.assertTrue(com['Fatores'].str.contains('Baixa frequência').all())
        sem = calculate_risk_scores(df, fator_frequencia=False)
        self.assertFalse(sem['Fatores'].str.contains('Baixa frequência').any())
        # O gerador recalcula mesmo que receba o risco com o fator.
        html = _laudo(df, {'risk_scores': com})
        self.assertNotIn('Baixa frequência (+10)', html)
        self.assertIn('Fator “Baixa frequência” não aplicado', html)

    def test_periodo_vai_do_primeiro_ao_ultimo_uso(self):
        df = _servicos()
        inicio = pd.to_datetime(df['Primeiro_Uso'], format='%Y-%m-%d %H:%M:%S').min()
        fim = pd.to_datetime(df['Ultimo_Uso'], format='%Y-%m-%d %H:%M:%S').max()
        # `Data` sozinha daria um início anos depois: é só o último uso.
        self.assertGreater(pd.to_datetime(df['Data']).min().year, inicio.year)
        self.assertIn('Período coberto (do primeiro ao último uso): <strong>'
                      f"{inicio:%d/%m/%Y} a {fim:%d/%m/%Y}</strong>", _laudo(df))

    def test_ips_de_servicos_pelos_dias_ativos_do_google(self):
        html = _laudo(_servicos())
        self.assertIn('IPs por Dias Ativos (Google)', html)
        # 198.51.100.21 tem 800 dias ativos, 198.51.100.20 tem 700.
        self.assertLess(html.index('<tr><td>198.51.100.21</td><td>800</td>'),
                        html.index('<tr><td>198.51.100.20</td><td>700</td>'))

    def test_ips_de_conexoes_pelos_identificadores_vinculados(self):
        html = _laudo(_conexoes())
        self.assertIn('IPs por Identificadores Vinculados', html)
        # O IPv6 aparece em 4 pares, os IPv4 em 1 cada.
        self.assertIn('<tr><td>2001:db8:5a1e:6400:1:2:3:aa55</td><td>4</td>', html)


class TestHashDoLaudo(unittest.TestCase):
    """A ressalva não toca nos dados: o SHA-256 impresso continua sendo o do CSV."""

    def test_hash_e_o_do_csv_do_dataset(self):
        frames = {'servicos': _servicos(), 'conexoes': _conexoes(),
                  'discord': _enriquecer(extrair_ips_de_texto(FORMATO_DISCORD, is_file=False, alvo='a'))}
        for nome, df in frames.items():
            with self.subTest(formato=nome):
                antes = df.copy()
                esperado = hashlib.sha256(df.to_csv(index=False).encode('utf-8')).hexdigest()
                html = _laudo(df, _todas_as_analises(df))
                self.assertIn(f'SHA-256 Dados Enriquecidos</div><div class="coc-value">{esperado}', html)
                pd.testing.assert_frame_equal(df, antes)


def _pagina_relatorio_gravando_download():
    # Sem acentos neste corpo: no Windows o AppTest grava o script em cp1252
    # e o Streamlit o le como UTF-8 - o script falharia sem erro visivel.
    import os
    import sys
    sys.path.insert(0, os.getcwd())
    import streamlit as st
    for chave, valor in {'alvo': 'alvo', 'lang': 'pt'}.items():
        st.session_state.setdefault(chave, valor)

    original = st.download_button

    def gravar(label, data=None, file_name=None, *args, **kwargs):
        if isinstance(data, (bytes, str)):
            st.session_state.setdefault('_downloads', {})[file_name] = data
        return False

    st.download_button = gravar
    try:
        from pages_app.relatorio import page_relatorio
        page_relatorio()
    finally:
        st.download_button = original


class TestRelatorioPelaPagina(unittest.TestCase):
    """O caminho do analista: a página avisa antes, e o laudo baixado declara."""

    def test_laudo_baixado_declara_o_formato(self):
        from streamlit.testing.v1 import AppTest
        import json
        with open('locales/pt.json', encoding='utf-8') as fh:
            notas = json.load(fh)['resultados']
        casos = (('google_atividades', _servicos, 'google_agg_note_activities'),
                 ('google_conexoes', _conexoes, 'google_agg_note_connections'))
        for familia, fabrica, nota in casos:
            with self.subTest(formato=familia):
                at = AppTest.from_function(_pagina_relatorio_gravando_download, default_timeout=120)
                at.session_state['df_resultado'] = fabrica()
                at = at.run()
                self.assertFalse(at.exception, [e.value for e in at.exception])
                self.assertIn(notas[nota], [i.value for i in at.info])

                gerar = [b for b in at.button if b.key == 'btn_pro_html']
                self.assertEqual(len(gerar), 1)
                at = gerar[0].click().run()
                self.assertFalse(at.exception, [e.value for e in at.exception])
                baixados = at.session_state['_downloads']
                self.assertEqual(len(baixados), 1)
                html = unescape(next(iter(baixados.values())).decode('utf-8'))
                self.assertIn(f"Formato do documento: {RESSALVA_AGREGADO[familia]['titulo']}", html)
                for trecho in _TRECHOS_POR_ACESSO:
                    self.assertNotIn(trecho, html)


if __name__ == '__main__':
    unittest.main()
