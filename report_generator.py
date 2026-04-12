"""
report_generator.py — Gerador de Relatórios Profissionais
================================================================
Gera relatórios PDF com template profissional:
- Sumário executivo
- Metodologia
- Tabela de evidências
- Análises avançadas
- Hash de integridade
- Cabeçalho/rodapé configuráveis
"""

import os
import hashlib
import logging
import tempfile
from datetime import datetime

import pandas as pd
from fpdf import FPDF
from fpdf.enums import XPos, YPos

logger = logging.getLogger(__name__)


# ============================================================
# CUSTOM PDF CLASS
# ============================================================

class ReportPDF(FPDF):
    """PDF with auto header/footer and configurable branding."""

    def __init__(self, config=None):
        super().__init__()
        self.config = config or {}
        self._report_title = self.config.get('title', 'Log Enrichment - Relatório de Análise')
        self._org_name = self.config.get('organization', '')
        self._case_number = self.config.get('case_number', '')
        self._analyst = self.config.get('analyst', '')
        self._classification = self.config.get('classification', '')
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(100, 100, 120)

        # Left: org name
        if self._org_name:
            self.cell(90, 6, self._org_name, align='L')
        else:
            self.cell(90, 6, '', align='L')

        # Right: classification
        if self._classification:
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(200, 50, 50)
            self.cell(0, 6, self._classification, align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_text_color(100, 100, 120)
        else:
            self.ln(6)

        # Separator
        self.set_draw_color(130, 140, 248)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 7)
        self.set_text_color(140, 140, 160)

        case_str = f' | Caso: {self._case_number}' if self._case_number else ''
        self.cell(0, 5,
                  f'Log Enrichment v5.2 Pro{case_str} | '
                  f'Gerado: {datetime.now().strftime("%d/%m/%Y %H:%M")} | '
                  f'Pagina {self.page_no()}/{{nb}}',
                  align='C')


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _safe_text(text):
    """Sanitiza texto para uso no PDF, preservando caracteres PT-BR."""
    if not isinstance(text, str):
        text = str(text)
    # Remove apenas caracteres que não podem ser renderizados de modo algum
    return text.encode('latin-1', errors='replace').decode('latin-1')


def _add_section_title(pdf, title, level=1):
    """Add a styled section title."""
    pdf.ln(4)
    if level == 1:
        pdf.set_font('Helvetica', 'B', 16)
        pdf.set_text_color(130, 140, 248)
    elif level == 2:
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(100, 120, 200)
    else:
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(80, 80, 100)

    pdf.cell(0, 10, _safe_text(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if level <= 2:
        pdf.set_draw_color(130, 140, 248)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.set_text_color(40, 40, 60)
    pdf.ln(3)


def _add_kv(pdf, key, value, indent=10):
    """Add a key-value line."""
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(indent, 7, '')  # indent
    pdf.cell(50, 7, _safe_text(f'{key}:'))
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 7, _safe_text(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _add_table(pdf, headers, rows, col_widths=None):
    """Add a simple table to the PDF."""
    n_cols = len(headers)
    if col_widths is None:
        available = 190
        col_widths = [available / n_cols] * n_cols

    # Header row
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(42, 42, 68)
    pdf.set_text_color(255, 255, 255)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, _safe_text(h), border=1, fill=True, align='C')
    pdf.ln()

    # Data rows
    pdf.set_font('Helvetica', '', 7)
    pdf.set_text_color(40, 40, 60)
    fill = False
    for row in rows:
        if pdf.get_y() > 265:
            pdf.add_page()
        if fill:
            pdf.set_fill_color(240, 240, 250)
        else:
            pdf.set_fill_color(255, 255, 255)
        for i, val in enumerate(row):
            pdf.cell(col_widths[i], 6, _safe_text(str(val)[:60]), border=1, fill=True)
        pdf.ln()
        fill = not fill


def _try_add_chart(pdf, fig, label=''):
    """Try to render a plotly figure to the PDF as an image."""
    tmp_path = None
    try:
        img_bytes = fig.to_image(format='png', width=800, height=400, scale=2)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(img_bytes)
            tmp_path = f.name
        pdf.image(tmp_path, x=10, w=190)
        pdf.ln(3)
        return True
    except Exception as e:
        logger.warning(f"Chart '{label}' nao incluido no PDF: {e}")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ============================================================
# MAIN REPORT GENERATION
# ============================================================

def generate_basic_report(df, alvo):
    """Generate the legacy "basic" PDF using the unified professional pipeline."""
    basic_config = {
        'title': 'Log Enrichment - Relatorio de Analise',
        'include_raw_data': False,
        'include_charts': True,
        'max_raw_rows': 0,
    }
    return generate_professional_report(df, alvo, config=basic_config)

def generate_professional_report(
    df,
    alvo,
    config=None,
    analyses=None,
    audit_hash=None,
):
    """
    Gera relatório PDF profissional com múltiplas seções.

    Args:
        df: DataFrame com dados enriquecidos
        alvo: Identificador do alvo
        config: dict com configurações do relatório:
            - title, organization, case_number, analyst, classification
            - include_raw_data (bool): incluir tabela de dados brutos
            - include_charts (bool): incluir gráficos
            - max_raw_rows (int): máximo de linhas na tabela de dados
        analyses: dict com resultados de análises avançadas:
            - risk_scores, impossible_jumps, base_locations,
              behavioral_profile, vpn_heuristics, ip_confidence,
              life_patterns, infrastructure, time_patterns
        audit_hash: hash SHA-256 do audit trail para cadeia de custódia

    Returns:
        bytes: conteúdo do PDF
    """
    config = config or {}
    analyses = analyses or {}
    include_charts = config.get('include_charts', True)
    include_raw = config.get('include_raw_data', False)
    max_raw = config.get('max_raw_rows', 100)

    pdf = ReportPDF(config)
    pdf.alias_nb_pages()

    # ── COVER PAGE ──────────────────────────────────────────
    pdf.add_page()
    pdf.ln(30)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.set_text_color(130, 140, 248)
    pdf.cell(0, 15, _safe_text(config.get('title', 'Relatorio de Analise')), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(10)
    pdf.set_font('Helvetica', '', 14)
    pdf.set_text_color(80, 80, 100)
    pdf.cell(0, 10, _safe_text(f'Alvo: {alvo}'), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    if config.get('case_number'):
        pdf.cell(0, 8, _safe_text(f'Caso: {config["case_number"]}'), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if config.get('analyst'):
        pdf.set_font('Helvetica', '', 11)
        pdf.cell(0, 8, _safe_text(f'Analista: {config["analyst"]}'), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(10)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, datetime.now().strftime('Data: %d/%m/%Y   Hora: %H:%M'), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if config.get('classification'):
        pdf.ln(15)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_text_color(200, 50, 50)
        pdf.cell(0, 10, _safe_text(config['classification']), align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(40, 40, 60)

    # ── EXECUTIVE SUMMARY ───────────────────────────────────
    pdf.add_page()
    _add_section_title(pdf, '1. Sumario Executivo')
    pdf.set_font('Helvetica', '', 10)

    n_total = len(df)
    n_unique = df['Ip'].nunique() if 'Ip' in df.columns else 0
    n_countries = df['Ip_Pais'].dropna().nunique() if 'Ip_Pais' in df.columns else 0
    n_providers = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0

    _add_kv(pdf, 'Total de registros', f'{n_total:,}')
    _add_kv(pdf, 'IPs unicos', f'{n_unique:,}')
    _add_kv(pdf, 'Paises identificados', n_countries)
    _add_kv(pdf, 'Provedores distintos', n_providers)

    if 'Data' in df.columns:
        dates = pd.to_datetime(df['Data'], errors='coerce').dropna()
        if len(dates) > 0:
            _add_kv(pdf, 'Periodo analisado',
                    f'{dates.min().strftime("%d/%m/%Y")} a {dates.max().strftime("%d/%m/%Y")}')
            _add_kv(pdf, 'Dias com atividade', dates.dt.date.nunique())

    proxy_n = hosting_n = mobile_n = 0
    if all(c in df.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        proxy_n = int(df['Ip_Proxy'].apply(lambda x: str(x).lower() == 'true').sum())
        hosting_n = int(df['Ip_Hospedagem'].apply(lambda x: str(x).lower() == 'true').sum())
        mobile_n = int(df['Ip_Movel'].apply(lambda x: str(x).lower() == 'true').sum())
        _add_kv(pdf, 'Acessos via Proxy/VPN', f'{proxy_n} ({proxy_n/max(n_total,1)*100:.1f}%)')
        _add_kv(pdf, 'Acessos via Hosting', f'{hosting_n} ({hosting_n/max(n_total,1)*100:.1f}%)')
        _add_kv(pdf, 'Acessos Moveis', f'{mobile_n} ({mobile_n/max(n_total,1)*100:.1f}%)')

    # Key findings
    findings = []
    if proxy_n + hosting_n > n_total * 0.3:
        findings.append(f'Alto uso de anonimizacao ({proxy_n + hosting_n} conexoes via proxy/hosting)')
    vpn_result = analyses.get('vpn_heuristics')
    if vpn_result and vpn_result.get('score', 0) >= 50:
        findings.append(f'Indicadores de VPN detectados (score: {vpn_result["score"]})')
    jumps = analyses.get('impossible_jumps')
    if isinstance(jumps, pd.DataFrame) and not jumps.empty:
        findings.append(f'{len(jumps)} salto(s) impossivel(is) detectado(s)')
    elif isinstance(jumps, list) and len(jumps) > 0:
        findings.append(f'{len(jumps)} salto(s) impossivel(is) detectado(s)')
    risk = analyses.get('risk_scores')
    if isinstance(risk, pd.DataFrame) and not risk.empty and 'Score' in risk.columns:
        high_risk = len(risk[risk['Score'] >= 70])
        if high_risk > 0:
            findings.append(f'{high_risk} IP(s) com risco elevado (>= 70)')

    if findings:
        pdf.ln(5)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 8, 'Principais achados:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 10)
        for f in findings:
            pdf.cell(15, 7, '')
            pdf.cell(0, 7, _safe_text(f'- {f}'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── METHODOLOGY ─────────────────────────────────────────
    _add_section_title(pdf, '2. Metodologia')
    pdf.set_font('Helvetica', '', 10)
    methodology_text = (
        'Este relatorio foi gerado pelo sistema Log Enrichment v3.0. '
        'Os dados de log foram processados e enriquecidos utilizando a API ip-api.com para '
        'geolocalizacao de enderecos IP. A analise inclui classificacao de infraestrutura, '
        'deteccao de saltos impossiveis (baseada em velocidade maxima de deslocamento), '
        'scoring de risco comportamental e heuristicas de deteccao de VPN/proxy. '
        'Todos os resultados sao indicativos e devem ser validados com informacoes adicionais.'
    )
    pdf.multi_cell(0, 6, _safe_text(methodology_text))
    pdf.ln(3)

    # ── TOP PROVIDERS ───────────────────────────────────────
    _add_section_title(pdf, '3. Distribuicao de Provedores')

    if 'Ip_Dono' in df.columns:
        pc = df['Ip_Dono'].value_counts().head(15)
        rows = []
        for prov, cnt in pc.items():
            pct = cnt / max(n_total, 1) * 100
            rows.append([str(prov), str(cnt), f'{pct:.1f}%'])
        _add_table(pdf, ['Provedor', 'Ocorrencias', '%'],
                   rows, col_widths=[110, 40, 40])

    # Chart
    if include_charts and 'Ip_Dono' in df.columns:
        try:
            import plotly.express as _px
            pc_df = df['Ip_Dono'].value_counts().head(10).reset_index()
            pc_df.columns = ['Provedor', 'Qtd']
            fig = _px.bar(pc_df, x='Qtd', y='Provedor', orientation='h',
                          color='Qtd', color_continuous_scale='Viridis',
                          title='Top 10 Provedores')
            fig.update_layout(height=400, width=800, showlegend=False,
                              yaxis={'categoryorder': 'total ascending'},
                              coloraxis_showscale=False,
                              margin=dict(l=10, r=10, t=40, b=10))
            _try_add_chart(pdf, fig, 'providers')
        except Exception:
            pass

    # ── GEOGRAPHIC DISTRIBUTION ─────────────────────────────
    _add_section_title(pdf, '4. Distribuicao Geografica')

    if 'Ip_Pais' in df.columns:
        country_counts = df['Ip_Pais'].value_counts().head(10)
        rows = [[str(c), str(n), f'{n/max(n_total,1)*100:.1f}%']
                for c, n in country_counts.items()]
        _add_table(pdf, ['Pais', 'Ocorrencias', '%'], rows, col_widths=[80, 55, 55])
        pdf.ln(3)

    if 'Ip_Regiao' in df.columns:
        region_counts = df['Ip_Regiao'].value_counts().head(10)
        rows = [[str(r), str(n)] for r, n in region_counts.items()]
        _add_table(pdf, ['Regiao', 'Ocorrencias'], rows, col_widths=[120, 70])

    # ── CONNECTION TYPES ────────────────────────────────────
    if all(c in df.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        _add_section_title(pdf, '5. Tipos de Conexao')
        normal_n = n_total - proxy_n - hosting_n - mobile_n
        rows = [
            ['Residencial', str(normal_n), f'{normal_n/max(n_total,1)*100:.1f}%'],
            ['Movel', str(mobile_n), f'{mobile_n/max(n_total,1)*100:.1f}%'],
            ['Proxy/VPN', str(proxy_n), f'{proxy_n/max(n_total,1)*100:.1f}%'],
            ['Hosting', str(hosting_n), f'{hosting_n/max(n_total,1)*100:.1f}%'],
        ]
        _add_table(pdf, ['Tipo', 'Qtd', '%'], rows, col_widths=[70, 60, 60])

    # ── PERIOD ANALYSIS ─────────────────────────────────────
    if 'Periodo' in df.columns:
        _add_section_title(pdf, '6. Atividade por Periodo')
        period_counts = df['Periodo'].value_counts()
        rows = [[str(p), str(n), f'{n/max(n_total,1)*100:.1f}%']
                for p, n in period_counts.items()]
        _add_table(pdf, ['Periodo', 'Acessos', '%'], rows, col_widths=[70, 60, 60])

    # ── RISK ANALYSIS ───────────────────────────────────────
    risk_df = analyses.get('risk_scores')
    if isinstance(risk_df, pd.DataFrame) and not risk_df.empty and 'Score' in risk_df.columns:
        _add_section_title(pdf, '7. Analise de Risco')

        # Summary
        pdf.set_font('Helvetica', '', 10)
        high = len(risk_df[risk_df['Score'] >= 70])
        med = len(risk_df[(risk_df['Score'] >= 40) & (risk_df['Score'] < 70)])
        low = len(risk_df[risk_df['Score'] < 40])
        _add_kv(pdf, 'Risco Alto (>= 70)', high)
        _add_kv(pdf, 'Risco Medio (40-69)', med)
        _add_kv(pdf, 'Risco Baixo (< 40)', low)
        pdf.ln(3)

        # Top risky IPs
        top_risk = risk_df.nlargest(15, 'Score')
        rows = []
        for _, r in top_risk.iterrows():
            rows.append([
                str(r.get('IP', r.get('Ip', ''))),
                str(int(r.get('Score', 0))),
                str(r.get('Ip_Dono', r.get('Provedor', ''))),
                str(r.get('Ip_Pais', r.get('Cidade', ''))),
            ])
        if rows:
            _add_table(pdf, ['IP', 'Score', 'Provedor', 'Pais'],
                       rows, col_widths=[55, 25, 70, 40])

    # ── IMPOSSIBLE JUMPS ────────────────────────────────────
    jumps = analyses.get('impossible_jumps')
    jumps_list = []
    if isinstance(jumps, pd.DataFrame) and not jumps.empty:
        jumps_list = jumps.to_dict('records')
    elif isinstance(jumps, list):
        jumps_list = jumps
    if jumps_list:
        _add_section_title(pdf, '8. Saltos Impossiveis')
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 5, _safe_text(
            'Deslocamentos entre enderecos IP que excedem velocidades '
            'fisicamente possiveis, sugerindo uso de VPN/proxy ou '
            'compartilhamento de conta.'
        ))
        pdf.ln(3)

        rows = []
        for j in jumps_list[:20]:
            rows.append([
                j.get('De_IP', j.get('from_ip', '')),
                j.get('Para_IP', j.get('to_ip', '')),
                f"{j.get('Distancia_km', j.get('distance_km', 0)):.0f} km",
                f"{j.get('Tempo_h', j.get('time_hours', 0)):.1f} h",
                f"{j.get('Velocidade_kmh', j.get('speed_kmh', 0)):.0f} km/h",
            ])
        _add_table(pdf, ['IP Origem', 'IP Destino', 'Distancia', 'Tempo', 'Velocidade'],
                   rows, col_widths=[40, 40, 35, 30, 45])

    # ── VPN HEURISTICS ──────────────────────────────────────
    vpn = analyses.get('vpn_heuristics')
    if vpn and vpn.get('score', 0) > 0:
        _add_section_title(pdf, '9. Analise Heuristica de VPN')
        pdf.set_font('Helvetica', '', 10)
        _add_kv(pdf, 'Score VPN', f"{vpn['score']}/100")
        pdf.ln(2)

        indicators = vpn.get('indicators', {})
        if indicators:
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, 'Indicadores detectados:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Helvetica', '', 9)
            for k, v in indicators.items():
                pdf.cell(15, 6, '')
                pdf.cell(0, 6, _safe_text(f'{k}: {v}'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        suspicious = vpn.get('suspicious_ips', [])
        if suspicious:
            pdf.ln(2)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, 'IPs suspeitos:', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Helvetica', '', 9)
            for ip in suspicious[:10]:
                pdf.cell(15, 6, '')
                pdf.cell(0, 6, _safe_text(ip), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── IP CONFIDENCE ───────────────────────────────────────
    ip_conf = analyses.get('ip_confidence')
    if isinstance(ip_conf, pd.DataFrame) and not ip_conf.empty:
        _add_section_title(pdf, '10. Confianca de IPs')
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 5, _safe_text(
            'Score de confianca indicando a probabilidade de cada IP '
            'ser o endereco real do alvo vs um IP mascarado/VPN.'
        ))
        pdf.ln(3)

        rows = []
        for _, r in ip_conf.head(20).iterrows():
            rows.append([
                str(r.get('IP', '')),
                str(r.get('Confidence', '')),
                str(r.get('Classification', '')),
                str(r.get('Motivo', ''))[:50],
            ])
        _add_table(pdf, ['IP', 'Score', 'Classificacao', 'Motivo'],
                   rows, col_widths=[45, 20, 40, 85])

    # ── BASE LOCATIONS ──────────────────────────────────────
    bases = analyses.get('base_locations')
    if bases and (bases.get('home') or bases.get('work')):
        _add_section_title(pdf, '11. Locais Base Estimados')

        home = bases.get('home')
        if home:
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, 'Residencia (estimada):', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Helvetica', '', 10)
            _add_kv(pdf, 'Cidade', home.get('city', ''))
            _add_kv(pdf, 'Regiao', home.get('region', ''))
            _add_kv(pdf, 'Provedor', home.get('provider', ''))
            _add_kv(pdf, 'Acessos noturnos', home.get('count', 0))
            pdf.ln(3)

        work = bases.get('work')
        if work:
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, 'Trabalho (estimado):', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Helvetica', '', 10)
            _add_kv(pdf, 'Cidade', work.get('city', ''))
            _add_kv(pdf, 'Regiao', work.get('region', ''))
            _add_kv(pdf, 'Provedor', work.get('provider', ''))
            _add_kv(pdf, 'Acessos diurnos', work.get('count', 0))

    # ── BEHAVIORAL PROFILE ──────────────────────────────────
    profile = analyses.get('behavioral_profile')
    if profile:
        _add_section_title(pdf, '12. Perfil Comportamental')
        pdf.set_font('Helvetica', '', 10)

        if profile.get('primary_hours'):
            _add_kv(pdf, 'Horarios principais', profile['primary_hours'])
        if profile.get('weekday_vs_weekend'):
            ww = profile['weekday_vs_weekend']
            _add_kv(pdf, 'Dias uteis vs fim de semana',
                    f"{ww.get('weekday', 0)} / {ww.get('weekend', 0)}")
        if profile.get('regularity_score') is not None:
            _add_kv(pdf, 'Score de regularidade',
                    f"{profile['regularity_score']:.0f}/100")

    # ── LIFE PATTERNS ───────────────────────────────────────
    life = analyses.get('life_patterns')
    if life and life.get('has_data'):
        _add_section_title(pdf, '13. Padroes de Vida (Clustering)')

        clusters = life.get('clusters', [])
        if clusters:
            rows = []
            for c in clusters:
                rows.append([
                    str(c.get('label', '')),
                    str(c.get('city', '')),
                    str(c.get('count', 0)),
                    str(c.get('provider', '')),
                    f"{c.get('first_seen', '')} - {c.get('last_seen', '')}",
                ])
            _add_table(pdf, ['Tipo', 'Cidade', 'N', 'Provedor', 'Periodo'],
                       rows, col_widths=[45, 35, 15, 55, 40])

        deviations = life.get('routine_deviations', [])
        if deviations:
            pdf.ln(3)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, f'Desvios de rotina ({len(deviations)}):', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Helvetica', '', 9)
            for d in deviations[:10]:
                pdf.cell(15, 6, '')
                pdf.cell(0, 6, _safe_text(
                    f"{d.get('date', '')} - {d.get('city', '')} ({d.get('ip', '')})"
                ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── TOP IPs TABLE ───────────────────────────────────────
    if 'Ip' in df.columns:
        _add_section_title(pdf, '14. IPs Mais Recorrentes')
        top = df['Ip'].value_counts().head(20)
        rows = []
        for ip, cnt in top.items():
            ip_data = df[df['Ip'] == ip].iloc[0]
            rows.append([
                str(ip),
                str(cnt),
                str(ip_data.get('Ip_Dono', '')),
                str(ip_data.get('Ip_Pais', '')),
                str(ip_data.get('Ip_Cidade', '')),
            ])
        _add_table(pdf, ['IP', 'N', 'Provedor', 'Pais', 'Cidade'],
                   rows, col_widths=[42, 15, 60, 35, 38])

    # ── RAW DATA (optional) ─────────────────────────────────
    if include_raw:
        _add_section_title(pdf, '15. Dados Brutos (Amostra)')
        export_cols = [c for c in ['Data', 'Ip', 'Ip_Pais', 'Ip_Regiao', 'Ip_Cidade', 'Ip_Dono']
                       if c in df.columns]
        if export_cols:
            sample = df[export_cols].head(max_raw)
            rows = [list(r) for _, r in sample.iterrows()]
            widths = [30, 35, 25, 30, 35, 35][:len(export_cols)]
            _add_table(pdf, export_cols, rows, col_widths=widths)

    # ── INTEGRITY / CHAIN OF CUSTODY ────────────────────────
    _add_section_title(pdf, 'Integridade e Cadeia de Custodia')
    pdf.set_font('Helvetica', '', 9)

    # Hash the data
    data_str = df.to_csv(index=False)
    data_hash = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    _add_kv(pdf, 'Hash SHA-256 dos dados', data_hash[:32] + '...')
    _add_kv(pdf, 'Registros analisados', n_total)
    _add_kv(pdf, 'Gerado em', datetime.now().strftime('%d/%m/%Y %H:%M:%S'))

    if audit_hash:
        _add_kv(pdf, 'Hash audit trail', str(audit_hash)[:32] + '...')

    if config.get('analyst'):
        _add_kv(pdf, 'Analista', config['analyst'])

    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 7)
    pdf.multi_cell(0, 4, _safe_text(
        'Este relatorio foi gerado automaticamente. Os resultados sao indicativos '
        'e devem ser corroborados com outras fontes de informacao. O hash SHA-256 '
        'garante a integridade dos dados originais utilizados na analise.'
    ))

    return pdf.output()
