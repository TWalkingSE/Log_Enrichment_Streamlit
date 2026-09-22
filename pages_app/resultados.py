"""
Log Enrichment - Página de Resultados
Tabela interativa com busca, filtros, reputação colorida e exportação.
"""

import streamlit as st
import pandas as pd
import os
import io
import logging

from data_processor import COLUNAS_EXPORT, COLUNAS_EXPORT_META, COLUNAS_EXPORT_PRESERVATION_GOOGLE, COLUNAS_EXPORT_DISCORD
from analysis import classify_infrastructure
from components.graph_view import render_ip_network_graph
from components.visualizations import render_ip_table_with_sparklines
from html_report_generator import generate_html_report
from file_handler import export_xlsx_colored, export_xlsx_to_disk
from i18n import t
from validators import bool_series
from helpers.large_data import (
    bump_data_version, cache_key, estimate_xlsx_seconds, fmt_duracao,
    prepare_button, show_truncation,
    PREVIEW_ROWS, XLSX_DISK_THRESHOLD, fmt,
)

logger = logging.getLogger(__name__)


# Os argumentos prefixados com underscore não são hasheados pelo Streamlit.
# Passar o DataFrame como argumento normal forçava o hash dos bytes do frame
# inteiro a CADA rerun, mesmo com acerto de cache. A identidade dos dados vem
# do `key`, derivado da versão do dataset e dos filtros ativos.

@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _build_reputacao(_df_key_cols, key):
    """Compute Reputação column (cached to avoid repeated classify calls).

    A classificação depende apenas da combinação de flags/ASN/provedor, e
    200k linhas costumam ter poucos milhares de combinações distintas.
    Classificar as combinações e mapear de volta troca 200k chamadas Python
    por alguns milhares.
    """
    cols = list(_df_key_cols.columns)
    uniq = _df_key_cols.drop_duplicates()
    rotulos = {}
    for valores in uniq.itertuples(index=False, name=None):
        c = classify_infrastructure(dict(zip(cols, valores)))
        rotulos[valores] = f"{c['icon']} {c['label']}"
    return pd.Series(
        [rotulos[v] for v in _df_key_cols.itertuples(index=False, name=None)],
        index=_df_key_cols.index)


@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _generate_csv_export(_df_data, key):
    from validators import sanitize_dataframe_for_csv
    return sanitize_dataframe_for_csv(_df_data).to_csv(index=False, sep=';').encode('utf-8-sig')


@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _generate_json_export(_df_data, key):
    return _df_data.to_json(orient='records', force_ascii=False, indent=2)


@st.cache_data(ttl=300, max_entries=4, show_spinner=False)
def _cache_freshness(cache_file, mtime):
    """Frescor do cache de IPs; `mtime` na chave invalida quando o arquivo
    é regravado — sem reler 2 MB de JSON a cada rerun."""
    from api_client import summarize_ip_cache
    return summarize_ip_cache(cache_file)


@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _generate_xlsx_export(_df_data, key):
    buf = io.BytesIO()
    export_xlsx_colored(_df_data, buf)
    buf.seek(0)
    return buf.getvalue()


def _xlsx_grande(df_data, key, nome_base):
    """Gera o Excel colorido em disco, com barra de progresso.

    Não usa `st.cache_data`: o que se guarda aqui é um caminho de arquivo, e um
    cache que sobrevive ao arquivo devolveria um caminho morto. O estado fica
    em `session_state` e é revalidado contra o disco a cada rerun.
    """
    estado = st.session_state.get('_xlsx_disco')
    if estado and estado['key'] == key and os.path.exists(estado['caminho']):
        return estado['caminho'], estado['resumo']

    barra = st.progress(0.0, text="Gerando Excel colorido...")

    def _progresso(feitas, total):
        barra.progress(min(feitas / max(total, 1), 1.0),
                       text=f"Gerando Excel colorido: {fmt(feitas)} de {fmt(total)} linhas")

    try:
        caminho, resumo = export_xlsx_to_disk(df_data, nome_base, _progresso)
    finally:
        barra.empty()

    st.session_state['_xlsx_disco'] = {
        'key': key, 'caminho': caminho, 'resumo': resumo}
    return caminho, resumo


def _declarar_abas(resumo):
    """Declara quantas linhas foram gravadas e em quantas abas.

    Acima de 1.048.575 linhas o resultado continua em `Resultado (2)`, `(3)`...
    Sem essa legenda o analista abre a planilha, vê a primeira aba cheia e não
    tem como saber que existe continuação.
    """
    if not resumo:
        return
    if resumo.get('abas', 1) > 1:
        st.caption(f"✅ {fmt(resumo['linhas'])} linhas gravadas em "
                   f"{resumo['abas']} abas — o formato XLSX não aceita mais de "
                   f"1.048.575 linhas por planilha.")
    else:
        st.caption(f"✅ {fmt(resumo['linhas'])} linhas gravadas (total).")


def page_resultados():
    from styles.components import section_header, empty_state, kpi_row
    section_header(t('resultados.title'), t('resultados.subtitle'), divider="blue")

    df = st.session_state.df_resultado

    if df is None or df.empty:
        empty_state(t('resultados.no_data'), "📊", t('common.process_data_first'))
        output_file = st.session_state.output_file
        if output_file and os.path.exists(output_file):
            if st.button(f"📂 Carregar: {os.path.basename(output_file)}"):
                try:
                    if output_file.lower().endswith(('.xlsx', '.xls')):
                        df = pd.read_excel(output_file)
                    else:
                        df = pd.read_csv(output_file, sep=';', encoding='utf-8-sig')
                    st.session_state.df_resultado = df
                    bump_data_version()
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro: {e}")
        return

    # Frescor do enriquecimento: geolocalização de cache pode estar velha —
    # o analista vê a idade em vez de presumir dado atual.
    cache_path = 'ip_cache.json'
    try:
        stats = _cache_freshness(cache_path, os.path.getmtime(cache_path)) \
            if os.path.exists(cache_path) else None
    except OSError:
        stats = None
    if stats and (stats['expirados'] or stats['sem_data'] or stats['mais_antigo_dias'] > 25):
        st.warning(
            f"⏱️ Cache de IPs: {stats['expirados']} expirada(s), "
            f"{stats['sem_data']} sem carimbo de data, mais antigo há "
            f"{stats['mais_antigo_dias']:.0f} dias. O enriquecimento pode "
            "não refletir o estado atual da rede.")
    elif stats and stats['total']:
        st.caption(f"🌐 Enriquecimento: {stats['total']} IPs em cache — "
                   f"mais antigo há {stats['mais_antigo_dias']:.0f} dias (TTL 30d).")

    # Filters
    c_search, c_prov, c_region, c_type = st.columns([2, 1, 1, 1])
    with c_search:
        search = st.text_input("🔍 " + t('common.search'), placeholder=t('resultados.search_placeholder'))
    with c_prov:
        providers = ['Todos'] + sorted(df['Ip_Dono'].dropna().unique().tolist()) if 'Ip_Dono' in df.columns else ['Todos']
        sel_provider = st.selectbox(t('resultados.provider'), providers)
    with c_region:
        regions = ['Todos'] + sorted(df['Ip_Regiao'].dropna().unique().tolist()) if 'Ip_Regiao' in df.columns else ['Todos']
        sel_region = st.selectbox(t('resultados.region'), regions)
    with c_type:
        types = [t('common.all'), t('common.residential'), t('common.mobile'), t('common.proxy_vpn'), t('common.hosting')]
        sel_type = st.selectbox(t('resultados.type'), types)

    df_f = df
    if search:
        # `astype(str).apply(..., axis=1)` materializava uma cópia em string do
        # frame inteiro e fazia uma passada Python por linha — a cada tecla.
        # Aqui é um OR vetorizado só nas colunas textuais. `regex=False`
        # também corrige o erro ao digitar caracteres como "(" na busca.
        mask = pd.Series(False, index=df_f.index)
        for col in df_f.columns:
            if pd.api.types.is_object_dtype(df_f[col]) or pd.api.types.is_string_dtype(df_f[col]):
                mask |= df_f[col].astype('string').str.contains(
                    search, case=False, na=False, regex=False)
        df_f = df_f[mask]
    if sel_provider != t('common.all') and 'Ip_Dono' in df_f.columns:
        df_f = df_f[df_f['Ip_Dono'] == sel_provider]
    if sel_region != t('common.all') and 'Ip_Regiao' in df_f.columns:
        df_f = df_f[df_f['Ip_Regiao'] == sel_region]
    if sel_type != t('common.all') and all(c in df_f.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        proxy_s = bool_series(df_f, 'Ip_Proxy')
        host_s = bool_series(df_f, 'Ip_Hospedagem')
        mob_s = bool_series(df_f, 'Ip_Movel')
        if sel_type == t('common.residential'):
            df_f = df_f[~proxy_s & ~host_s & ~mob_s]
        elif sel_type == t('common.mobile'):
            df_f = df_f[mob_s]
        elif sel_type == t('common.proxy_vpn'):
            df_f = df_f[proxy_s]
        elif sel_type == t('common.hosting'):
            df_f = df_f[host_s]

    # Metrics
    kpi_row([
        {'label': t('resultados.filtered'), 'value': len(df_f)},
        {'label': t('common.unique_ips'), 'value': df_f['Ip'].nunique() if 'Ip' in df_f.columns else 0},
        {'label': t('resultados.proxies'), 'value': int(bool_series(df_f, 'Ip_Proxy').sum())},
        {'label': t('resultados.mobiles'), 'value': int(bool_series(df_f, 'Ip_Movel').sum())},
    ])

    # Table
    is_meta = 'Porta' in df_f.columns
    is_preservation_google = 'User_Agent' in df_f.columns
    is_discord = 'User_ID' in df_f.columns

    if all(c in df_f.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']) and 'Reputação' not in df_f.columns:
        df_f = df_f.copy()
        key_cols = ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_AS', 'Ip_Dono']
        existing_keys = [c for c in key_cols if c in df_f.columns]
        df_f['Reputação'] = _build_reputacao(
            df_f[existing_keys], cache_key('rep', len(df_f), tuple(existing_keys)))

    if is_discord:
        display_cols = [c for c in COLUNAS_EXPORT_DISCORD if c in df_f.columns]
    elif is_preservation_google:
        display_cols = [c for c in COLUNAS_EXPORT_PRESERVATION_GOOGLE if c in df_f.columns]
    elif is_meta:
        display_cols = [c for c in COLUNAS_EXPORT_META if c in df_f.columns]
    else:
        display_cols = [c for c in COLUNAS_EXPORT if c in df_f.columns]
    df_display = df_f[display_cols].copy()

    def _color_reputacao_text(val):
        """Retorna cor do TEXTO para célula da coluna Reputação."""
        from styles.theme import COLORS
        if not isinstance(val, str):
            return ''
        v = val.lower()
        if any(k in v for k in ['proxy', 'vpn', 'tor', 'datacenter']):
            return f'color: {COLORS["danger"]}; font-weight: bold'
        if 'cloud' in v:
            return f'color: {COLORS["warning"]}; font-weight: bold'
        if any(k in v for k in ['hospedagem', 'hosting']):
            return f'color: {COLORS["hosting"]}'
        if any(k in v for k in ['móvel', 'mobile', 'movel', 'rede m']):
            return f'color: {COLORS["mobile"]}'
        if 'normal' in v:
            return f'color: {COLORS["success"]}'
        return ''

    # O Styler constrói uma estrutura CSS por célula; o código anterior elevava
    # `styler.render.max_elements` para caber o frame inteiro — uma opção GLOBAL
    # e permanente do pandas, que também desprotegia outras páginas. Aqui a
    # prévia é limitada e a truncagem é declarada ao analista.
    preview = df_display.head(PREVIEW_ROWS)
    if 'Reputação' in preview.columns:
        styled = preview.style.map(_color_reputacao_text, subset=['Reputação'])
        st.dataframe(styled, height=500, hide_index=True, use_container_width=True)
    else:
        st.dataframe(preview, height=500, hide_index=True, use_container_width=True)
    show_truncation(len(preview), len(df_display))
    st.caption(t('resultados.records_of_total', filtered=len(df_display), total=len(df)))

    with st.expander(t('resultados.sparklines_title'), expanded=False):
        if st.button(t('resultados.generate_sparklines'), key="btn_sparklines"):
            render_ip_table_with_sparklines(df_f)

    with st.expander(t('resultados.graph_title'), expanded=False):
        if st.button(t('resultados.generate_graph'), key="btn_graph"):
            render_ip_network_graph(df_f)

    # Multi-format export
    # Antes, CSV + JSON + XLSX + IOC + STIX eram gerados a CADA rerun (inclusive
    # ao digitar na busca) e trafegavam inteiros pelo websocket — a origem dos
    # WebSocketClosedError em datasets grandes. Agora cada um é preparado sob
    # demanda; datasets pequenos mantêm o comportamento imediato de antes.
    st.divider()
    st.subheader(t('resultados.export_title'))
    df_export = df_f[display_cols]
    export_key = cache_key('exp', len(df_export), tuple(display_cols))

    c_exp1, c_exp2, c_exp3, c_exp4 = st.columns(4)
    with c_exp1:
        if prepare_button("⚙️ Preparar CSV", df_export, 'csv'):
            st.download_button(t('resultados.csv_filtered'),
                               _generate_csv_export(df_export, export_key),
                               "resultado_filtrado.csv", "text/csv")
    with c_exp2:
        if prepare_button("⚙️ Preparar JSON", df_export, 'json'):
            st.download_button(t('resultados.json_export'),
                               _generate_json_export(df_export, export_key),
                               "resultado.json", "application/json")
    with c_exp3:
        _est = fmt_duracao(estimate_xlsx_seconds(len(df_export), len(display_cols)))
        if prepare_button("⚙️ Preparar Excel", df_export, 'xlsx',
                          help=f"{fmt(len(df_export))} linhas — {_est} de geração"):
            if len(df_export) <= XLSX_DISK_THRESHOLD:
                st.download_button(t('resultados.excel_colored'),
                                   _generate_xlsx_export(df_export, export_key),
                                   "resultado_colorido.xlsx",
                                   "application/vnd.openxmlformats-officedocument."
                                   "spreadsheetml.sheet")
            else:
                # Dezenas de MB não passam por st.cache_data nem pelo websocket
                # sem derrubar a sessão — o arquivo grande é servido do disco.
                caminho, resumo = _xlsx_grande(df_export, export_key,
                                               "resultado_colorido")
                with open(caminho, 'rb') as fh:
                    st.download_button(t('resultados.excel_colored'), fh,
                                       os.path.basename(caminho),
                                       "application/vnd.openxmlformats-officedocument."
                                       "spreadsheetml.sheet",
                                       key="dl_xlsx_grande")
                _declarar_abas(resumo)
    with c_exp4:
        if st.session_state.output_file and os.path.exists(st.session_state.output_file):
            xlsx_complete = os.path.splitext(st.session_state.output_file)[0] + '.xlsx'
            if os.path.exists(xlsx_complete):
                with open(xlsx_complete, 'rb') as f:
                    st.download_button(t('resultados.excel_complete'), f,
                        os.path.basename(xlsx_complete),
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            else:
                with open(st.session_state.output_file, 'rb') as f:
                    st.download_button(t('resultados.csv_complete'), f,
                        os.path.basename(st.session_state.output_file), "text/csv")

    # IOC / STIX export (SIEM)
    from export_ioc import export_ioc_csv, export_ioc_list, export_stix_json
    st.markdown(f"**{t('resultados.ioc_stix_title')}**")
    only_susp = st.checkbox(t('resultados.ioc_only_suspicious'), value=False, key="ioc_only_susp")
    i1, i2, i3 = st.columns(3)
    with i1:
        if prepare_button("⚙️ Preparar IOC (txt)", df_f, 'ioc_txt'):
            st.download_button(t('resultados.ioc_txt'),
                               export_ioc_list(df_f, only_suspicious=only_susp),
                               "iocs.txt", "text/plain", key="dl_ioc_txt")
    with i2:
        if prepare_button("⚙️ Preparar IOC (csv)", df_f, 'ioc_csv'):
            st.download_button(t('resultados.ioc_csv'), export_ioc_csv(df_f),
                               "iocs.csv", "text/csv", key="dl_ioc_csv")
    with i3:
        if prepare_button("⚙️ Preparar STIX", df_f, 'stix'):
            alvo_name = st.session_state.get("alvo") or "Log Enrichment"
            st.download_button(
                t('resultados.stix_export'),
                export_stix_json(df_f, name=f"IOCs — {alvo_name}",
                                 only_suspicious=only_susp),
                "iocs_stix_bundle.json", "application/stix+json", key="dl_stix")

    if st.button(t('resultados.export_all_zip'), key="zip_export_btn"):
        import zipfile
        from validators import sanitize_dataframe_for_csv
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("resultado.csv",
                sanitize_dataframe_for_csv(df_f[display_cols]).to_csv(
                    index=False, sep=';', encoding='utf-8-sig'))
            zf.writestr("resultado.json",
                df_f[display_cols].to_json(orient='records', force_ascii=False, indent=2))
            # Excel colorido no ZIP. Em dataset grande vem do arquivo em disco,
            # para não materializar dezenas de MB de bytes em memória.
            if len(df_export) <= XLSX_DISK_THRESHOLD:
                zf.writestr("resultado.xlsx", _generate_xlsx_export(df_export, export_key))
            else:
                caminho_zip, resumo_zip = _xlsx_grande(df_export, export_key,
                                                       "resultado_colorido")
                zf.write(caminho_zip, "resultado.xlsx")
                _declarar_abas(resumo_zip)
            zf.writestr("iocs.txt", export_ioc_list(df_f, only_suspicious=only_susp))
            zf.writestr("iocs.csv", export_ioc_csv(df_f))
            zf.writestr(
                "iocs_stix_bundle.json",
                export_stix_json(
                    df_f,
                    name=f"IOCs — {st.session_state.get('alvo') or 'Log Enrichment'}",
                    only_suspicious=only_susp,
                ),
            )
            try:
                alvo_z = st.session_state.alvo or t('common.unknown')
                html_data = generate_html_report(df, alvo_z, config={}, analyses={}, audit_hash='')
                if html_data:
                    zf.writestr("relatorio.html", html_data)
            except Exception as e:
                logger.warning(f"Relatório HTML não incluído no ZIP: {e}")
                st.toast(t('resultados.pdf_not_included'))
        zip_buf.seek(0)
        st.download_button(t('resultados.download_zip'), zip_buf.getvalue(),
            "log_enrichment_export.zip", "application/zip", key="zip_dl")
