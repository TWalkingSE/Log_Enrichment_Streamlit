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
from file_handler import export_xlsx_colored
from i18n import t

logger = logging.getLogger(__name__)


@st.cache_data
def _build_reputacao(df_key_cols):
    """Compute Reputação column (cached to avoid repeated classify calls)."""
    classifications = df_key_cols.apply(classify_infrastructure, axis=1)
    return classifications.apply(lambda c: f"{c['icon']} {c['label']}")


@st.cache_data
def _generate_csv_export(df_data):
    from validators import sanitize_dataframe_for_csv
    return sanitize_dataframe_for_csv(df_data).to_csv(index=False, sep=';').encode('utf-8-sig')


@st.cache_data
def _generate_json_export(df_data):
    return df_data.to_json(orient='records', force_ascii=False, indent=2)


@st.cache_data
def _generate_xlsx_export(df_data):
    buf = io.BytesIO()
    export_xlsx_colored(df_data, buf)
    buf.seek(0)
    return buf.getvalue()


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
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro: {e}")
        return

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

    df_f = df.copy()
    if search:
        mask = df_f.astype(str).apply(lambda r: r.str.contains(search, case=False, na=False).any(), axis=1)
        df_f = df_f[mask]
    if sel_provider != t('common.all') and 'Ip_Dono' in df_f.columns:
        df_f = df_f[df_f['Ip_Dono'] == sel_provider]
    if sel_region != t('common.all') and 'Ip_Regiao' in df_f.columns:
        df_f = df_f[df_f['Ip_Regiao'] == sel_region]
    if sel_type != t('common.all') and all(c in df_f.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']):
        if sel_type == t('common.residential'):
            df_f = df_f[~df_f['Ip_Proxy'] & ~df_f['Ip_Hospedagem'] & ~df_f['Ip_Movel']]
        elif sel_type == t('common.mobile'):
            df_f = df_f[df_f['Ip_Movel'].astype(bool)]
        elif sel_type == t('common.proxy_vpn'):
            df_f = df_f[df_f['Ip_Proxy'].astype(bool)]
        elif sel_type == t('common.hosting'):
            df_f = df_f[df_f['Ip_Hospedagem'].astype(bool)]

    # Metrics
    kpi_row([
        {'label': t('resultados.filtered'), 'value': len(df_f)},
        {'label': t('common.unique_ips'), 'value': df_f['Ip'].nunique() if 'Ip' in df_f.columns else 0},
        {'label': t('resultados.proxies'), 'value': int(df_f['Ip_Proxy'].sum()) if 'Ip_Proxy' in df_f.columns else 0},
        {'label': t('resultados.mobiles'), 'value': int(df_f['Ip_Movel'].sum()) if 'Ip_Movel' in df_f.columns else 0},
    ])

    # Table
    is_meta = 'Porta' in df_f.columns
    is_preservation_google = 'User_Agent' in df_f.columns
    is_discord = 'User_ID' in df_f.columns

    if all(c in df_f.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']) and 'Reputação' not in df_f.columns:
        df_f = df_f.copy()
        key_cols = ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel', 'Ip_AS', 'Ip_Dono']
        existing_keys = [c for c in key_cols if c in df_f.columns]
        df_f['Reputação'] = _build_reputacao(df_f[existing_keys])

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

    if 'Reputação' in df_display.columns:
        max_cells = len(df_display) * len(df_display.columns)
        pd.set_option("styler.render.max_elements", max(262144, max_cells))
        styled = df_display.style.map(_color_reputacao_text, subset=['Reputação'])
        st.dataframe(styled, height=500, hide_index=True, use_container_width=True)
    else:
        st.dataframe(df_display, height=500, hide_index=True, use_container_width=True)
    st.caption(t('resultados.records_of_total', filtered=len(df_display), total=len(df)))

    with st.expander(t('resultados.sparklines_title'), expanded=False):
        if st.button(t('resultados.generate_sparklines'), key="btn_sparklines"):
            render_ip_table_with_sparklines(df_f)

    with st.expander(t('resultados.graph_title'), expanded=False):
        if st.button(t('resultados.generate_graph'), key="btn_graph"):
            render_ip_network_graph(df_f)

    # Multi-format export
    st.divider()
    st.subheader(t('resultados.export_title'))
    c_exp1, c_exp2, c_exp3, c_exp4 = st.columns(4)
    df_export = df_f[display_cols]
    with c_exp1:
        csv_data = _generate_csv_export(df_export)
        st.download_button(t('resultados.csv_filtered'), csv_data, "resultado_filtrado.csv", "text/csv")
    with c_exp2:
        json_data = _generate_json_export(df_export)
        st.download_button(t('resultados.json_export'), json_data, "resultado.json", "application/json")
    with c_exp3:
        xlsx_data = _generate_xlsx_export(df_export)
        st.download_button(t('resultados.excel_colored'), xlsx_data,
            "resultado_colorido.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    with c_exp4:
        if os.path.exists(st.session_state.output_file):
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
        st.download_button(
            t('resultados.ioc_txt'),
            export_ioc_list(df_f, only_suspicious=only_susp),
            "iocs.txt",
            "text/plain",
            key="dl_ioc_txt",
        )
    with i2:
        st.download_button(
            t('resultados.ioc_csv'),
            export_ioc_csv(df_f),
            "iocs.csv",
            "text/csv",
            key="dl_ioc_csv",
        )
    with i3:
        alvo_name = st.session_state.get("alvo") or "Log Enrichment"
        stix_payload = export_stix_json(
            df_f,
            name=f"IOCs — {alvo_name}",
            only_suspicious=only_susp,
        )
        st.download_button(
            t('resultados.stix_export'),
            stix_payload,
            "iocs_stix_bundle.json",
            "application/stix+json",
            key="dl_stix",
        )

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
            # Excel colorido no ZIP (usa cache)
            zf.writestr("resultado.xlsx", _generate_xlsx_export(df_export))
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
