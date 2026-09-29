"""
Log Enrichment - Página de Interceptação Telemática
Processamento de logs WhatsApp (Message Log + Call Log) a partir de HTML/ZIP.
"""

import streamlit as st
import os
import io
import logging
import uuid
import plotly.express as px

from interception_parser import (
    parse_zip_interception, parse_html_records, records_to_dataframe,
    processar_interceptacao_async, COLUNAS_EXPORT_INTERCEPTACAO,
    processar_resultados_interceptacao, _add_reputacao_interceptacao
)
from api_client import IP_CACHE_PATH
from file_handler import export_xlsx_colored, export_xlsx_to_disk
from helpers.atomic_io import atomic_write_bytes
from helpers.shared import run_async
from validators import safe_output_path, sanitize_dataframe_for_csv
from helpers.large_data import (
    declare_sheets, estimate_xlsx_seconds, fmt_duracao, prepare_button, show_truncation,
    xlsx_progress_bar, PREVIEW_ROWS, XLSX_DISK_THRESHOLD, fmt,
)

from i18n import t

logger = logging.getLogger(__name__)


def _set_df_interceptacao(df):
    """Única porta de escrita de `df_interceptacao`.

    Cada novo resultado ganha uma identidade própria (`_int_token`), que entra
    nas chaves dos exports. Sem ela, uma interceptação nova com o mesmo número
    de linhas recebia o Excel/CSV já gerado da anterior.
    """
    st.session_state['df_interceptacao'] = df
    st.session_state['_int_token'] = uuid.uuid4().hex


def _int_token():
    token = st.session_state.get('_int_token')
    if not token:
        token = uuid.uuid4().hex
        st.session_state['_int_token'] = token
    return token


# Os exports levam o frame com `_` (não hasheado a cada rerun) e a identidade
# em `key`. Antes eram regenerados a cada interação da página.
@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _csv_interceptacao(_df_exp, key):
    return sanitize_dataframe_for_csv(_df_exp).to_csv(index=False, sep=';').encode('utf-8-sig')


@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _json_interceptacao(_df_exp, key):
    return _df_exp.to_json(orient='records', force_ascii=False, indent=2)


@st.cache_data(ttl=1800, max_entries=3, show_spinner=False)
def _xlsx_interceptacao(_df_exp, key):
    buf = io.BytesIO()
    export_xlsx_colored(_df_exp, buf)
    return buf.getvalue()


def _xlsx_grande_interceptacao(df_exp, nome_base):
    """Excel colorido em disco, com progresso, revalidado contra o arquivo.

    Mesmo padrão da página de Resultados: o estado guarda um caminho, então
    precisa ser conferido no disco a cada rerun em vez de ficar em cache.
    """
    chave = (_int_token(), nome_base, len(df_exp), tuple(df_exp.columns))
    estado = st.session_state.get('_xlsx_disco_int')
    if estado and estado['key'] == chave and os.path.exists(estado['caminho']):
        return estado['caminho'], estado['resumo']

    barra, _progresso = xlsx_progress_bar()
    try:
        caminho, resumo = export_xlsx_to_disk(df_exp, nome_base, _progresso)
    finally:
        barra.empty()

    st.session_state['_xlsx_disco_int'] = {
        'key': chave, 'caminho': caminho, 'resumo': resumo}
    return caminho, resumo


async def _enrich_df_async(df, output_file, batch_size, period, update_callback, api_key=None):
    """Enrich a pre-parsed DataFrame (from single HTML upload) via shared service."""
    from enrich_service import enrich_dataframe

    df, _results = await enrich_dataframe(
        df,
        'Sender IP',
        cache_file=IP_CACHE_PATH,
        api_key=api_key,
        batch_size=batch_size,
        period=period,
        update_callback=update_callback,
        apply_results=processar_resultados_interceptacao,
    )
    df = _add_reputacao_interceptacao(df)

    export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df.columns]
    atomic_write_bytes(
        output_file,
        sanitize_dataframe_for_csv(df[export_cols]).to_csv(
            index=False, sep=';').encode('utf-8-sig'))
    if update_callback:
        update_callback(t('interceptacao.saved_to', path=output_file))
    return df


def page_interceptacao():
    from styles.components import section_header
    section_header(t('interceptacao.title'), t('interceptacao.subtitle'), divider="red")

    st.info(t('interceptacao.how_it_works'))

    output_intercept = st.text_input(
        t('interceptacao.output_file'),
        value="interceptacao_resultado.csv",
        key="output_intercept",
    )
    if not output_intercept.lower().endswith('.csv'):
        output_intercept = os.path.splitext(output_intercept)[0] + '.csv'
    output_intercept = safe_output_path(output_intercept, default_name='interceptacao_resultado.csv')

    tab_zip, tab_html = st.tabs([t('interceptacao.tab_zip'), t('interceptacao.tab_html')])
    intercept_data = None
    is_zip = True

    with tab_zip:
        uploaded_zip = st.file_uploader(t('interceptacao.upload_zip'), type=['zip'], key="intercept_zip")
        if uploaded_zip:
            st.success(t('interceptacao.zip_loaded', filename=uploaded_zip.name))
            intercept_data = uploaded_zip.getvalue()
            is_zip = True
            import zipfile
            try:
                zf = zipfile.ZipFile(io.BytesIO(intercept_data))
                st.caption(t('interceptacao.files_in_zip', count=len(zf.namelist())))
                zf.close()
            except Exception as e:
                logger.warning("Prévia do ZIP falhou (%s): %s", uploaded_zip.name, e)

    with tab_html:
        uploaded_html = st.file_uploader(t('interceptacao.upload_html'), type=['html', 'htm'], key="intercept_html")
        if uploaded_html:
            st.success(t('interceptacao.html_loaded', filename=uploaded_html.name))
            intercept_data = uploaded_html.getvalue()
            is_zip = False
            try:
                html_content = intercept_data.decode('utf-8', errors='replace')
                records = parse_html_records(html_content)
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric(t('common.total'), len(records))
                with c2:
                    st.metric(t('interceptacao.messages'), len([r for r in records if r['type'].startswith('message')]))
                with c3:
                    st.metric(t('interceptacao.calls'), len([r for r in records if r['type'].startswith('call')]))
                with c4:
                    st.metric(t('interceptacao.logins'), len([r for r in records if r['type'].startswith('login')]))
            except Exception as e:
                logger.warning("Prévia do HTML falhou (%s): %s", uploaded_html.name, e)
                st.caption(t('interceptacao.html_preview_error', error=e))

    with st.expander(t('interceptacao.options'), expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            batch_intercept = st.number_input(t('interceptacao.batch'), 1, 1000, value=500, key="batch_i")
        with c2:
            period_intercept = st.number_input(t('interceptacao.period_seconds'), 0, 300, value=0, key="period_i")

    st.divider()
    if st.button(t('interceptacao.process_btn'), type="primary", key="btn_intercept"):
        if intercept_data is None:
            st.error(t('interceptacao.no_file'))
        else:
            with st.status(t('interceptacao.processing'), expanded=True) as status:
                try:
                    if is_zip:
                        st.write(t('interceptacao.extracting_zip'))
                        df = parse_zip_interception(intercept_data, update_callback=lambda msg: st.write(f"  {msg}"))
                    else:
                        st.write(t('interceptacao.processing_html'))
                        html_content = intercept_data.decode('utf-8', errors='replace')
                        records = parse_html_records(html_content, update_callback=lambda msg: st.write(f"  {msg}"))
                        df = records_to_dataframe(records)

                    if df.empty:
                        st.warning(t('interceptacao.no_records'))
                        status.update(label=t('interceptacao.no_records_label'), state="error")
                        return

                    st.write(t('interceptacao.records_extracted', count=len(df), ips=df['Sender IP'].nunique()))
                    st.write(t('interceptacao.enriching_ips'))

                    api_key_i = st.session_state.api_key or None
                    if is_zip:
                        result = run_async(
                            processar_interceptacao_async(
                                intercept_data, output_intercept,
                                batch_size=batch_intercept, period=period_intercept,
                                cache_file=IP_CACHE_PATH,
                                update_callback=lambda msg: st.write(f"  {msg}"),
                                api_key=api_key_i
                            )
                        )
                    else:
                        result = run_async(
                            _enrich_df_async(
                                df, output_intercept, batch_intercept, period_intercept,
                                lambda msg: st.write(f"  {msg}"), api_key=api_key_i
                            )
                        )

                    if result is not None and not result.empty:
                        _set_df_interceptacao(result)
                        status.update(label=t('interceptacao.records_processed', count=len(result)),
                                      state="complete")
                    else:
                        status.update(label=t('interceptacao.no_results'), state="error")
                except Exception as e:
                    logger.exception("Falha no processamento da interceptação")
                    st.error(t('interceptacao.error', error=e))
                    status.update(label=t('interceptacao.error_label'), state="error")

    # Results
    df_i = st.session_state.get('df_interceptacao')
    if df_i is not None and not df_i.empty:
        # Garantir coluna Reputação
        if all(c in df_i.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']) and 'Reputação' not in df_i.columns:
            df_i = _add_reputacao_interceptacao(df_i)
            # Mesmo dataset, só com a coluna derivada: mantém a identidade.
            st.session_state['df_interceptacao'] = df_i

        st.divider()
        st.subheader(t('interceptacao.results_title'))
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric(t('relatorio.records'), len(df_i))
        with c2:
            st.metric(t('common.unique_ips'), df_i['Sender IP'].nunique())
        with c3:
            st.metric(t('interceptacao.messages'), len(df_i[df_i['type'].str.startswith('message', na=False)]))
        with c4:
            st.metric(t('interceptacao.calls'), len(df_i[df_i['type'].str.startswith('call', na=False)]))
        with c5:
            st.metric(t('interceptacao.logins'), len(df_i[df_i['type'].str.startswith('login', na=False)]))

        export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df_i.columns]
        df_display = df_i[export_cols]

        preview = df_display.head(PREVIEW_ROWS)
        st.dataframe(preview, height=400, hide_index=True, width='stretch')
        show_truncation(len(preview), len(df_display))

        st.subheader(t('interceptacao.downloads_title'))
        # Estes três eram gerados a CADA rerun da página, sem cache: em 200k
        # linhas são centenas de MB serializados por interação.
        df_exp = df_i[export_cols]
        exp_key = (_int_token(), tuple(export_cols))
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            if prepare_button(t('common.prepare_csv'), df_exp, 'int_csv'):
                st.download_button("📥 CSV", _csv_interceptacao(df_exp, exp_key),
                                   os.path.basename(output_intercept), "text/csv")
        with c2:
            if prepare_button(t('common.prepare_json'), df_exp, 'int_json'):
                st.download_button("📥 JSON", _json_interceptacao(df_exp, exp_key),
                                   "interceptacao.json", "application/json")
        with c3:
            _est = fmt_duracao(estimate_xlsx_seconds(len(df_exp), len(export_cols)))
            if prepare_button(t('common.prepare_excel'), df_exp, 'int_xlsx',
                              help=t('guards.xlsx_help', rows=fmt(len(df_exp)), duration=_est)):
                nome_xlsx = os.path.splitext(os.path.basename(output_intercept))[0]
                if len(df_exp) <= XLSX_DISK_THRESHOLD:
                    st.download_button(
                        t('common.excel_colored'), _xlsx_interceptacao(df_exp, exp_key),
                        nome_xlsx + '.xlsx',
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                else:
                    # Acima do limiar o arquivo vai para o disco: dezenas de MB
                    # em memória e no websocket derrubam a sessão.
                    caminho, resumo = _xlsx_grande_interceptacao(df_exp, nome_xlsx)
                    with open(caminho, 'rb') as fh:
                        st.download_button(
                            t('common.excel_colored'), fh, os.path.basename(caminho),
                            "application/vnd.openxmlformats-officedocument."
                            "spreadsheetml.sheet", key="dl_int_xlsx_grande")
                    declare_sheets(resumo)
        with c4:
            if os.path.exists(output_intercept):
                with open(output_intercept, 'rb') as f:
                    st.download_button(t('interceptacao.saved_file'), f,
                                       os.path.basename(output_intercept), "text/csv")

        if 'Ip_Dono' in df_i.columns and df_i['Ip_Dono'].notna().any():
            st.subheader(t('interceptacao.provider_chart'))
            contagem_prov = df_i['Ip_Dono'].value_counts()
            prov = contagem_prov.head(15).reset_index()
            show_truncation(len(prov), len(contagem_prov), t('interceptacao.unit_providers'))
            col_prov, col_qtd = t('common.provider'), t('common.count')
            prov.columns = [col_prov, col_qtd]
            fig = px.bar(prov, x=col_qtd, y=col_prov, orientation='h',
                color=col_qtd, color_continuous_scale='Viridis')
            fig.update_layout(height=400, showlegend=False, yaxis={'categoryorder':'total ascending'},
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                coloraxis_showscale=False)
            st.plotly_chart(fig, key='intercept_prov')

        if 'type' in df_i.columns:
            st.subheader(t('interceptacao.type_distribution'))
            type_counts = df_i['type'].value_counts().reset_index()
            col_tipo, col_qtd = t('common.type'), t('common.count')
            type_counts.columns = [col_tipo, col_qtd]
            fig = px.pie(type_counts, values=col_qtd, names=col_tipo, hole=0.4)
            fig.update_layout(height=350, plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, key='intercept_type')
