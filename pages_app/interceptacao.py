"""
Log Enrichment - Página de Interceptação Telemática
Processamento de logs WhatsApp (Message Log + Call Log) a partir de HTML/ZIP.
"""

import streamlit as st
import os
import io
import logging
import plotly.express as px

from interception_parser import (
    parse_zip_interception, parse_html_records, records_to_dataframe,
    processar_interceptacao_async, COLUNAS_EXPORT_INTERCEPTACAO,
    processar_resultados_interceptacao, _add_reputacao_interceptacao
)
from file_handler import export_xlsx_colored, export_xlsx_to_disk
from helpers.shared import run_async
from validators import safe_output_path
from helpers.large_data import (
    estimate_xlsx_seconds, fmt_duracao, prepare_button, show_truncation,
    PREVIEW_ROWS, XLSX_DISK_THRESHOLD, fmt,
)

from i18n import t

logger = logging.getLogger(__name__)


def _xlsx_grande_interceptacao(df_exp, nome_base):
    """Excel colorido em disco, com progresso, revalidado contra o arquivo.

    Mesmo padrão da página de Resultados: o estado guarda um caminho, então
    precisa ser conferido no disco a cada rerun em vez de ficar em cache.
    """
    chave = (nome_base, len(df_exp), tuple(df_exp.columns))
    estado = st.session_state.get('_xlsx_disco_int')
    if estado and estado['key'] == chave and os.path.exists(estado['caminho']):
        return estado['caminho'], estado['resumo']

    barra = st.progress(0.0, text="Gerando Excel colorido...")

    def _progresso(feitas, total):
        barra.progress(min(feitas / max(total, 1), 1.0),
                       text=f"Gerando Excel colorido: {fmt(feitas)} de {fmt(total)} linhas")

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
    from validators import sanitize_dataframe_for_csv

    df, _results = await enrich_dataframe(
        df,
        'Sender IP',
        cache_file='ip_cache.json',
        api_key=api_key,
        batch_size=batch_size,
        period=period,
        update_callback=update_callback,
        apply_results=processar_resultados_interceptacao,
    )
    df = _add_reputacao_interceptacao(df)

    export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df.columns]
    sanitize_dataframe_for_csv(df[export_cols]).to_csv(
        output_file, index=False, sep=';', encoding='utf-8-sig'
    )
    if update_callback:
        update_callback(f"Salvo em {output_file}")
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
                    st.metric("Total", len(records))
                with c2:
                    st.metric("Messages", len([r for r in records if r['type'].startswith('message')]))
                with c3:
                    st.metric("Calls", len([r for r in records if r['type'].startswith('call')]))
                with c4:
                    st.metric("Logins", len([r for r in records if r['type'].startswith('login')]))
            except Exception as e:
                logger.warning("Prévia do HTML falhou (%s): %s", uploaded_html.name, e)
                st.caption(f"⚠️ Não foi possível pré-visualizar o HTML: {e}")

    with st.expander("⚙️ Opções", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            batch_intercept = st.number_input("Lote", 1, 1000, value=500, key="batch_i")
        with c2:
            period_intercept = st.number_input("Período (s)", 0, 300, value=0, key="period_i")

    st.divider()
    if st.button("▶️ Processar Interceptação", type="primary", key="btn_intercept"):
        if intercept_data is None:
            st.error("⚠️ Faça upload de um arquivo ZIP ou HTML!")
        else:
            with st.status("Processando interceptação telemática...", expanded=True) as status:
                try:
                    if is_zip:
                        st.write("📦 Extraindo dados do ZIP...")
                        df = parse_zip_interception(intercept_data, update_callback=lambda msg: st.write(f"  {msg}"))
                    else:
                        st.write("📄 Processando HTML...")
                        html_content = intercept_data.decode('utf-8', errors='replace')
                        records = parse_html_records(html_content, update_callback=lambda msg: st.write(f"  {msg}"))
                        df = records_to_dataframe(records)

                    if df.empty:
                        st.warning("Nenhum registro encontrado")
                        status.update(label="Sem registros", state="error")
                        return

                    st.write(f"✅ {len(df)} registros extraídos, {df['Sender IP'].nunique()} IPs únicos")
                    st.write("🔄 Enriquecendo IPs via API...")

                    api_key_i = st.session_state.api_key or None
                    if is_zip:
                        result = run_async(
                            processar_interceptacao_async(
                                intercept_data, output_intercept,
                                batch_size=batch_intercept, period=period_intercept,
                                cache_file='ip_cache.json',
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
                        st.session_state['df_interceptacao'] = result
                        status.update(label=f"✅ {len(result)} registros processados!", state="complete")
                    else:
                        status.update(label="Sem resultados", state="error")
                except Exception as e:
                    st.error(f"❌ Erro: {e}")
                    status.update(label="Erro", state="error")

    # Results
    df_i = st.session_state.get('df_interceptacao')
    if df_i is not None and not df_i.empty:
        # Garantir coluna Reputação
        if all(c in df_i.columns for c in ['Ip_Proxy', 'Ip_Hospedagem', 'Ip_Movel']) and 'Reputação' not in df_i.columns:
            df_i = _add_reputacao_interceptacao(df_i)
            st.session_state['df_interceptacao'] = df_i

        st.divider()
        st.subheader("📊 Resultados da Interceptação")
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Registros", len(df_i))
        with c2:
            st.metric("IPs Únicos", df_i['Sender IP'].nunique())
        with c3:
            st.metric("Messages", len(df_i[df_i['type'].str.startswith('message', na=False)]))
        with c4:
            st.metric("Calls", len(df_i[df_i['type'].str.startswith('call', na=False)]))
        with c5:
            st.metric("Logins", len(df_i[df_i['type'].str.startswith('login', na=False)]))

        export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df_i.columns]
        df_display = df_i[export_cols]

        preview = df_display.head(PREVIEW_ROWS)
        st.dataframe(preview, height=400, hide_index=True, use_container_width=True)
        show_truncation(len(preview), len(df_display))

        st.subheader("📥 Downloads")
        # Estes três eram gerados a CADA rerun da página, sem cache: em 200k
        # linhas são centenas de MB serializados por interação.
        df_exp = df_i[export_cols]
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            if prepare_button("⚙️ Preparar CSV", df_exp, 'int_csv'):
                st.download_button("📥 CSV",
                                   df_exp.to_csv(index=False, sep=';').encode('utf-8-sig'),
                                   output_intercept, "text/csv")
        with c2:
            if prepare_button("⚙️ Preparar JSON", df_exp, 'int_json'):
                st.download_button("📥 JSON",
                                   df_exp.to_json(orient='records', force_ascii=False, indent=2),
                                   "interceptacao.json", "application/json")
        with c3:
            _est = fmt_duracao(estimate_xlsx_seconds(len(df_exp), len(export_cols)))
            if prepare_button("⚙️ Preparar Excel", df_exp, 'int_xlsx',
                              help=f"{fmt(len(df_exp))} linhas — {_est} de geração"):
                nome_xlsx = os.path.splitext(os.path.basename(output_intercept))[0]
                if len(df_exp) <= XLSX_DISK_THRESHOLD:
                    xlsx_buf = io.BytesIO()
                    export_xlsx_colored(df_exp, xlsx_buf)
                    xlsx_buf.seek(0)
                    st.download_button(
                        "📥 Excel (colorido)", xlsx_buf.getvalue(),
                        nome_xlsx + '.xlsx',
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                else:
                    # Acima do limiar o arquivo vai para o disco: dezenas de MB
                    # em memória e no websocket derrubam a sessão.
                    caminho, resumo = _xlsx_grande_interceptacao(df_exp, nome_xlsx)
                    with open(caminho, 'rb') as fh:
                        st.download_button(
                            "📥 Excel (colorido)", fh, os.path.basename(caminho),
                            "application/vnd.openxmlformats-officedocument."
                            "spreadsheetml.sheet", key="dl_int_xlsx_grande")
                    if resumo.get('abas', 1) > 1:
                        st.caption(f"✅ {fmt(resumo['linhas'])} linhas gravadas em "
                                   f"{resumo['abas']} abas — o formato XLSX não aceita "
                                   f"mais de 1.048.575 linhas por planilha.")
                    else:
                        st.caption(f"✅ {fmt(resumo['linhas'])} linhas gravadas (total).")
        with c4:
            if os.path.exists(output_intercept):
                with open(output_intercept, 'rb') as f:
                    st.download_button("📥 Arquivo Salvo", f, output_intercept, "text/csv")

        if 'Ip_Dono' in df_i.columns and df_i['Ip_Dono'].notna().any():
            st.subheader("🏢 IPs por Provedor")
            prov = df_i['Ip_Dono'].value_counts().head(15).reset_index()
            prov.columns = ['Provedor', 'Qtd']
            fig = px.bar(prov, x='Qtd', y='Provedor', orientation='h',
                color='Qtd', color_continuous_scale='Viridis')
            fig.update_layout(height=400, showlegend=False, yaxis={'categoryorder':'total ascending'},
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                coloraxis_showscale=False)
            st.plotly_chart(fig, key='intercept_prov')

        if 'type' in df_i.columns:
            st.subheader("📋 Distribuição por Tipo")
            type_counts = df_i['type'].value_counts().reset_index()
            type_counts.columns = ['Tipo', 'Qtd']
            fig = px.pie(type_counts, values='Qtd', names='Tipo', hole=0.4)
            fig.update_layout(height=350, plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, key='intercept_type')
