"""
Log Enrichment - Página de Interceptação Telemática
Processamento de logs WhatsApp (Message Log + Call Log) a partir de HTML/ZIP.
"""

import streamlit as st
import os
import io
import asyncio
import logging
import plotly.express as px

from interception_parser import (
    parse_zip_interception, parse_html_records, records_to_dataframe,
    processar_interceptacao_async, COLUNAS_EXPORT_INTERCEPTACAO,
    processar_resultados_interceptacao, _add_reputacao_interceptacao
)
from file_handler import export_xlsx_colored

from i18n import t

logger = logging.getLogger(__name__)


async def _enrich_df_async(df, output_file, batch_size, period, update_callback, api_key=None):
    """Enrich a pre-parsed DataFrame (from single HTML upload)"""
    import aiohttp
    from api_client import IPAPIClient, is_valid_ip

    unique_ips = df['Sender IP'].dropna().unique().tolist()
    unique_ips = [ip for ip in unique_ips if is_valid_ip(ip)]

    client = IPAPIClient(cache_file='ip_cache.json', api_key=api_key)

    cached = {ip: client.cache[ip] for ip in unique_ips if ip in client.cache}
    df = processar_resultados_interceptacao(df, cached)

    ips_to_query = [ip for ip in unique_ips if ip not in client.cache]
    if update_callback:
        update_callback(f"{len(cached)} do cache, {len(ips_to_query)} para consultar")

    if ips_to_query:
        total_batches = (len(ips_to_query) + batch_size - 1) // batch_size
        async with aiohttp.ClientSession() as session:
            for bn in range(total_batches):
                start = bn * batch_size
                batch = ips_to_query[start:start + batch_size]
                if update_callback:
                    update_callback(f"Lote {bn+1}/{total_batches}")
                results = await client.consultar_lote_ips(session, batch)
                df = processar_resultados_interceptacao(df, results)
                if bn < total_batches - 1:
                    await asyncio.sleep(period)
        client.salvar_cache()

    # Adicionar coluna Reputação
    df = _add_reputacao_interceptacao(df)

    # Salvar CSV
    export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df.columns]
    df[export_cols].to_csv(output_file, index=False, sep=';', encoding='utf-8-sig')

    if update_callback:
        update_callback(f"Salvo em {output_file}")
    return df


def page_interceptacao():
    from styles.components import section_header
    section_header(t('interceptacao.title'), t('interceptacao.subtitle'), divider="red")

    st.info("""
    **Como funciona:**
    1. Faça upload do arquivo ZIP contendo os 15 dias de interceptação (ZIP de ZIPs com records.html)
    2. Ou faça upload de um único arquivo records.html
    3. O sistema extrai IPs do **Message Log** e **Call Log**
    4. Os IPs são enriquecidos via IP-API
    5. O resultado é salvo em **CSV** e **Excel (.xlsx)** com reputação colorida
    """)

    output_intercept = st.text_input("💾 Arquivo de saída (.csv)", value="interceptacao_resultado.csv", key="output_intercept")
    if not output_intercept.lower().endswith('.csv'):
        output_intercept = os.path.splitext(output_intercept)[0] + '.csv'

    tab_zip, tab_html = st.tabs(["📦 Upload ZIP (15 dias)", "📄 Upload HTML único"])
    intercept_data = None
    is_zip = True

    with tab_zip:
        uploaded_zip = st.file_uploader("Upload do ZIP de interceptação", type=['zip'], key="intercept_zip")
        if uploaded_zip:
            st.success(f"📦 **{uploaded_zip.name}** carregado")
            intercept_data = uploaded_zip.getvalue()
            is_zip = True
            import zipfile
            try:
                zf = zipfile.ZipFile(io.BytesIO(intercept_data))
                st.caption(f"{len(zf.namelist())} arquivos no ZIP")
                zf.close()
            except Exception:
                pass

    with tab_html:
        uploaded_html = st.file_uploader("Upload de records.html", type=['html', 'htm'], key="intercept_html")
        if uploaded_html:
            st.success(f"📄 **{uploaded_html.name}** carregado")
            intercept_data = uploaded_html.getvalue()
            is_zip = False
            try:
                html_content = intercept_data.decode('utf-8', errors='ignore')
                records = parse_html_records(html_content)
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Total", len(records))
                with c2:
                    st.metric("Messages", len([r for r in records if r['type'].startswith('message')]))
                with c3:
                    st.metric("Calls", len([r for r in records if r['type'].startswith('call')]))
            except Exception:
                pass

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
                        html_content = intercept_data.decode('utf-8', errors='ignore')
                        records = parse_html_records(html_content, update_callback=lambda msg: st.write(f"  {msg}"))
                        df = records_to_dataframe(records)

                    if df.empty:
                        st.warning("Nenhum registro encontrado")
                        status.update(label="Sem registros", state="error")
                        return

                    st.write(f"✅ {len(df)} registros extraídos, {df['Sender IP'].nunique()} IPs únicos")
                    st.write("🔄 Enriquecendo IPs via API...")

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        api_key_i = st.session_state.api_key or None
                        result = loop.run_until_complete(
                            processar_interceptacao_async(
                                intercept_data if is_zip else None, output_intercept,
                                batch_size=batch_intercept, period=period_intercept,
                                cache_file='ip_cache.json',
                                update_callback=lambda msg: st.write(f"  {msg}"),
                                api_key=api_key_i
                            ) if is_zip else _enrich_df_async(
                                df, output_intercept, batch_intercept, period_intercept,
                                lambda msg: st.write(f"  {msg}"), api_key=api_key_i
                            )
                        )
                    finally:
                        loop.close()

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
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Registros", len(df_i))
        with c2:
            st.metric("IPs Únicos", df_i['Sender IP'].nunique())
        with c3:
            st.metric("Messages", len(df_i[df_i['type'].str.startswith('message', na=False)]))
        with c4:
            st.metric("Calls", len(df_i[df_i['type'].str.startswith('call', na=False)]))

        export_cols = [c for c in COLUNAS_EXPORT_INTERCEPTACAO if c in df_i.columns]
        df_display = df_i[export_cols]

        st.dataframe(df_display, height=400, hide_index=True, width='stretch')

        st.subheader("📥 Downloads")
        df_exp = df_i[export_cols]
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            csv_data = df_exp.to_csv(index=False, sep=';').encode('utf-8-sig')
            st.download_button("📥 CSV", csv_data, output_intercept, "text/csv")
        with c2:
            json_data = df_exp.to_json(orient='records', force_ascii=False, indent=2)
            st.download_button("📥 JSON", json_data, "interceptacao.json", "application/json")
        with c3:
            xlsx_buf = io.BytesIO()
            export_xlsx_colored(df_exp, xlsx_buf)
            xlsx_buf.seek(0)
            xlsx_filename = os.path.splitext(output_intercept)[0] + '.xlsx'
            st.download_button("📥 Excel (colorido)", xlsx_buf.getvalue(),
                xlsx_filename,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
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
