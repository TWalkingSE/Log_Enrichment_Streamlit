"""
Análise Avançada - Operacional
Investigativa, Análise AI, Comparação Temporal, Saúde dos Dados.
"""

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime, date

from analysis import compute_data_health, calculate_risk_scores
from ip_investigativo import render_analise_investigativa
from components.visualizations import render_health_gauges
from ai_assistant import AI_MODELS, check_ollama_status, get_default_ai_tier, run_ai_analysis
from styles.theme import COLORS
from i18n import t

_SNAPSHOTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                'output', 'analysis_snapshots.json')


def _load_snapshots():
    if os.path.exists(_SNAPSHOTS_FILE):
        with open(_SNAPSHOTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []


def _save_snapshot(snapshot):
    snapshots = _load_snapshots()
    snapshots.append(snapshot)
    # Manter no máximo 50 snapshots
    if len(snapshots) > 50:
        snapshots = snapshots[-50:]
    os.makedirs(os.path.dirname(_SNAPSHOTS_FILE), exist_ok=True)
    with open(_SNAPSHOTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(snapshots, f, ensure_ascii=False, indent=2, default=str)


def page_operacional():
    from styles.components import section_header, empty_state
    section_header(t('operacional.title'), divider="gray")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('operacional.no_data'), "📋", t('common.process_data_first'))
        return

    # ── Investigativa ──
    with st.container(border=True):
        st.subheader("🔍 Análise Investigativa")
        render_analise_investigativa(df)

    # ── Análise AI ──
    with st.container(border=True):
        st.subheader("🤖 Análise AI (Ollama)")

        # Status do Ollama
        ollama_url = st.session_state.get('ai_ollama_url', 'http://localhost:11434')
        status = check_ollama_status(ollama_url)

        if status['online']:
            st.success(f"✅ Ollama online — {len(status['models'])} modelo(s) disponível(is)")

            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                current_tier = st.session_state.get('ai_tier', get_default_ai_tier())
                if current_tier not in AI_MODELS:
                    current_tier = get_default_ai_tier()
                tier = st.selectbox("Tier do modelo", list(AI_MODELS.keys()),
                                     index=list(AI_MODELS.keys()).index(current_tier),
                                     format_func=lambda t: f"{t.title()} — {AI_MODELS[t]['label']}",
                                     key="ai_tier_sel")
                st.session_state['ai_tier'] = tier
                ips_por_prov = st.slider("IPs por provedor", 3, 10, 5, key="ai_ips_prov")
            with col_ai2:
                dt_fato = st.date_input("Data do fato", value=date.today(), key="ai_dt_fato")
                periodo_fato = st.selectbox("Período do fato", ["manhã", "tarde", "noite", "madrugada", "desconhecido"], key="ai_periodo")
                janela_h = st.slider("Janela temporal (horas)", 1, 48, 24, key="ai_janela")

            if st.button("🧠 Executar Análise AI", type="primary", key="ai_run_btn"):
                with st.spinner("Analisando com IA... pode levar alguns minutos."):
                    # Preparar dados
                    df_scored = calculate_risk_scores(df)
                    contagem = df['Ip_Dono'].value_counts().to_dict() if 'Ip_Dono' in df.columns else {}
                    provedores = list(contagem.keys())[:10]

                    result = run_ai_analysis(
                        df_scored=df_scored,
                        provedores_sel=provedores,
                        contagem_prov=contagem,
                        dt_fato=datetime.combine(dt_fato, datetime.min.time()),
                        periodo_fato=periodo_fato,
                        janela_horas=janela_h,
                        ips_por_provedor=ips_por_prov,
                        tier=tier,
                        alvo=st.session_state.alvo or '',
                        base_url=ollama_url,
                    )

                    st.session_state['ai_result'] = result

            # Exibir resultado
            ai_result = st.session_state.get('ai_result')
            if ai_result:
                if ai_result['success']:
                    data = ai_result['data']
                    st.success(f"✅ Análise concluída em {ai_result['elapsed_seconds']}s (modelo: {ai_result['model_used']})")

                    # Confiança
                    conf = data.get('confianca', 'desconhecida')
                    conf_colors = {'alta': '🟢', 'media': '🟡', 'baixa': '🔴'}
                    st.markdown(f"**Confiança:** {conf_colors.get(conf, '⚪')} {conf.title()} — {data.get('motivo_confianca', '')}")

                    # Narrativa
                    if data.get('resumo_narrativo'):
                        st.markdown(f"**Resumo:**\n\n{data['resumo_narrativo']}")

                    # Provedores selecionados
                    provedores_ai = data.get('provedores', [])
                    if provedores_ai:
                        st.markdown("**Provedores selecionados:**")
                        for prov in provedores_ai:
                            with st.expander(f"📡 {prov.get('nome', '?')} — {prov.get('registros_total', 0)} registros ({prov.get('percentual_cobertura', 0):.0f}%)", expanded=False):
                                st.caption(prov.get('justificativa', ''))
                                ips_sel = prov.get('ips_selecionados', [])
                                if ips_sel:
                                    ip_rows = []
                                    for ip_info in ips_sel:
                                        ip_rows.append({
                                            'IP': ip_info.get('ip', ''),
                                            'Tipo': ip_info.get('tipo', ''),
                                            'Data': ip_info.get('data', ''),
                                            'Provedor': ip_info.get('provedor', ''),
                                            'Score': ip_info.get('score', 0),
                                            'Motivo': ip_info.get('motivo', ''),
                                        })
                                    st.dataframe(pd.DataFrame(ip_rows), hide_index=True, use_container_width=True)

                    # Alertas
                    alertas = data.get('alertas', [])
                    if alertas:
                        st.markdown("**Alertas:**")
                        for alerta in alertas:
                            st.warning(alerta)

                    # Cobertura
                    cob = data.get('cobertura_total', 0)
                    st.caption(f"Cobertura total: {cob:.0f}%")

                    # Warnings de validação
                    warnings = ai_result.get('validation_warnings', [])
                    if warnings:
                        with st.expander("⚠️ Avisos de validação", expanded=False):
                            for w in warnings:
                                st.caption(f"• {w}")
                    if ai_result.get('fallback_used'):
                        st.info(
                            f"Fallback automático ativado: solicitado `{ai_result.get('requested_model')}`, "
                            f"usado `{ai_result.get('model_used')}`."
                        )
                    for note in ai_result.get('notes', []):
                        st.info(note)
                else:
                    for note in ai_result.get('notes', []):
                        st.warning(note)
                    st.error(f"❌ Erro na análise AI: {ai_result.get('error', 'Erro desconhecido')}")
        else:
            st.warning(f"⚠️ Ollama offline: {status.get('error', '')}")
            st.caption("Para usar a análise AI, instale e inicie o Ollama: [ollama.ai](https://ollama.ai)")

    # ── Comparação Temporal ──
    with st.container(border=True):
        st.subheader("📅 Comparação Temporal entre Investigações")
        st.caption("Salve snapshots da análise atual e compare com análises anteriores do mesmo alvo")

        alvo_atual = st.session_state.get('alvo', '')
        inv_result = st.session_state.get('inv_result')

        tab_save, tab_compare = st.tabs(["💾 Salvar Snapshot", "📊 Comparar"])

        with tab_save:
            if inv_result and alvo_atual:
                snap_label = st.text_input(
                    "Rótulo do snapshot",
                    value=f"{alvo_atual} — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                    key="snap_label"
                )
                if st.button("💾 Salvar Análise Atual", key="snap_save_btn"):
                    scored = inv_result.get('df_scored', pd.DataFrame())
                    selecionados = inv_result.get('df_selecionados', pd.DataFrame())
                    snapshot = {
                        'label': snap_label,
                        'alvo': alvo_atual,
                        'timestamp': datetime.now().isoformat(),
                        'dt_fato': str(inv_result.get('dt_fato', '')),
                        'total_registros': len(scored),
                        'ips_unicos': int(scored['Ip'].nunique()) if 'Ip' in scored.columns else 0,
                        'provedores': inv_result.get('provedores_sel', []),
                        'cobertura': inv_result.get('pct_cobertura', 0),
                        'score_medio': round(float(scored['Score'].mean()), 1) if 'Score' in scored.columns and not scored.empty else 0,
                        'score_unicidade': inv_result.get('resultado_unicidade', {}).get('score', 0),
                        'n_ipv6': int(scored['Tipo_IP'].eq('IPv6').sum()) if 'Tipo_IP' in scored.columns else 0,
                        'n_selecionados': len(selecionados),
                        'ips_selecionados': selecionados['Ip'].tolist() if 'Ip' in selecionados.columns else [],
                        'resumo': inv_result.get('resumo_narrativo', '')[:500],
                    }
                    _save_snapshot(snapshot)
                    st.success(f"✅ Snapshot salvo: **{snap_label}**")
            else:
                st.info("Execute a Análise Investigativa primeiro para salvar um snapshot.")

        with tab_compare:
            snapshots = _load_snapshots()
            if len(snapshots) < 2:
                st.info(f"{'Nenhum snapshot salvo.' if not snapshots else '1 snapshot salvo — salve ao menos 2 para comparar.'}")
            else:
                # Filtrar por alvo se disponível
                alvos = sorted(set(s.get('alvo', '') for s in snapshots))
                if len(alvos) > 1:
                    alvo_filter = st.selectbox("Filtrar por alvo", ['Todos'] + alvos, key="snap_filter_alvo")
                    if alvo_filter != 'Todos':
                        snapshots = [s for s in snapshots if s.get('alvo') == alvo_filter]

                labels = [f"{s['label']} ({s['timestamp'][:10]})" for s in snapshots]

                c1, c2 = st.columns(2)
                with c1:
                    idx_a = st.selectbox("Snapshot A", range(len(labels)),
                                          format_func=lambda i: labels[i],
                                          index=max(0, len(labels) - 2), key="snap_a")
                with c2:
                    idx_b = st.selectbox("Snapshot B", range(len(labels)),
                                          format_func=lambda i: labels[i],
                                          index=len(labels) - 1, key="snap_b")

                if idx_a != idx_b:
                    a, b = snapshots[idx_a], snapshots[idx_b]

                    st.markdown("#### Comparação lado a lado")
                    comp_data = []
                    metrics = [
                        ('Registros', 'total_registros'),
                        ('IPs Únicos', 'ips_unicos'),
                        ('IPv6', 'n_ipv6'),
                        ('Selecionados', 'n_selecionados'),
                        ('Score Médio', 'score_medio'),
                        ('Unicidade', 'score_unicidade'),
                        ('Cobertura %', 'cobertura'),
                    ]
                    for label, key in metrics:
                        va = a.get(key, 0)
                        vb = b.get(key, 0)
                        diff = vb - va if isinstance(vb, (int, float)) and isinstance(va, (int, float)) else '-'
                        if isinstance(diff, (int, float)):
                            arrow = '↑' if diff > 0 else ('↓' if diff < 0 else '='
                            )
                            diff_str = f"{arrow} {abs(diff)}"
                        else:
                            diff_str = '-'
                        comp_data.append({
                            'Métrica': label,
                            f'A: {a["label"][:30]}': va,
                            f'B: {b["label"][:30]}': vb,
                            'Δ': diff_str,
                        })

                    st.dataframe(pd.DataFrame(comp_data), hide_index=True, use_container_width=True)

                    # IPs que mudaram
                    ips_a = set(a.get('ips_selecionados', []))
                    ips_b = set(b.get('ips_selecionados', []))
                    novos = ips_b - ips_a
                    removidos = ips_a - ips_b
                    mantidos = ips_a & ips_b

                    mc1, mc2, mc3 = st.columns(3)
                    with mc1:
                        st.metric("🟢 Mantidos", len(mantidos))
                    with mc2:
                        st.metric("🔵 Novos em B", len(novos))
                    with mc3:
                        st.metric("🔴 Removidos de A", len(removidos))

                    if novos:
                        with st.expander(f"🔵 {len(novos)} IPs novos em B"):
                            for ip in sorted(novos):
                                st.code(ip, language=None)
                    if removidos:
                        with st.expander(f"🔴 {len(removidos)} IPs de A não presentes em B"):
                            for ip in sorted(removidos):
                                st.code(ip, language=None)

                    # Provedores
                    prov_a = set(a.get('provedores', []))
                    prov_b = set(b.get('provedores', []))
                    if prov_a != prov_b:
                        st.warning(f"Provedores mudaram: A={', '.join(prov_a)} → B={', '.join(prov_b)}")
                else:
                    st.warning("Selecione dois snapshots diferentes para comparar.")

    # ── Saúde dos Dados ──
    with st.container(border=True):
        st.subheader("💊 Saúde dos Dados")
        health = compute_data_health(df)
        render_health_gauges(health)
