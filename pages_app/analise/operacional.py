"""
Análise Avançada - Operacional
Investigativa, Análise AI, Comparação Temporal, Saúde dos Dados.
"""

import streamlit as st
import pandas as pd
import json
import logging
import os
from datetime import datetime, date

from analysis import compute_data_health
from helpers.large_data import gate
from ip_investigativo import calcular_score, render_analise_investigativa, selecionar_provedores
from components.visualizations import render_health_gauges
from ai_assistant import AI_MODELS, check_ollama_status, get_default_ai_tier, run_ai_analysis
from i18n import t, t_or
from helpers.atomic_io import atomic_write_json

logger = logging.getLogger(__name__)

_SNAPSHOTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                'output', 'analysis_snapshots.json')


def _load_snapshots():
    """Snapshots salvos. Arquivo ilegível é informado, não tratado como vazio."""
    if not os.path.exists(_SNAPSHOTS_FILE):
        return []
    try:
        with open(_SNAPSHOTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        logger.exception("Snapshots ilegíveis em %s", _SNAPSHOTS_FILE)
        st.error(t('operacional.snapshots_unreadable', error=exc, path=_SNAPSHOTS_FILE))
        return []


def _save_snapshot(snapshot):
    snapshots = _load_snapshots()
    snapshots.append(snapshot)
    # Manter no máximo 50 snapshots
    if len(snapshots) > 50:
        snapshots = snapshots[-50:]
    atomic_write_json(_SNAPSHOTS_FILE, snapshots, ensure_ascii=False, indent=2, default=str)


def page_operacional():
    from styles.components import section_header, empty_state
    section_header(t('operacional.title'), divider="gray")

    df = st.session_state.df_resultado
    if df is None or df.empty:
        empty_state(t('operacional.no_data'), "📋", t('common.process_data_first'))
        return

    # ── Investigativa ──
    with st.container(border=True):
        st.subheader(t('operacional.investigative_title'))
        render_analise_investigativa(df)

    # ── Análise AI ──
    with st.container(border=True):
        st.subheader(t('operacional.ai_title'))

        # Status do Ollama
        ollama_url = st.session_state.get('ai_ollama_url', 'http://localhost:11434')
        status = check_ollama_status(ollama_url)

        if status['online']:
            st.success(t('operacional.ollama_online', count=len(status['models'])))

            col_ai1, col_ai2 = st.columns(2)
            with col_ai1:
                current_tier = st.session_state.get('ai_tier', get_default_ai_tier())
                if current_tier not in AI_MODELS:
                    current_tier = get_default_ai_tier()
                tier = st.selectbox(t('operacional.model_tier'), list(AI_MODELS.keys()),
                                     index=list(AI_MODELS.keys()).index(current_tier),
                                     format_func=lambda k: f"{k.title()} — {AI_MODELS[k]['label']}",
                                     key="ai_tier_sel")
                st.session_state['ai_tier'] = tier
                ips_por_prov = st.slider(t('operacional.ips_per_provider'), 3, 10, 5, key="ai_ips_prov")
            with col_ai2:
                dt_fato = st.date_input(t('operacional.fact_date'), value=date.today(), key="ai_dt_fato")
                # Mesmos códigos da análise investigativa: `calcular_score`
                # compara com o `Periodo` dos registros (Diurno/Noturno). As
                # opções anteriores (manhã/tarde/noite/madrugada) nunca
                # coincidiam, e os 15 pontos de período nunca eram somados.
                periodo_fato = st.selectbox(t('operacional.fact_period'), ["Diurno", "Noturno"],
                                            format_func=lambda k: t(f'common.period.{k}'),
                                            key="ai_periodo")
                janela_h = st.slider(t('operacional.time_window'), 1, 48, 24, key="ai_janela")

            if st.button(t('operacional.run_ai'), type="primary", key="ai_run_btn"):
                with st.spinner(t('operacional.ai_running')):
                    # O prompt da IA descreve REGISTROS (Ip, Data, Ip_Dono,
                    # Ip_Proxy...). `calculate_risk_scores` devolve uma linha
                    # por IP com outras colunas — o prompt saía com "0 IPs" e
                    # percentuais acima de 100%. Mesma preparação da análise
                    # investigativa.
                    dt_fato_dt = datetime.combine(dt_fato, datetime.min.time())
                    provedores, contagem, _cobertura = selecionar_provedores(df)
                    df_scored = calcular_score(df, dt_fato_dt, periodo_fato, contagem,
                                               janela_horas_max=float(janela_h))

                    result = run_ai_analysis(
                        df_scored=df_scored,
                        provedores_sel=provedores,
                        contagem_prov=contagem,
                        dt_fato=dt_fato_dt,
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
                    st.success(t('operacional.ai_done', seconds=ai_result['elapsed_seconds'],
                                 model=ai_result['model_used']))

                    # Confiança
                    conf = data.get('confianca', 'desconhecida')
                    conf_colors = {'alta': '🟢', 'media': '🟡', 'baixa': '🔴'}
                    st.markdown(t('operacional.confidence', icon=conf_colors.get(conf, '⚪'),
                                  level=t_or(f'operacional.conf.{conf}', conf.title()),
                                  reason=data.get('motivo_confianca', '')))

                    # Narrativa
                    if data.get('resumo_narrativo'):
                        st.markdown(t('operacional.summary', text=data['resumo_narrativo']))

                    # Provedores selecionados
                    provedores_ai = data.get('provedores', [])
                    if provedores_ai:
                        st.markdown(t('operacional.selected_providers'))
                        for prov in provedores_ai:
                            with st.expander(t('operacional.provider_expander', name=prov.get('nome', '?'),
                                               count=prov.get('registros_total', 0),
                                               pct=f"{prov.get('percentual_cobertura', 0):.0f}"),
                                             expanded=False):
                                st.caption(prov.get('justificativa', ''))
                                ips_sel = prov.get('ips_selecionados', [])
                                if ips_sel:
                                    ip_rows = []
                                    for ip_info in ips_sel:
                                        ip_rows.append({
                                            'IP': ip_info.get('ip', ''),
                                            t('operacional.col_type'): ip_info.get('tipo', ''),
                                            t('operacional.col_date'): ip_info.get('data', ''),
                                            t('operacional.col_provider'): ip_info.get('provedor', ''),
                                            'Score': ip_info.get('score', 0),
                                            t('operacional.col_reason'): ip_info.get('motivo', ''),
                                        })
                                    st.dataframe(pd.DataFrame(ip_rows), hide_index=True, width='stretch')

                    # Alertas
                    alertas = data.get('alertas', [])
                    if alertas:
                        st.markdown(t('operacional.alerts'))
                        for alerta in alertas:
                            st.warning(alerta)

                    # Cobertura
                    cob = data.get('cobertura_total', 0)
                    st.caption(t('operacional.coverage', pct=f"{cob:.0f}"))

                    # Warnings de validação
                    warnings = ai_result.get('validation_warnings', [])
                    if warnings:
                        with st.expander(t('operacional.validation_warnings'), expanded=False):
                            for w in warnings:
                                st.caption(f"• {w}")
                    if ai_result.get('fallback_used'):
                        st.info(t('operacional.fallback', requested=ai_result.get('requested_model'),
                                  used=ai_result.get('model_used')))
                    for note in ai_result.get('notes', []):
                        st.info(note)
                else:
                    for note in ai_result.get('notes', []):
                        st.warning(note)
                    st.error(t('operacional.ai_error',
                               error=ai_result.get('error') or t('operacional.unknown_error')))
        else:
            st.warning(t('operacional.ollama_offline', error=status.get('error', '')))
            st.caption(t('operacional.ollama_install'))

    # ── Comparação Temporal ──
    with st.container(border=True):
        st.subheader(t('operacional.comparison_title'))
        st.caption(t('operacional.snapshots_subtitle'))

        alvo_atual = st.session_state.get('alvo', '')
        inv_result = st.session_state.get('inv_result')

        tab_save, tab_compare = st.tabs([t('operacional.tab_save'), t('operacional.tab_compare')])

        with tab_save:
            if inv_result and alvo_atual:
                snap_label = st.text_input(
                    t('operacional.snapshot_label'),
                    value=f"{alvo_atual} — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                    key="snap_label"
                )
                if st.button(t('operacional.save_snapshot'), key="snap_save_btn"):
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
                    st.success(t('operacional.snapshot_saved', label=snap_label))
            else:
                st.info(t('operacional.run_investigative_first'))

        with tab_compare:
            snapshots = _load_snapshots()
            if len(snapshots) < 2:
                st.info(t('operacional.no_snapshots') if not snapshots else t('operacional.one_snapshot'))
            else:
                # Filtrar por alvo se disponível
                alvos = sorted(set(s.get('alvo', '') for s in snapshots))
                if len(alvos) > 1:
                    opt_all = t('common.all')
                    alvo_filter = st.selectbox(t('operacional.filter_target'), [opt_all] + alvos,
                                               key="snap_filter_alvo")
                    if alvo_filter != opt_all:
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

                    st.markdown(t('operacional.side_by_side'))
                    comp_data = []
                    metrics = [
                        (t('operacional.m_records'), 'total_registros'),
                        (t('common.unique_ips'), 'ips_unicos'),
                        ('IPv6', 'n_ipv6'),
                        (t('operacional.m_selected'), 'n_selecionados'),
                        (t('operacional.m_avg_score'), 'score_medio'),
                        (t('operacional.m_uniqueness'), 'score_unicidade'),
                        (t('operacional.m_coverage'), 'cobertura'),
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
                            t('operacional.col_metric'): label,
                            f'A: {a["label"][:30]}': va,
                            f'B: {b["label"][:30]}': vb,
                            'Δ': diff_str,
                        })

                    st.dataframe(pd.DataFrame(comp_data), hide_index=True, width='stretch')

                    # IPs que mudaram
                    ips_a = set(a.get('ips_selecionados', []))
                    ips_b = set(b.get('ips_selecionados', []))
                    novos = ips_b - ips_a
                    removidos = ips_a - ips_b
                    mantidos = ips_a & ips_b

                    mc1, mc2, mc3 = st.columns(3)
                    with mc1:
                        st.metric(t('operacional.kept'), len(mantidos))
                    with mc2:
                        st.metric(t('operacional.new_in_b'), len(novos))
                    with mc3:
                        st.metric(t('operacional.removed_from_a'), len(removidos))

                    if novos:
                        with st.expander(t('operacional.new_ips_b', count=len(novos))):
                            for ip in sorted(novos):
                                st.code(ip, language=None)
                    if removidos:
                        with st.expander(t('operacional.missing_ips_b', count=len(removidos))):
                            for ip in sorted(removidos):
                                st.code(ip, language=None)

                    # Provedores
                    prov_a = set(a.get('provedores', []))
                    prov_b = set(b.get('provedores', []))
                    if prov_a != prov_b:
                        st.warning(t('operacional.providers_changed', a=', '.join(prov_a), b=', '.join(prov_b)))
                else:
                    st.warning(t('operacional.pick_two'))

    # ── Saúde dos Dados ──
    with st.container(border=True):
        st.subheader(t('operacional.health_title'))
        if gate(t('operacional.gate_health'), df, 'op_health'):
            health = compute_data_health(df)
            render_health_gauges(health)
