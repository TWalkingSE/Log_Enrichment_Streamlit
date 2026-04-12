"""
Log Enrichment - Reusable UI Components
Streamlit-native components using the design system tokens.
"""

import streamlit as st
from styles.theme import COLORS
from i18n import t


def section_header(title, subtitle=None, divider="violet"):
    """Render a standardized page/section header."""
    st.header(title, divider=divider)
    if subtitle:
        st.caption(subtitle)


def empty_state(message=None, icon="📭", hint=None):
    """Render a centered empty state with icon and message."""
    if message is None:
        message = t('common.no_data_processed')
    if hint is None:
        hint = t('common.use_entrada_tab')
    st.markdown(
        f'<div class="le-empty-state">'
        f'<div class="le-empty-icon">{icon}</div>'
        f'<div class="le-empty-msg">{message}</div>'
        f'{"<div class=\"le-empty-hint\">" + hint + "</div>" if hint else ""}'
        f'</div>',
        unsafe_allow_html=True,
    )


def status_badge(text, variant="info"):
    """Render an inline status badge. Variants: success, warning, info, danger, primary."""
    return f'<span class="le-badge le-badge-{variant}">{text}</span>'


def kpi_row(items):
    """
    Render a row of KPI metric cards inside bordered containers.

    items: list of dicts with keys:
        - label: str (metric label)
        - value: str|int|float (metric value)
        - delta: str|None (delta text, optional)
        - delta_color: str ('normal'|'inverse'|'off', default 'normal')
        - help: str|None (tooltip text, optional)
    """
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        with col:
            with st.container(border=True):
                st.metric(
                    label=item.get('label', ''),
                    value=item.get('value', ''),
                    delta=item.get('delta'),
                    delta_color=item.get('delta_color', 'normal'),
                    help=item.get('help'),
                )


def sidebar_brand(version="v5.2 Pro"):
    """Render the sidebar brand/logo section."""
    st.markdown("### 🔍 Log Enrichment")
    st.markdown(f'<div class="le-sidebar-version">{version}</div>', unsafe_allow_html=True)


def sidebar_data_summary():
    """Render the sidebar data summary section."""
    if st.session_state.df_resultado is not None:
        df = st.session_state.df_resultado
        n_total = len(df)
        n_unique = df['Ip'].nunique() if 'Ip' in df.columns else 0
        n_prov = df['Ip_Dono'].dropna().nunique() if 'Ip_Dono' in df.columns else 0
        with st.container(border=True):
            st.markdown(f"**{t('sidebar.data_loaded')}**")
            st.caption(t('sidebar.data_summary', total=f'{n_total:,}', unique=f'{n_unique:,}', providers=n_prov))

            n_targets = len(st.session_state.get('stored_targets', {}))
            if n_targets > 0:
                st.caption(t('sidebar.targets_stored', count=n_targets))
    else:
        with st.container(border=True):
            no_data = t('sidebar.no_data')
            use_entrada = t('sidebar.use_entrada')
            st.markdown(
                '<div class="le-empty-state" style="padding: 0.5rem 0;">'
                '<div style="font-size: 1.2rem; opacity: 0.4;">📭</div>'
                f'<div class="le-empty-msg" style="font-size: 0.78rem;">{no_data}</div>'
                f'<div class="le-empty-hint">{use_entrada}</div>'
                '</div>',
                unsafe_allow_html=True,
            )


def sidebar_api_status():
    """Render the sidebar API status badge."""
    api_key = st.session_state.get('api_key', '')
    if api_key:
        st.markdown(status_badge(t('sidebar.api_paid_active'), "success"), unsafe_allow_html=True)
    else:
        st.markdown(status_badge(t('sidebar.api_free'), "warning"), unsafe_allow_html=True)


def sidebar_footer():
    """Render the sidebar footer."""
    st.markdown('<div class="le-sidebar-footer">TWalking • AI-powered</div>', unsafe_allow_html=True)


def auth_header():
    """Render the auth page header with animated gradient."""
    st.markdown(
        '<div class="le-auth-card">'
        '<h1>🔍 Log Enrichment</h1>'
        f'<p>{t("auth.protected_access")}</p>'
        '</div>',
        unsafe_allow_html=True,
    )
