"""
Log Enrichment - Streamlit Application v5.2 Pro
Multipage architecture with st.navigation: config, CSS, sidebar, auth, and routing.
Page implementations in pages_app/ directory.
"""

import streamlit as st
import os
import logging
from datetime import datetime, timedelta

from dotenv import load_dotenv
load_dotenv()

from auth_password import verify_stored_password_hash, verify_plain_env_password
from i18n import t, get_lang, set_lang, SUPPORTED_LANGUAGES

# ============================================================
# PERSISTENT LOGGING
# ============================================================
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

OUTPUT_CSV_DIR = os.path.join(os.path.dirname(__file__), 'output', 'csv')
OUTPUT_MAPAS_DIR = os.path.join(os.path.dirname(__file__), 'output', 'mapas')
os.makedirs(OUTPUT_CSV_DIR, exist_ok=True)
os.makedirs(OUTPUT_MAPAS_DIR, exist_ok=True)

_file_handler = logging.FileHandler(
    os.path.join(log_dir, f'log_enrichment_{datetime.now().strftime("%Y%m%d")}.log'),
    encoding='utf-8'
)
_file_handler.setFormatter(logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[_file_handler, logging.StreamHandler()])

# Suprimir WebSocketClosedError do Tornado/asyncio (bug interno do Streamlit)
logging.getLogger('tornado.application').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Register Plotly theme & design system
from styles.theme import register_plotly_theme
from styles.custom_css import inject_global_css
from styles.components import (
    sidebar_brand, sidebar_data_summary, sidebar_api_status, sidebar_footer,
    auth_header,
)
register_plotly_theme()

# ============================================================
# AUTH HELPERS
# ============================================================
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD', '')
AUTH_PASSWORD_HASH = os.getenv('AUTH_PASSWORD_HASH', '')
MAX_LOGIN_ATTEMPTS = 5

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="Log Enrichment",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS — centralized design system
# ============================================================
inject_global_css()

# ============================================================
# SESSION STATE
# ============================================================
def init_session_state():
    defaults = {
        'df_resultado': None,
        'processing': False,
        'log_messages': [],
        'alvo': '',
        'output_file': os.path.join(OUTPUT_CSV_DIR, 'resultado_logs.csv'),
        'batch_size': 500,
        'period': 0,
        'use_cache': True,
        'incremental': True,
        'api_key': os.getenv('IPAPI_KEY', ''),
        'history': [],
        'authenticated': False,
        'stored_targets': {},
        'ai_tier': 'lite',
        'ai_ollama_url': 'http://localhost:11434',
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val

init_session_state()

# ============================================================
# AUTHENTICATION
# ============================================================
def check_auth():
    if not AUTH_PASSWORD and not AUTH_PASSWORD_HASH:
        return True
    return st.session_state.get('authenticated', False)

if (AUTH_PASSWORD or AUTH_PASSWORD_HASH) and not st.session_state.authenticated:
    auth_header()

    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'login_locked_until' not in st.session_state:
        st.session_state.login_locked_until = None

    if st.session_state.login_locked_until and datetime.now() < st.session_state.login_locked_until:
        remaining = (st.session_state.login_locked_until - datetime.now()).seconds
        st.error(t('auth.too_many_attempts', remaining=remaining))
        st.stop()
    elif st.session_state.login_locked_until:
        st.session_state.login_locked_until = None
        st.session_state.login_attempts = 0

    pwd = st.text_input(t('auth.password'), type="password", key="auth_pwd")
    if st.button(t('auth.login'), type="primary"):
        is_valid = False
        if AUTH_PASSWORD_HASH:
            is_valid = verify_stored_password_hash(pwd, AUTH_PASSWORD_HASH)
        elif AUTH_PASSWORD:
            is_valid = verify_plain_env_password(pwd, AUTH_PASSWORD)

        if is_valid:
            st.session_state.authenticated = True
            st.session_state.login_attempts = 0
            st.rerun()
        else:
            st.session_state.login_attempts += 1
            remaining = MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
            if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
                st.session_state.login_locked_until = datetime.now() + timedelta(minutes=5)
                st.error(t('auth.locked'))
            else:
                st.error(t('auth.wrong_password', remaining=remaining))
    st.stop()

# ============================================================
# CACHE BACKUP ON STARTUP
# ============================================================
from analysis import backup_cache
if 'cache_backed_up' not in st.session_state:
    backup_cache()
    st.session_state.cache_backed_up = True

# Load history
from helpers.shared import load_history
load_history()

# ============================================================
# PAGE IMPORTS
# ============================================================
from pages_app.entrada import page_entrada
from pages_app.resultados import page_resultados
from pages_app.estatisticas import page_estatisticas
from pages_app.mapa import page_mapa
from pages_app.relatorio import page_relatorio
from pages_app.interceptacao import page_interceptacao
from pages_app.configuracoes import page_configuracoes
from pages_app.analise.overview import page_overview
from pages_app.analise.risco import page_risco
from pages_app.analise.temporal import page_temporal
from pages_app.analise.geo import page_geo
from pages_app.analise.correlacao import page_correlacao
from pages_app.analise.comportamento import page_comportamento
from pages_app.analise.operacional import page_operacional

# ============================================================
# NAVIGATION — st.navigation() with grouped sections
# ============================================================
pages = {
    t('nav.data'): [
        st.Page(page_entrada, title=t('nav.data_input'), icon=":material/upload_file:"),
        st.Page(page_resultados, title=t('nav.results'), icon=":material/table_chart:"),
    ],
    t('nav.visualization'): [
        st.Page(page_estatisticas, title=t('nav.statistics'), icon=":material/bar_chart:"),
        st.Page(page_mapa, title=t('nav.map'), icon=":material/map:"),
    ],
    t('nav.analysis'): [
        st.Page(page_overview, title=t('nav.overview'), icon=":material/dashboard:"),
        st.Page(page_risco, title=t('nav.risk_threats'), icon=":material/shield:"),
        st.Page(page_temporal, title=t('nav.temporal_patterns'), icon=":material/schedule:"),
        st.Page(page_geo, title=t('nav.geolocation'), icon=":material/public:"),
        st.Page(page_correlacao, title=t('nav.correlation'), icon=":material/hub:"),
        st.Page(page_comportamento, title=t('nav.behavior'), icon=":material/fingerprint:"),
        st.Page(page_operacional, title=t('nav.operational'), icon=":material/description:"),
    ],
    t('nav.system'): [
        st.Page(page_interceptacao, title=t('nav.interception'), icon=":material/phone_in_talk:"),
        st.Page(page_relatorio, title=t('nav.report'), icon=":material/picture_as_pdf:"),
        st.Page(page_configuracoes, title=t('nav.settings'), icon=":material/settings:"),
    ],
}

pg = st.navigation(pages)

# ============================================================
# SIDEBAR — Data summary & status
# ============================================================
with st.sidebar:
    # Language selector
    lang_options = list(SUPPORTED_LANGUAGES.keys())
    lang_labels = list(SUPPORTED_LANGUAGES.values())
    current_lang = get_lang()
    current_idx = lang_options.index(current_lang) if current_lang in lang_options else 0
    selected_lang = st.selectbox(
        t('sidebar.language'),
        lang_options,
        index=current_idx,
        format_func=lambda x: SUPPORTED_LANGUAGES[x],
        key='lang_selector',
    )
    if selected_lang != current_lang:
        set_lang(selected_lang)
        st.rerun()

    sidebar_brand()
    st.divider()
    sidebar_data_summary()
    sidebar_api_status()
    sidebar_footer()

# ============================================================
# RUN SELECTED PAGE
# ============================================================
pg.run()
