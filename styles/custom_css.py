"""
Log Enrichment - Global CSS Injection
Centralized CSS for all Streamlit components. Called once in app.py.
Uses data-testid selectors for stability across Streamlit versions.
"""

from styles.theme import COLORS, BORDER_RADIUS, TRANSITIONS, FONT_SIZES, SPACING, get_css_vars


def get_global_css():
    """Return the complete CSS string for the application."""
    css_vars = get_css_vars()

    return f"""
{css_vars}

/* ══════════════════════════════════════════════════════════
   SIDEBAR
   ══════════════════════════════════════════════════════════ */
[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, {COLORS['gradient_start']} 0%, {COLORS['gradient_end']} 100%);
}}

[data-testid="stSidebar"] .stMarkdown h3 {{
    background: linear-gradient(135deg, {COLORS['primary']}, {COLORS['secondary']});
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-size: 1.3rem;
    font-weight: 700;
    letter-spacing: -0.02em;
}}

/* Sidebar nav items */
[data-testid="stSidebarNav"] a {{
    transition: {TRANSITIONS['normal']};
    border-radius: {BORDER_RADIUS['sm']};
}}
[data-testid="stSidebarNav"] a:hover {{
    background-color: rgba(129, 140, 248, 0.08);
}}
[data-testid="stSidebarNav"] a[aria-selected="true"] {{
    background-color: rgba(129, 140, 248, 0.12);
    border-left: 3px solid {COLORS['primary']};
}}

/* ══════════════════════════════════════════════════════════
   HIDE DEFAULT ELEMENTS
   ══════════════════════════════════════════════════════════ */
#MainMenu {{visibility: hidden;}}
footer {{visibility: hidden;}}

/* ══════════════════════════════════════════════════════════
   CONTAINERS & CARDS
   ══════════════════════════════════════════════════════════ */
[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"] {{
    transition: {TRANSITIONS['normal']};
    border-color: {COLORS['border']}40;
}}
[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlockBorderWrapper"]:hover {{
    border-color: {COLORS['primary']}60;
    box-shadow: 0 0 20px {COLORS['glow_primary']};
}}

/* ══════════════════════════════════════════════════════════
   METRIC CARDS
   ══════════════════════════════════════════════════════════ */
[data-testid="stMetric"] {{
    padding: {SPACING['sm']};
}}
[data-testid="stMetricLabel"] {{
    font-size: {FONT_SIZES['sm']};
    color: {COLORS['text_muted']};
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
}}
[data-testid="stMetricValue"] {{
    font-size: {FONT_SIZES['xl']};
    font-weight: 700;
    letter-spacing: -0.02em;
}}

/* ══════════════════════════════════════════════════════════
   HEADERS
   ══════════════════════════════════════════════════════════ */
[data-testid="stHeader"] {{
    background-color: transparent;
}}

/* Header divider accents */
.stMainBlockContainer hr {{
    border-color: {COLORS['border']}60;
}}

/* ══════════════════════════════════════════════════════════
   BUTTONS
   ══════════════════════════════════════════════════════════ */
[data-testid="stBaseButton-primary"] {{
    transition: {TRANSITIONS['fast']};
    font-weight: 600;
    letter-spacing: 0.01em;
}}
[data-testid="stBaseButton-primary"]:hover {{
    transform: translateY(-1px);
    box-shadow: 0 4px 12px {COLORS['glow_primary']};
}}

[data-testid="stBaseButton-secondary"] {{
    transition: {TRANSITIONS['fast']};
}}
[data-testid="stBaseButton-secondary"]:hover {{
    border-color: {COLORS['primary']};
    color: {COLORS['primary']};
}}

/* Download buttons */
[data-testid="stDownloadButton"] button {{
    transition: {TRANSITIONS['fast']};
}}
[data-testid="stDownloadButton"] button:hover {{
    border-color: {COLORS['success']};
    color: {COLORS['success']};
}}

/* ══════════════════════════════════════════════════════════
   TABS
   ══════════════════════════════════════════════════════════ */
[data-testid="stTabs"] button {{
    transition: {TRANSITIONS['fast']};
    font-weight: 500;
}}
[data-testid="stTabs"] button:hover {{
    color: {COLORS['primary']};
}}
[data-testid="stTabs"] button[aria-selected="true"] {{
    font-weight: 600;
}}

/* ══════════════════════════════════════════════════════════
   EXPANDERS
   ══════════════════════════════════════════════════════════ */
[data-testid="stExpander"] {{
    transition: {TRANSITIONS['normal']};
    border-color: {COLORS['border']}40;
}}
[data-testid="stExpander"]:hover {{
    border-color: {COLORS['primary']}50;
}}
[data-testid="stExpander"] summary {{
    font-weight: 500;
}}

/* ══════════════════════════════════════════════════════════
   INPUTS
   ══════════════════════════════════════════════════════════ */
[data-testid="stTextInput"] input:focus,
[data-testid="stSelectbox"] > div > div:focus-within,
[data-testid="stMultiSelect"] > div > div:focus-within {{
    border-color: {COLORS['primary']} !important;
    box-shadow: 0 0 0 1px {COLORS['primary']}40;
}}

/* ══════════════════════════════════════════════════════════
   DATAFRAMES
   ══════════════════════════════════════════════════════════ */
[data-testid="stDataFrame"] {{
    border-radius: {BORDER_RADIUS['md']};
}}

/* ══════════════════════════════════════════════════════════
   ALERTS (info, success, warning, error)
   ══════════════════════════════════════════════════════════ */
[data-testid="stAlert"] {{
    border-radius: {BORDER_RADIUS['md']};
    border-left-width: 4px;
}}

/* ══════════════════════════════════════════════════════════
   STATUS WIDGET
   ══════════════════════════════════════════════════════════ */
[data-testid="stStatusWidget"] {{
    border-radius: {BORDER_RADIUS['md']};
}}

/* ══════════════════════════════════════════════════════════
   POPOVER
   ══════════════════════════════════════════════════════════ */
[data-testid="stPopover"] button {{
    transition: {TRANSITIONS['fast']};
}}
[data-testid="stPopover"] button:hover {{
    border-color: {COLORS['primary']};
}}

/* ══════════════════════════════════════════════════════════
   SCROLLBAR
   ══════════════════════════════════════════════════════════ */
::-webkit-scrollbar {{
    width: 6px;
    height: 6px;
}}
::-webkit-scrollbar-track {{
    background: transparent;
}}
::-webkit-scrollbar-thumb {{
    background: {COLORS['border']};
    border-radius: {BORDER_RADIUS['pill']};
}}
::-webkit-scrollbar-thumb:hover {{
    background: {COLORS['text_dim']};
}}

/* ══════════════════════════════════════════════════════════
   AUTH PAGE
   ══════════════════════════════════════════════════════════ */
.le-auth-card {{
    max-width: 400px;
    margin: 80px auto 0;
    padding: {SPACING['xl']};
    text-align: center;
}}
.le-auth-card h1 {{
    background: linear-gradient(135deg, {COLORS['primary']}, {COLORS['secondary']});
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-size: {FONT_SIZES['display']};
    font-weight: 800;
    margin-bottom: {SPACING['xs']};
    animation: le-gradient-shift 6s ease infinite;
    background-size: 200% 200%;
}}
.le-auth-card p {{
    color: {COLORS['text_muted']};
    font-size: {FONT_SIZES['body']};
}}

@keyframes le-gradient-shift {{
    0%, 100% {{ background-position: 0% 50%; }}
    50% {{ background-position: 100% 50%; }}
}}

/* ══════════════════════════════════════════════════════════
   SIDEBAR BRAND
   ══════════════════════════════════════════════════════════ */
.le-sidebar-brand {{
    text-align: center;
    padding: {SPACING['sm']} 0;
}}
.le-sidebar-version {{
    color: {COLORS['text_dim']};
    font-size: {FONT_SIZES['xs']};
    text-transform: uppercase;
    letter-spacing: 0.1em;
}}
.le-sidebar-footer {{
    color: {COLORS['text_dim']};
    font-size: {FONT_SIZES['xs']};
    text-align: center;
    padding-top: {SPACING['sm']};
    border-top: 1px solid {COLORS['border']}30;
}}

/* ══════════════════════════════════════════════════════════
   STATUS BADGES (sidebar & inline)
   ══════════════════════════════════════════════════════════ */
.le-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: {BORDER_RADIUS['pill']};
    font-size: {FONT_SIZES['xs']};
    font-weight: 600;
    letter-spacing: 0.03em;
}}
.le-badge-success {{
    background: {COLORS['success']}18;
    color: {COLORS['success']};
    border: 1px solid {COLORS['success']}30;
}}
.le-badge-warning {{
    background: {COLORS['warning']}18;
    color: {COLORS['warning']};
    border: 1px solid {COLORS['warning']}30;
}}
.le-badge-info {{
    background: {COLORS['info']}18;
    color: {COLORS['info']};
    border: 1px solid {COLORS['info']}30;
}}
.le-badge-danger {{
    background: {COLORS['danger']}18;
    color: {COLORS['danger']};
    border: 1px solid {COLORS['danger']}30;
}}
.le-badge-primary {{
    background: {COLORS['primary']}18;
    color: {COLORS['primary']};
    border: 1px solid {COLORS['primary']}30;
}}

/* ══════════════════════════════════════════════════════════
   EMPTY STATE
   ══════════════════════════════════════════════════════════ */
.le-empty-state {{
    text-align: center;
    padding: {SPACING['xxl']} {SPACING['lg']};
    color: {COLORS['text_muted']};
}}
.le-empty-state .le-empty-icon {{
    font-size: 2.5rem;
    margin-bottom: {SPACING['sm']};
    opacity: 0.5;
}}
.le-empty-state .le-empty-msg {{
    font-size: {FONT_SIZES['body']};
}}
.le-empty-state .le-empty-hint {{
    font-size: {FONT_SIZES['sm']};
    color: {COLORS['text_dim']};
    margin-top: {SPACING['xs']};
}}

/* ══════════════════════════════════════════════════════════
   RESPONSIVE ADJUSTMENTS
   ══════════════════════════════════════════════════════════ */
@media (max-width: 768px) {{
    [data-testid="stMetricValue"] {{
        font-size: {FONT_SIZES['lg']};
    }}
    [data-testid="stMetricLabel"] {{
        font-size: {FONT_SIZES['xs']};
    }}
}}
"""


def inject_global_css():
    """Inject global CSS into the Streamlit app. Call once in app.py."""
    import streamlit as st
    st.markdown(f'<style>{get_global_css()}</style>', unsafe_allow_html=True)
