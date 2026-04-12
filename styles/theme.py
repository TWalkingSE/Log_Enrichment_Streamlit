"""
Log Enrichment - Design System Tokens
Centralized color palette, typography, spacing, and Plotly theme.
Single source of truth for all visual styling across the application.
"""

import plotly.io as pio
import plotly.graph_objects as go


# ══════════════════════════════════════════════════════════════
# COLOR PALETTE
# ══════════════════════════════════════════════════════════════
COLORS = {
    # ── Brand ──
    'primary': '#818cf8',        # Indigo — buttons, accents, links
    'secondary': '#c084fc',      # Purple — secondary actions, highlights
    'accent': '#38bdf8',         # Cyan — special highlights, hover

    # ── Semantic ──
    'success': '#22c55e',        # Green — positive status, normal IPs
    'warning': '#f59e0b',        # Amber — caution, moderate risk
    'danger': '#ef4444',         # Red — errors, high risk, proxy/VPN
    'info': '#3b82f6',           # Blue — informational

    # ── IP Classification ──
    'hosting': '#f97316',        # Orange — hosting/datacenter
    'mobile': '#3b82f6',         # Blue — mobile connections
    'residential': '#22c55e',    # Green — residential/normal

    # ── Surfaces ──
    'bg': '#0e1117',             # App background (matches config.toml)
    'surface': '#1e1f33',        # Card/container background
    'surface_elevated': '#262840',  # Elevated cards, popovers
    'surface_card': '#1a1b2e',   # Subtle card variant

    # ── Borders ──
    'border': '#3d3d5c',         # Default border
    'border_subtle': '#2a2d3a',  # Subtle grid lines, dividers
    'border_hover': '#818cf8',   # Hover state border (primary)

    # ── Text ──
    'text': '#e2e8f0',           # Primary text
    'text_muted': '#94a3b8',     # Secondary/muted text
    'text_dim': '#475569',       # Disabled/very muted text

    # ── Gradients ──
    'gradient_start': '#0f0f1a', # Sidebar gradient start
    'gradient_end': '#1a1a2e',   # Sidebar gradient end

    # ── Effects ──
    'shadow': 'rgba(0, 0, 0, 0.3)',        # Default shadow
    'glow_primary': 'rgba(129, 140, 248, 0.15)',  # Primary glow
    'glow_danger': 'rgba(239, 68, 68, 0.15)',     # Danger glow
}

# Chart colorway (ordered for contrast)
COLORWAY = [
    COLORS['primary'], COLORS['success'], COLORS['warning'],
    COLORS['danger'], COLORS['secondary'], COLORS['info'],
    COLORS['hosting'],
]


# ══════════════════════════════════════════════════════════════
# TYPOGRAPHY
# ══════════════════════════════════════════════════════════════
FONT_SIZES = {
    'xs': '0.7rem',
    'sm': '0.8rem',
    'body': '0.9rem',
    'md': '1rem',
    'lg': '1.15rem',
    'xl': '1.4rem',
    'display': '2rem',
}


# ══════════════════════════════════════════════════════════════
# SPACING
# ══════════════════════════════════════════════════════════════
SPACING = {
    'xs': '0.25rem',
    'sm': '0.5rem',
    'md': '1rem',
    'lg': '1.5rem',
    'xl': '2rem',
    'xxl': '3rem',
}


# ══════════════════════════════════════════════════════════════
# BORDERS & RADIUS
# ══════════════════════════════════════════════════════════════
BORDER_RADIUS = {
    'sm': '6px',
    'md': '10px',
    'lg': '16px',
    'pill': '9999px',
}


# ══════════════════════════════════════════════════════════════
# TRANSITIONS
# ══════════════════════════════════════════════════════════════
TRANSITIONS = {
    'fast': 'all 0.15s ease',
    'normal': 'all 0.2s ease',
    'slow': 'all 0.35s ease',
}


# ══════════════════════════════════════════════════════════════
# CSS VARIABLES GENERATOR
# ══════════════════════════════════════════════════════════════
def get_css_vars():
    """Generate CSS :root variables from design tokens."""
    lines = [':root {']
    for key, val in COLORS.items():
        css_name = key.replace('_', '-')
        lines.append(f'  --le-{css_name}: {val};')
    for key, val in FONT_SIZES.items():
        lines.append(f'  --le-font-{key}: {val};')
    for key, val in SPACING.items():
        lines.append(f'  --le-space-{key}: {val};')
    for key, val in BORDER_RADIUS.items():
        lines.append(f'  --le-radius-{key}: {val};')
    lines.append('}')
    return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════
# PLOTLY THEME
# ══════════════════════════════════════════════════════════════
def register_plotly_theme():
    """Register custom 'le_dark' Plotly template matching the app theme."""
    le_template = go.layout.Template()
    le_template.layout = go.Layout(
        font=dict(color=COLORS['text'], family='sans-serif'),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        colorway=COLORWAY,
        xaxis=dict(
            gridcolor=COLORS['border_subtle'], gridwidth=1,
            zerolinecolor=COLORS['border_subtle'],
            linecolor=COLORS['border'], tickfont=dict(color=COLORS['text_muted']),
        ),
        yaxis=dict(
            gridcolor=COLORS['border_subtle'], gridwidth=1,
            zerolinecolor=COLORS['border_subtle'],
            linecolor=COLORS['border'], tickfont=dict(color=COLORS['text_muted']),
        ),
        legend=dict(
            orientation='h', yanchor='bottom', y=-0.2,
            xanchor='center', x=0.5, font=dict(color=COLORS['text_muted'], size=11),
        ),
        margin=dict(l=0, r=20, t=10, b=10),
        hoverlabel=dict(
            bgcolor=COLORS['surface'], bordercolor=COLORS['primary'],
            font=dict(color=COLORS['text']),
        ),
    )
    pio.templates['le_dark'] = le_template
    pio.templates.default = 'le_dark'
