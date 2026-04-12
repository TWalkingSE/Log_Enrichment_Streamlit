"""
Log Enrichment - Internationalization (i18n) Module
Provides translation support for Portuguese (pt), English (en), and Spanish (es).
"""

import json
import os
import streamlit as st

SUPPORTED_LANGUAGES = {
    'pt': '🇧🇷 Português',
    'en': '🇺🇸 English',
    'es': '🇪🇸 Español',
}

DEFAULT_LANGUAGE = 'pt'

_LOCALES_DIR = os.path.join(os.path.dirname(__file__), 'locales')
_translations_cache = {}


def _load_locale(lang):
    """Load a locale JSON file and cache it."""
    if lang in _translations_cache:
        return _translations_cache[lang]
    filepath = os.path.join(_LOCALES_DIR, f'{lang}.json')
    if not os.path.exists(filepath):
        _translations_cache[lang] = {}
        return {}
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    _translations_cache[lang] = data
    return data


def get_lang():
    """Return the current language from session state."""
    return st.session_state.get('lang', DEFAULT_LANGUAGE)


def set_lang(lang):
    """Set the current language in session state."""
    if lang in SUPPORTED_LANGUAGES:
        st.session_state['lang'] = lang


def t(key, **kwargs):
    """
    Translate a key using the current language.

    Supports nested keys with dot notation: t('nav.data')
    Supports interpolation: t('entrada.records_found', count=10)
    Falls back to Portuguese if key not found in current language.
    Falls back to the key itself if not found in any language.
    """
    lang = get_lang()
    translations = _load_locale(lang)

    # Navigate nested keys
    value = _resolve_key(translations, key)

    # Fallback to Portuguese
    if value is None and lang != DEFAULT_LANGUAGE:
        pt_translations = _load_locale(DEFAULT_LANGUAGE)
        value = _resolve_key(pt_translations, key)

    # Fallback to key itself
    if value is None:
        return key

    # Interpolation
    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError):
            return value

    return value


def _resolve_key(data, key):
    """Resolve a dotted key path in a nested dict."""
    parts = key.split('.')
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current if isinstance(current, str) else None


def reload_translations():
    """Clear the translation cache to force reload from disk."""
    _translations_cache.clear()
