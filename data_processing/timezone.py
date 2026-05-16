import os
from datetime import timedelta

# Fuso horário configurável via variável de ambiente (padrão: -3)
TZ_OFFSET_HOURS = int(os.getenv('TZ_OFFSET_HOURS', '-3'))


def _format_tz_label():
    """Formata o label do fuso horário baseado no offset configurado"""
    sign = '+' if TZ_OFFSET_HOURS >= 0 else '-'
    hours = abs(TZ_OFFSET_HOURS)
    return f'GMT {sign}{hours:02d}00'


TZ_LABEL = os.getenv('TZ_LABEL', _format_tz_label())


def convert_utc_to_local(dt_utc):
    """Converte datetime UTC para o fuso horário local configurado"""
    return dt_utc + timedelta(hours=TZ_OFFSET_HOURS)


def format_iso_date(dt_local):
    """Formata datetime local em ISO 8601 com offset do fuso configurado"""
    sign = '+' if TZ_OFFSET_HOURS >= 0 else '-'
    hours = abs(TZ_OFFSET_HOURS)
    return dt_local.strftime(f'%Y-%m-%dT%H:%M:%S{sign}{hours:02d}:00')


def get_periodo(hora):
    """Retorna período do dia baseado na hora"""
    return '☀️ Diurno' if 6 <= hora < 18 else '🌙 Noturno'


def normalizar_periodo(periodo_str):
    """Remove emojis e normaliza string de período para comparação segura."""
    if not isinstance(periodo_str, str):
        return ''
    p = periodo_str.strip().lower()
    if 'noturno' in p:
        return 'noturno'
    if 'diurno' in p:
        return 'diurno'
    return p


def is_noturno(periodo_str):
    """Verifica se o período é noturno (funciona com ou sem emoji)."""
    return normalizar_periodo(periodo_str) == 'noturno'


def is_diurno(periodo_str):
    """Verifica se o período é diurno (funciona com ou sem emoji)."""
    return normalizar_periodo(periodo_str) == 'diurno'


def periodo_matches(p1, p2):
    """Compara dois períodos de forma segura, ignorando emojis."""
    return normalizar_periodo(p1) == normalizar_periodo(p2)
