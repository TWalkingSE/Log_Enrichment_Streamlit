import re

import pandas as pd


PROVIDER_ALIASES = {
    'Claro': ['claro s.a', 'claro s/a', 'claro nxt', 'net servicos', 'net serviços',
              'net telecomunicacoes', 'embratel', 'claro nxt telecomunica'],
    'Vivo': ['telefonica', 'telefônica', 'global village', 'global vilage', 'gvt',
             'terra networks', 'vivo s.a', 'vivo s/a'],
    'TIM': ['tim s.a', 'tim s/a', 'tim celular', 'tim live', 'intelig telecomunicacoes'],
    'Oi': ['oi movel', 'oi móvel', 'telemar', 'oi s.a', 'brasil telecom'],
    'Algar': ['algar telecom', 'ctbc telecom'],
}


def normalizar_provedor(nome):
    """
    Normaliza nome de provedor para agrupar variantes da mesma empresa.
    Ex: 'Claro S.A.' → 'Claro', 'TELEFÔNICA BRASIL S.A.' → 'Vivo'
    Retorna o nome normalizado ou o original se não encontrar match.
    """
    if not isinstance(nome, str) or not nome.strip():
        return nome
    nome_lower = nome.strip().lower()
    for grupo, aliases in PROVIDER_ALIASES.items():
        if re.search(r'\b' + re.escape(grupo.lower()) + r'\b', nome_lower):
            return grupo
        for alias in aliases:
            if re.search(r'\b' + re.escape(alias), nome_lower):
                return grupo
    return nome


def normalizar_provedor_df(df, col='Ip_Dono'):
    """Aplica normalização de provedores a um DataFrame inteiro."""
    if col not in df.columns:
        return df
    df = df.copy()
    df[col] = df[col].apply(normalizar_provedor)
    return df
