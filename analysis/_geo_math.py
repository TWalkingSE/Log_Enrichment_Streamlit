"""Geometria esférica compartilhada pelas análises (sem streamlit)."""
import numpy as np

EARTH_RADIUS_KM = 6371.0


def haversine_km(lat1, lon1, lat2, lon2):
    """Distância em km pela fórmula de Haversine.

    Aceita escalares ou arrays/Series (vetorizado com numpy). Havia quatro
    cópias inline desta fórmula em `analysis/geo.py` e `analysis/movement.py`;
    a ordem das operações é a mesma delas (diferença em graus convertida
    depois), para os resultados já publicados não mudarem nem no arredondamento.
    """
    dlat = np.radians(lat2 - lat1)
    dlon = np.radians(lon2 - lon1)
    a = np.sin(dlat / 2) ** 2 + np.cos(np.radians(lat1)) * np.cos(np.radians(lat2)) * np.sin(dlon / 2) ** 2
    return EARTH_RADIUS_KM * 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))
