"""analysis.export_kml — split from analysis monolith."""
import pandas as pd
import numpy as np
import os
import json
import shutil
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def export_kml_animated(df, ip_col='Ip', lat_col='Ip_Lat', lon_col='Ip_Lon', date_col='Data'):
    """
    4.3 — Export KML com timestamps para animação temporal no Google Earth Pro.
    Inclui rota temporal (LineString) conectando pontos em ordem cronológica.
    """
    import simplekml

    kml = simplekml.Kml(name='Log Enrichment - Rota Temporal')

    df_kml = df.copy()
    df_kml[lat_col] = pd.to_numeric(df_kml[lat_col], errors='coerce')
    df_kml[lon_col] = pd.to_numeric(df_kml[lon_col], errors='coerce')
    df_kml['_dt'] = pd.to_datetime(df_kml.get(date_col, pd.Series(dtype='object')),
                                    format='mixed', errors='coerce')
    df_kml = df_kml.dropna(subset=[lat_col, lon_col, '_dt'])
    df_kml = df_kml[(df_kml[lat_col] != 0) | (df_kml[lon_col] != 0)]
    df_kml = df_kml.sort_values('_dt')

    if df_kml.empty:
        return kml.kml()

    # Folder: Pontos com timestamp
    folder = kml.newfolder(name='IPs Geolocalizados')
    coords_for_line = []

    for _, row in df_kml.iterrows():
        ip = str(row.get(ip_col, 'N/A'))
        lat, lon = row[lat_col], row[lon_col]
        dt = row['_dt']

        pnt = folder.newpoint(name=ip)
        pnt.coords = [(lon, lat)]
        pnt.timestamp.when = dt.strftime('%Y-%m-%dT%H:%M:%SZ')

        desc_parts = [f"IP: {ip}"]
        if pd.notna(row.get('Ip_Dono')):
            desc_parts.append(f"Provedor: {row['Ip_Dono']}")
        if pd.notna(row.get('Ip_Cidade')):
            desc_parts.append(f"Cidade: {row['Ip_Cidade']}")
        desc_parts.append(f"Data: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        pnt.description = '\n'.join(desc_parts)

        is_proxy = str(row.get('Ip_Proxy', '')).lower() == 'true'
        is_hosting = str(row.get('Ip_Hospedagem', '')).lower() == 'true'
        if is_proxy:
            pnt.style.iconstyle.color = simplekml.Color.red
        elif is_hosting:
            pnt.style.iconstyle.color = simplekml.Color.orange
        else:
            pnt.style.iconstyle.color = simplekml.Color.green

        coords_for_line.append((lon, lat, 0))

    # Rota temporal (LineString)
    if len(coords_for_line) >= 2:
        route = kml.newlinestring(name='Rota Temporal')
        route.coords = coords_for_line
        route.style.linestyle.color = simplekml.Color.changealphaint(180, simplekml.Color.cyan)
        route.style.linestyle.width = 3

    return kml.kml()


def export_kml(df, ip_col='Ip', lat_col='Ip_Lat', lon_col='Ip_Lon'):
    """
    Export IP locations as KML for Google Earth.

    Returns KML content as string.
    """
    import simplekml

    kml = simplekml.Kml(name='Log Enrichment - IP Locations')

    df_kml = df.copy()
    df_kml[lat_col] = pd.to_numeric(df_kml[lat_col], errors='coerce')
    df_kml[lon_col] = pd.to_numeric(df_kml[lon_col], errors='coerce')
    df_kml = df_kml.dropna(subset=[lat_col, lon_col])
    df_kml = df_kml[(df_kml[lat_col] != 0) | (df_kml[lon_col] != 0)]

    for _, row in df_kml.iterrows():
        ip = row.get(ip_col, 'N/A')
        pnt = kml.newpoint(name=str(ip))
        pnt.coords = [(row[lon_col], row[lat_col])]

        desc_parts = []
        if 'Ip_Dono' in row and pd.notna(row.get('Ip_Dono')):
            desc_parts.append(f"Provedor: {row['Ip_Dono']}")
        if 'Ip_Cidade' in row and pd.notna(row.get('Ip_Cidade')):
            desc_parts.append(f"Cidade: {row['Ip_Cidade']}")
        if 'Data' in row and pd.notna(row.get('Data')):
            desc_parts.append(f"Data: {row['Data']}")

        pnt.description = '\n'.join(desc_parts)

        # Color by type
        is_proxy = row.get('Ip_Proxy', False)
        is_hosting = row.get('Ip_Hospedagem', False)
        is_mobile = row.get('Ip_Movel', False)

        if is_proxy:
            pnt.style.iconstyle.color = simplekml.Color.red
        elif is_hosting:
            pnt.style.iconstyle.color = simplekml.Color.orange
        elif is_mobile:
            pnt.style.iconstyle.color = simplekml.Color.blue
        else:
            pnt.style.iconstyle.color = simplekml.Color.green

    return kml.kml()


