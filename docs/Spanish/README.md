# Log Enrichment v5.2 Pro

> 🇧🇷 [Português](../Portuguese/README.md) · 🇺🇸 [English](../English/README.md)

Herramienta profesional para extracción, análisis forense y enriquecimiento de direcciones IP en logs de acceso e interceptación telemática, utilizando múltiples fuentes de inteligencia (IP-API, VirusTotal, AbuseIPDB).

## 📋 Descripción

**Log Enrichment** es una aplicación web (Streamlit) que automatiza el análisis de logs de acceso e interceptación telemática de WhatsApp. Extrae direcciones IP de diversos formatos, consulta APIs de geolocalización y reputación vía **batch endpoint** (hasta 100 IPs por solicitud), y genera informes completos con gráficos, mapas, grafos interactivos y resumen ejecutivo.

## ⚠️ Alerta de Datos Sensibles

> **Atención:** esta herramienta puede procesar **direcciones IP, puertos lógicos, horarios de conexión, ubicación aproximada, ASN/proveedor y metadatos correlatos** obtenidos de registros de plataformas y servicios como **Google, WhatsApp, Meta, Discord** y proveedores de acceso. En muchos contextos, estos datos pueden ser **sensibles, confidenciales o legalmente protegidos**.
>
> Cuando activa consultas de enriquecimiento o reputación con **API Key**, parte de estos datos se envía a **servicios externos de terceros**, como **IP-API, VirusTotal, AbuseIPDB y Shodan**.
>
> **Antes de procesar datos reales:** verifique su base legal, política institucional, cadena de custodia y necesidad operacional.

## ✨ Funcionalidades

### Enriquecimiento de Logs de Acceso
- **10 Formatos de Entrada**: Genérico, Meta Platforms, WhatsApp, Google, Preservation Google, Discord (PDF), CSV/Excel, HTML WhatsApp, HTML Meta Platforms, HTML Google
- **API Batch**: Consulta hasta 100 IPs por solicitud vía POST `/batch`
- **rDNS Asíncrono**: Resolución DNS inversa en paralelo
- **Detección Automática de Formato**: Identifica el tipo de log automáticamente
- **Vista Previa**: Visualice los IPs detectados antes de procesar

### Panel de Estadísticas
- Cards resumen, tendencias de actividad, spotlight por proveedor, mix de conexión, heatmap temporal, top IPs recurrentes

### 🗺️ Mapa de Geolocalización (Leaflet / Folium)
Cinco modos de visualización: Marcadores, Clusters, Heatmap, Ruta Temporal, Visión Investigativa

### Informe PDF
- Resumen general, top proveedores, anomalías, IPs recurrentes, gráficos incrustados

### Análisis Avanzado (7 páginas dedicadas)
- **Visión General**: KPIs, scores de riesgo, resumen ejecutivo
- **Riesgo y Amenazas**: Score de riesgo, VirusTotal, AbuseIPDB, Shodan, Tor exit nodes
- **Patrones Temporales**: Análisis horario, silencio digital, validación de huso horario
- **Geolocalización**: Historial geo, sub-redes, patrones de vida (clustering DBSCAN)
- **Correlación**: Correlación cruzada, WiFi compartido, relay chains
- **Comportamiento**: Detección heurística VPN/proxy, confianza de IP, números descartables
- **Operacional**: Análisis investigativo, comparación temporal, salud de datos

### 🌐 Soporte Multilingüe
- Interfaz disponible en **Portugués**, **Inglés** y **Español**
- Selector de idioma en la barra lateral para cambio en tiempo real
- Documentación disponible en los tres idiomas en `docs/`

## 🛠️ Instalación

### Prerrequisitos
- Python 3.10+ (3.11 recomendado)
- pip

### Pasos

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

### Ejecutar

```bash
streamlit run app.py
```

La aplicación se abrirá automáticamente en `http://localhost:8501`.

## 🧪 Tests

```bash
python -m pytest tests -v
```

**167+ tests automatizados** organizados en `tests/` por dominio.

## 📜 Licencia

Este proyecto se distribuye bajo la licencia MIT. Vea el archivo `LICENSE` para el texto completo.

## 👨‍💻 Autor

**Desarrollado por TWalking con ayuda de AI**
