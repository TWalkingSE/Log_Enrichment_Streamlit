# Log Enrichment v5.2 Pro

> 🇧🇷 [Português](../Portuguese/README.md) · 🇺🇸 [English](../English/README.md) · Docs PT completas: [README raíz](../../README.md)

Herramienta profesional para extracción, análisis forense y enriquecimiento de IPs en logs de acceso e interceptación telemática (IP-API, VirusTotal, AbuseIPDB, Shodan).

## Descripción

Aplicación Streamlit multipágina que extrae IPs de múltiples formatos, enriquece vía **API batch** (hasta 100 IPs/request) y genera tablas, mapas, grafos, resúmenes ejecutivos, export IOC/STIX y audit trail forense.

## Datos sensibles

Puede procesar IPs, puertos, timestamps, geo, ASN/proveedor y metadatos. Con API keys, parte de los datos se envía a terceros. Prefiera entornos controlados y use **air-gapped / caché firmado** cuando se requiera offline. Ver [SECURITY.md](../../SECURITY.md) y [DEPLOY.md](../DEPLOY.md).

## Funcionalidades (auditoría Lotes 1–8)

### Enriquecimiento
- 11 formatos de entrada (incluido TikTok PDF)
- Batch IP-API, rDNS async, detección de formato, vista previa, dedup incremental
- **Cancelación cooperativa** entre lotes (multi-pestaña)
- **Worker headless**: `python scripts/enrich_worker.py`
- **Air-gapped**: `AIR_GAPPED=true` (solo caché)
- **Caché firmado HMAC**: `CACHE_HMAC_SECRET` / `SIGN_IP_CACHE`
- Persistencia de sesión: `data/sessions/`
- Capa de aplicación: `application.enrich_use_case` + `enrich_service`
- Paquete modular `analysis/`
- Retención: `scripts/retention_cleanup.py`
- **Export SIEM**: IOC + **STIX 2.1**
- **Comparación A/B** de períodos
- Audit trail con cadena de hash + HMAC opcional
- i18n: pt / en / es
- Seguridad: sanitización CSV, escape XSS, sandbox de paths, logs rotativos

### Análisis avanzado (8 páginas)
Visión general · Riesgo · Temporal · **Comparación A/B** · Geo · Correlación · Comportamiento · Operacional

### Exportación
CSV sanitizado, JSON, Excel, ZIP (con IOC/STIX), KML, GeoJSON, informe HTML/PDF

## Instalación

```bash
python -m venv venv
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

Variables clave: `AUTH_PASSWORD_HASH`, `IPAPI_KEY`, `AUDIT_HMAC_SECRET`, `CACHE_HMAC_SECRET`, `SIGN_IP_CACHE`, `AIR_GAPPED`, `RETENTION_*`.

```bash
python scripts/enrich_worker.py --input logs.txt --output output/csv/out.csv --air-gapped
python scripts/retention_cleanup.py
python -m pytest tests -q
```

## Tests

~196 tests automatizados.

## Documentación

- [DEPLOY.md](../DEPLOY.md) · [AUDITORIA_TECNICA.md](../AUDITORIA_TECNICA.md) · [SECURITY.md](../../SECURITY.md) · [README PT completo](../../README.md)

## Licencia

MIT — ver `LICENSE`.

## Autor

**Desarrollado por TWalking con ayuda de AI**
