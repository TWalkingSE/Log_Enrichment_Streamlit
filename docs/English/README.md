# Log Enrichment v5.2 Pro

> 🇧🇷 [Português](../Portuguese/README.md) · 🇪🇸 [Español](../Spanish/README.md) · Full PT docs: [root README](../../README.md)

Professional tool for extraction, forensic analysis, and enrichment of IP addresses in access logs and telematic interception (IP-API, VirusTotal, AbuseIPDB, Shodan).

## Description

Streamlit multipage app that extracts IPs from many log formats, enriches via **batch API** (up to 100 IPs/request), and produces tables, maps, graphs, executive summaries, IOC/STIX exports, and forensic audit trails.

## Sensitive data

May process IPs, ports, timestamps, geo, ASN/provider and related metadata. With API keys enabled, data is sent to third parties. Prefer controlled environments, minimize external queries, and use **air-gapped / signed cache** when offline is required. See [SECURITY.md](../../SECURITY.md) and [DEPLOY.md](../DEPLOY.md).

## Features (audit Lotes 1–8)

### Enrichment
- 11 input formats (Generic, Meta, WhatsApp, Google, Discord PDF, TikTok PDF, HTML, CSV/Excel, …)
- Batch IP-API, async rDNS, format detection, preview, incremental dedup
- **Cooperative cancel** between API batches (multi-tab)
- **Headless worker**: `python scripts/enrich_worker.py --input … --output …`
- **Air-gapped**: `AIR_GAPPED=true` (cache-only)
- **HMAC-signed cache**: `CACHE_HMAC_SECRET` / `SIGN_IP_CACHE` (export/import in Settings)
- Session restore: `data/sessions/` (parquet/pickle)
- Application layer: `application.enrich_use_case` + `enrich_service`
- Modular `analysis/` package
- Retention: `scripts/retention_cleanup.py` + `RETENTION_*`
- **SIEM export**: IOC txt/csv + **STIX 2.1** on Results (+ ZIP)
- **A/B period comparison** page under Analysis
- Audit trail hash chain (`prev_hash`) + optional `AUDIT_HMAC_SECRET`
- i18n: pt / en / es
- Security: CSV injection sanitization, HTML escape (XSS), path sandbox under `output/`, rotating logs

### Advanced analysis (8 pages)
Overview · Risk & Threats · Temporal · **A/B Compare** · Geo · Correlation · Behavior · Operational

### Export
CSV (sanitized), JSON, colored Excel, ZIP (includes IOC/STIX), KML, GeoJSON, HTML/PDF report

### Settings tabs
API & Cache (air-gap, signed cache) · AI · Branding · Audit Trail

## Install

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

### Key environment variables

| Variable | Purpose |
|----------|---------|
| `AUTH_PASSWORD_HASH` | Streamlit auth (Argon2 recommended) |
| `IPAPI_KEY` | Paid IP-API (HTTPS) |
| `AUDIT_HMAC_SECRET` | Optional audit HMAC |
| `CACHE_HMAC_SECRET` | Signed cache HMAC |
| `SIGN_IP_CACHE` | Write signed `ip_cache.json` |
| `AIR_GAPPED` | Cache-only enrichment |
| `RETENTION_*` | Retention policy |
| VT / AbuseIPDB / Shodan keys | Optional reputation |

### Headless worker & maintenance

```bash
python scripts/enrich_worker.py --input logs.txt --output output/csv/out.csv
python scripts/enrich_worker.py --input logs.txt --air-gapped
python scripts/retention_cleanup.py
python scripts/gen_auth_password_hash.py
python -m pytest tests -q
```

## Project structure (high level)

```
app.py, pages_app/, analysis/, enrich_service.py, export_ioc.py
application/, domain/, infrastructure/
helpers/ (geo, job_control, period_compare, signed_cache, retention, persistence, …)
scripts/ (enrich_worker, retention_cleanup, gen_auth_password_hash)
locales/ (pt, en, es)
docs/ (DEPLOY, AUDITORIA_TECNICA, translations)
tests/
```

## Tests

```bash
python -m pytest tests -q
```

~196 automated tests (security, cache, STIX, cancel, A/B, API client mocks, …).

## Docs

- Deploy: [DEPLOY.md](../DEPLOY.md)
- Technical audit: [AUDITORIA_TECNICA.md](../AUDITORIA_TECNICA.md)
- Security: [SECURITY.md](../../SECURITY.md)
- Full Portuguese product README: [../../README.md](../../README.md)

## License

MIT — see `LICENSE`.

## Author

**Developed by TWalking with AI assistance**
