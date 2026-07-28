# Deploy — Log Enrichment Streamlit

## Requisitos

- Python 3.11+
- Dependências: `pip install -r requirements.txt`
- (Opcional) Ollama local para assistente AI
- (Recomendado) reverse proxy HTTPS (nginx/Caddy)

## Variáveis de ambiente

Copie `.env.example` para `.env`:

| Variável | Uso |
|----------|-----|
| `APP_PASSWORD_HASH` | Hash Argon2/bcrypt da senha de acesso (recomendado) |
| `APP_PASSWORD` | Senha em claro — **evitar em produção** |
| `IPAPI_KEY` | Chave pro IP-API (HTTPS, sem rate limit free) |
| `VIRUSTOTAL_API_KEY` | VT opcional |
| `ABUSEIPDB_API_KEY` | AbuseIPDB opcional |
| `SHODAN_API_KEY` | Shodan opcional |
| `AUDIT_HMAC_SECRET` | HMAC-SHA256 opcional sobre `event_hash` do audit trail |
| `AIR_GAPPED` | `true` = enriquecimento só com cache local (sem HTTP IP-API) |
| `CACHE_HMAC_SECRET` | HMAC do pacote de cache assinado (fallback: `AUDIT_HMAC_SECRET`) |
| `SIGN_IP_CACHE` | `true` = grava `ip_cache.json` como envelope assinado |
| `RETENTION_*` | Política de retenção (audit/sessions/cache); ver `.env.example` |
| Persistência | `data/sessions/*.parquet` (ou `.pkl`) restaura `df_resultado` |
| `pyarrow` | Necessário para parquet; sem ele usa pickle |

Sem hash/senha configurados, a autenticação Streamlit fica desabilitada — **não exponha a porta publicamente**.

## Execução local

```bash
streamlit run app.py --server.port 8501
```

## Produção (checklist)

1. **Auth obrigatória** — defina `APP_PASSWORD_HASH` (Argon2).
2. **HTTPS** — termine TLS no reverse proxy; não exponha HTTP da Streamlit na internet.
3. **IPAPI_KEY** — evita free tier em cleartext HTTP.
4. **Firewall** — permita apenas o proxy → `127.0.0.1:8501`.
5. **Logs** — `logs/` com `RotatingFileHandler`; audit trail em `logs/audit_trail.jsonl`.
6. **Persistência** — monte volume para `ip_cache.json`, `output/`, `logs/`.
7. **Tor list** — agende `python tor_updater.py --skip-if-fresh` (6–12h).
8. **Retenção** — `python scripts/retention_cleanup.py` (ou `RETENTION_ON_STARTUP=true`).
9. **Air-gapped** — `AIR_GAPPED=true` + `ip_cache.json` pré-populado em rede isolada.
10. **Worker headless** — `python scripts/enrich_worker.py --input file --output out.csv` (scale-out).

### Exemplo nginx

```nginx
server {
    listen 443 ssl;
    server_name log-enrichment.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
}
```

## Cache assinado (air-gap / transferência offline)

1. Defina `CACHE_HMAC_SECRET` (ou reutilize `AUDIT_HMAC_SECRET`).
2. Em **Configurações → API & Cache**, exporte o cache assinado, ou ative `SIGN_IP_CACHE=true` para gravar envelope em `ip_cache.json`.
3. No host isolado: importe o JSON assinado (mesma secret) ou copie o arquivo e use `AIR_GAPPED=true`.

Assinatura inválida → cache **rejeitado** no load (`api_client`).

## Cancelamento de jobs

Durante processamento longo na UI, abra outra aba da app e clique em **Solicitar cancelamento**. O flag em `data/jobs/cancel.flag` interrompe entre lotes de API (cooperativo, não hard-kill mid-request).

## Verificação pós-deploy

```bash
python -m pytest tests -q
python -m ruff check enrich_service.py validators.py helpers api_client.py analysis
```

Documentação relacionada: [`AUDITORIA_TECNICA.md`](AUDITORIA_TECNICA.md) · [`../SECURITY.md`](../SECURITY.md) · [`../README.md`](../README.md)
