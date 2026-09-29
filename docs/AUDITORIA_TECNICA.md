# Auditoria Técnica — Log Enrichment Streamlit

Relatório gerado na implementação do plano de auditoria (segurança, bugs, performance, arquitetura).

## 1. Escopo e método

- Revisão estática de módulos raiz, `pages_app/`, `helpers/`, `components/`, `validators`, `api_client`, `audit_logger`, pipelines e testes.
- Priorização por severidade × impacto operacional (dados sensíveis / forense).
- Correções Lote 1 (segurança/bugs) e Lote 2 (higiene/pipeline) aplicadas no código.

## 2. Achados e status

### Crítico / Alto

| ID | Achado | Causa | Impacto | Solução | Status |
|----|--------|-------|---------|---------|--------|
| S1 | CSV injection nos exports | `sanitize_csv_value` existia mas não era aplicado em `to_csv` | Fórmulas maliciosas em Excel | `sanitize_dataframe_for_csv` + uso em pipeline e downloads | **Corrigido** |
| S2 | XSS em popups de mapa | Campos API/usuário interpolados em HTML | Execução de script no browser do analista | `html.escape` em `helpers/geo.py` | **Corrigido** |
| S3 | XSS em sparklines | `unsafe_allow_html` com células cruas | Idem | Escape em `components/visualizations.py` | **Corrigido** |
| S4 | Path de saída livre | `st.text_input` sem sandbox | Escrita fora do projeto | `safe_output_path` em entrada/interceptação | **Corrigido** |
| S5 | Audit trail sem cadeia | Só `event_hash` isolado | Inserção/remoção de eventos difícil de detectar | `prev_hash` + `verify_audit_integrity` | **Corrigido** |
| S6 | Auth opcional se env vazio | Design Streamlit | Deploy exposto sem senha | Documentado em `.env.example` / SECURITY; não forçado breaking | **Documentado** |

### Médio

| ID | Achado | Solução | Status |
|----|--------|---------|--------|
| M1 | `fpdf2`, `kaleido` sem uso | Removidos de `requirements.txt` | **Corrigido** |
| M2 | `asyncio.new_event_loop` ad-hoc | `run_async` em `helpers/shared.py` | **Corrigido** |
| M3 | Dedup incremental só Ip+Data | `_incremental_dedup_columns` (Porta/User_ID/User_Agent) | **Corrigido** |
| M4 | Free IP-API em HTTP | Warning no logger do `IPAPIClient` | **Corrigido** |
| M5 | Logs diários sem rotação | `RotatingFileHandler` 5MB×7 | **Corrigido** |
| M6 | `detect_anomalies` via iterrows | Filtro vetorizado + itertuples limitado | **Corrigido** |
| M7 | KPIs overview recalculados a cada rerun | `@st.cache_data` | **Corrigido** |

### Baixo / dívida (roadmap) — status atualizado

| Item | Status |
|------|--------|
| Monólito `analysis.py` | **Feito** — pacote `analysis/` |
| i18n incompleto | **Feito** (principal + residual Lotes 5–8) |
| Ruff F401 global | **Parcial** — per-file-ignores |
| Pipelines enrich duplicados | **Feito** — `enrich_service` + use-case |
| Cache temporal/geo | **Feito** — `@st.cache_data` |
| Mocks HTTP `api_client` | **Parcial** — `tests/test_api_client.py` |
| Jinja2 `_safe` no HTML | Residual menor (não prioritário) |
| TAXII push server-side | Fora de escopo / opcional |

## 3. Correções aplicadas (arquivos)

### Lote 1 — segurança
- `validators.py` — `sanitize_dataframe_for_csv`, `safe_output_path`
- `file_handler.py` — sanitize CSV + dedup rico
- `pages_app/resultados.py` — sanitize download/ZIP
- `pages_app/entrada.py` — path sandbox
- `pages_app/interceptacao.py` — path sandbox, `run_async`, sanitize CSV
- `interception_parser.py` — sanitize CSV
- `helpers/geo.py` — escape HTML
- `components/visualizations.py` — escape sparklines
- `audit_logger.py` — hash chain
- `helpers/shared.py` — `run_async`, anomalies
- `api_client.py` — warning HTTP free tier
- `pages_app/analise/risco.py` — `run_async`

### Lote 2 — higiene
- `requirements.txt` — sem fpdf2/kaleido
- `app.py` — RotatingFileHandler
- `pages_app/analise/overview.py` — cache KPIs
- `.env.example` — Argon2 recomendado
- `tests/test_security.py` — regressões

### Lote 3 — arquitetura / i18n / cache
- `enrich_service.py` — serviço compartilhado `enrich_ips` / `enrich_dataframe`
- `file_handler.py` / `interception_parser.py` / `interceptacao.py` — usam o serviço
- `pages_app/analise/temporal.py` / `geo.py` / `risco.py` — `@st.cache_data` + i18n parcial
- `pages_app/interceptacao.py` — i18n UI
- `pyproject.toml` — F401 com per-file-ignores; mypy inclui `enrich_service`
- testes `TestEnrichService`

### Lote 4 — modularização analysis + deploy
- Pacote `analysis/` no lugar do monólito `analysis.py` (~2k linhas)
- `pages_app/configuracoes.py` — i18n API/Tor/audit/about
- `tests/test_api_client.py` — validação IP, cache, consultar com mock HTTP
- `docs/DEPLOY.md` — auth, HTTPS, proxy, checklist produção

### Lote 5 — i18n residual + HMAC + persistência
- `configuracoes` AI + Branding 100% i18n (pt/en/es)
- Fix: verificação de audit trail usa dict (`invalid`/`chain_breaks`), não truthiness
- `AUDIT_HMAC_SECRET` → `event_hmac` opcional em `audit_logger`
- `helpers/persistence.py` — parquet (pyarrow) com fallback pickle; restore no `app.py`
- `pyarrow` em `requirements.txt`; testes HMAC + persistence

### Lote 6 — air-gap, retenção, camadas, worker
- `AIR_GAPPED` + toggle em configurações; `IPAPIClient` cache-only
- `helpers/retention.py` + `scripts/retention_cleanup.py` (audit/sessions/cache)
- ~~Esqueleto `domain/` · `application/` · `infrastructure/`~~ — removido depois; nunca
  foi usado pelo pipeline
- `scripts/enrich_worker.py` — processamento headless (avaliação de scale-out)

### Lote 7 — STIX/IOC + cancelamento cooperativo
- `export_ioc.py` — lista IOC, CSV contextual, bundle STIX 2.1
- Downloads na página Resultados (+ inclusão no ZIP)
- `helpers/job_control.py` — cancel entre lotes (flag file multi-aba)
- Check de cancel em `api_client.consultar_batch`

### Lote 8 — residual de evolução
- Comparação A/B de períodos (`helpers/period_compare.py` + página Análise)
- Cache assinado HMAC (`helpers/signed_cache.py`, export/import em Configurações)
- `SIGN_IP_CACHE` / `CACHE_HMAC_SECRET` no `.env.example`
- ~~Pipeline principal via `application.enrich_use_case.enrich_ip_list`~~ — o pipeline
  usa `enrich_service` diretamente
- i18n residual (cancel, IOC/STIX, comparacao, signed cache) pt/en/es

### Lote 9 — prova errada, custódia e limpeza (2026-09)

Achados que não apareciam nos testes (a suíte estava verde) e alteravam o conteúdo
do laudo. Regressões em `tests/test_evidencia.py`.

| ID | Achado | Status |
|----|--------|--------|
| P1 | `cache_key` sem filtros nem identidade de sessão: export de um filtro servido para outro de mesmo tamanho; sessões compartilhavam cache | **Corrigido** |
| P2 | Filtro "Todos" quebrado em EN/ES (tabela vazia) | **Corrigido** |
| P3 | Análise de IA recebia frame por IP (`calculate_risk_scores`) em vez de registros | **Corrigido** |
| P4 | Faixas de risco 50/20 na página e 70/40 no relatório | **Corrigido** (70/40 em `analysis.risk`) |
| P5 | `detect_vpn_timing` com `str(x).lower() != 'true'` | **Corrigido** |
| P6 | Datas `NN/NN/AAAA` lidas como mês/dia; formato decidido pela 1ª linha | **Corrigido** (`infer_dayfirst`) |
| P7 | CSV de interceptação, investigativa e IOC sem sanitização | **Corrigido** |
| P8 | Páginas liam `ip_cache.json` sem envelope/TTL e com caminhos diferentes | **Corrigido** (`read_ip_cache`, `IP_CACHE_PATH`) |
| P9 | 403 da chave paga rebaixava para HTTP em claro no meio do job | **Corrigido** (`InvalidApiKeyError`) |
| P10 | ZIP: `RECORDS.HTML`/`.ZIP` ignorados; entradas puladas só no log | **Corrigido** |
| C1 | Retenção reescrevia o audit trail → quebra de cadeia | **Corrigido** (arquivar + `RETENTION_CHECKPOINT`) |
| C2 | Verificação limitada a 10 mil eventos; linha corrompida pulada | **Corrigido** |
| C3 | Retenção destruía cache assinado; rodava a cada sessão | **Corrigido** |
| C4 | sha256 divergente da sessão restaurada só no log | **Corrigido** |
| S7 | Relatório HTML sem autoescape; popups do mapa sem escape | **Corrigido** |
| S8 | Bloqueio de login por sessão (nova sessão zerava) | **Corrigido** (teto global) |
| S9 | Air-gapped não bloqueava VirusTotal/AbuseIPDB/Shodan/Tor/rDNS | **Corrigido** |

Pendências do Lote 9, todas resolvidas no Lote 10:

| Pendência | Resolução |
|-----------|-----------|
| Sessão `current` restaurada para qualquer usuário | Restauração só com clique, descrevendo alvo/registros/data |
| Texto livre sem data / data no IP errado | Extração por linha (`data_processing/parsers/texto.py`) |
| Parsers Discord e Preservation Google sem teste | `tests/test_parsers_plataformas.py` |
| `data_processor.py` e `advanced_analysis.py` monolíticos | Fachadas sobre `data_processing/`, `analysis/heuristics.py` e `intel/` |
| Haversine duplicado; `iterrows` em saltos/relay | `analysis/_geo_math.py`; vetorizados com saída idêntica |
| i18n incompleto (259 chaves sem uso) | Interface pt/en/es; chaves órfãs removidas; `tests/test_i18n.py` |
| Sem smoke test das páginas | `tests/test_paginas.py` (15 páginas × 3 idiomas) |
| CI só em Linux | Job `windows-latest` |

Achados do Lote 10: Visão Geral contava alto risco com Score ≥ 50; Correlação
exibia 20 cadeias de relay como total; Operacional oferecia períodos que nunca
casavam no score; Entrada gravava `unknown` como alvo em inglês (o parser do
Discord só reconhece `desconhecido`); comparação lado a lado somava `Ip_Proxy`
textual; listas de IPs cortadas sem total (A/B, CGNAT, sparklines).

## 4. Roadmap 30 / 60 / 90 dias

### 30 dias
- ~~Cache temporal/geo~~ **feito (Lote 3)**
- ~~Endurecer Ruff (F401 per-file)~~ **feito (parcial)**
- ~~i18n interceptação + risco + temporal/geo (parcial)~~ **feito**
- ~~i18n residual (configurações API/Tor/audit)~~ **feito (Lote 4)**
- ~~Documentar deploy: auth + HTTPS reverse proxy~~ **feito (`docs/DEPLOY.md`)**
- ~~i18n branding tab + AI tab residual~~ **feito (Lote 5)**

### 60 dias
- ~~Extrair `enrich_service` compartilhado~~ **feito**
- ~~Quebrar `analysis.py` em submódulos~~ **feito (`analysis/` package)**
- ~~Mocks HTTP + cobertura api_client~~ **feito (parcial, `tests/test_api_client.py`)**
- ~~Persistência opcional parquet fora do session_state~~ **feito (`helpers/persistence.py`)**

### 90 dias
- ~~Camadas domain/application/infrastructure~~ **esqueleto feito (Lote 6), depois removido**
- ~~Audit trail com HMAC opcional~~ **feito (`AUDIT_HMAC_SECRET`)**
- ~~Modo air-gapped + retenção~~ **feito (Lote 6)**
- ~~Avaliar worker assíncrono se volume crescer~~ **CLI `scripts/enrich_worker.py`**

## 5. Features sugeridas (evolução)

- ~~Cancelamento de jobs longos e progresso unificado~~ **cooperativo (Lote 7)**
- ~~Comparação A/B de períodos na UI principal~~ **feito (Lote 8)**
- ~~Política de retenção de `ip_cache.json` e audit trail~~ **feito**
- ~~Export STIX/TAXII ou IOCs para integração SIEM~~ **STIX 2.1 + IOC (Lote 7)**
- ~~Cache assinado / assinatura de pacotes offline~~ **HMAC (Lote 8)**
- ~~Migrar pipelines UI para `application.enrich_use_case`~~ **substituído por `enrich_service`**
- TAXII push server-side (além do download STIX) — **fora de escopo / opcional**

## 6. Verificação

```bash
python -m pytest tests -q
```

Critérios de aceite do plano: exports sanitizados, HTML escapado, paths em `output/`, audit com cadeia, testes de regressão nos helpers.

**Última verificação:** 418 testes (409 rápidos + 9 `slow`), Lote 10.

## 7. Mapa de módulos novos (referência)

| Módulo | Função |
|--------|--------|
| `enrich_service.py` | Enriquecimento compartilhado |
| `export_ioc.py` | IOC txt/csv + STIX 2.1 |
| `helpers/job_control.py` | Cancel cooperativo |
| `helpers/period_compare.py` | A/B de períodos |
| `helpers/signed_cache.py` | Cache HMAC |
| `helpers/retention.py` | Retenção audit/sessions/cache |
| `helpers/persistence.py` | Parquet/pickle de sessão |
| `helpers/runtime_flags.py` | `AIR_GAPPED` etc. |
| `helpers/atomic_io.py` | Escrita atômica (`.part` + `os.replace`) |
| `scripts/enrich_worker.py` | Worker headless |
| `scripts/retention_cleanup.py` | CLI de retenção |
| `pages_app/analise/comparacao.py` | UI A/B |
| `docs/DEPLOY.md` | Deploy produção |
| `docs/AUDITORIA_TECNICA.md` | Este relatório |

## 8. Documentação de produto

- README raiz (PT, completo): `README.md`
- Espelhos resumidos: `docs/English/README.md`, `docs/Spanish/README.md` (o português é o da raiz)
- Segurança: `SECURITY.md` (+ traduções em `docs/*/SECURITY.md`)
- Deploy: `docs/DEPLOY.md`
- Env template: `.env.example`
