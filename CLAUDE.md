# Log Enrichment — notas para trabalho no código

Ferramenta **pericial** em Streamlit: enriquece logs de acesso e interceptações
(WhatsApp, Meta, Google, Discord, TikTok) com geolocalização e reputação de IP,
e produz relatórios com cadeia de custódia.

Isso muda o critério de "bom o bastante": a saída é **prova**. Um proxy
classificado como residencial, um total truncado apresentado como total real,
ou um dado obsoleto servido como atual são defeitos de conteúdo, não de
polimento.

## Comandos

```bash
venv/Scripts/python.exe -m pytest tests -q -m "not slow"
```

```bash
venv/Scripts/python.exe -m pytest tests/test_load.py -m slow
```

```bash
venv/Scripts/python.exe -m ruff check . && venv/Scripts/python.exe -m mypy
```

(O `mypy` sem argumentos usa a lista de `[tool.mypy].files` do `pyproject.toml`
— a mesma que o CI roda.)

```bash
venv/Scripts/python.exe -m pytest tests -q -m "not slow" --cov
```

```bash
venv/Scripts/python.exe -m pip_audit -r requirements.txt --strict
```

(Escopo e piso de cobertura em `[tool.coverage]` do `pyproject.toml`: suba o
`fail_under` quando a cobertura subir, não o desça para acomodar código sem teste.)

```bash
venv/Scripts/python.exe -m streamlit run app.py
```

## Regras que não se deduzem do código

**Escala.** Um caso real tem ~200.000 linhas. Fixtures de poucas linhas não
revelam complexidade O(n²) nem cópias do frame inteiro. Antes de aceitar
qualquer código no caminho de análise/exportação, considere se ele roda em
`tests/test_load.py` (202.128 linhas). Foi um `DBSCAN` sobre linhas brutas —
O(n²) de memória — que derrubou a geração de relatório em produção.

**Truncagem é sempre visível.** Se a interface ou um export mostra parte dos
dados, precisa declarar o total: `show_truncation(exibidos, total)` em
[helpers/large_data.py](helpers/large_data.py). Nunca fatie uma lista e
apresente o tamanho da fatia como se fosse a contagem real.

**Trabalho pesado exige clique.** `st.tabs` executa o corpo de **todas** as
abas a cada rerun, visíveis ou não. Análises que varrem o DataFrame vão atrás
de `gate(...)`; exports vão atrás de `prepare_button(...)` — `st.download_button`
exige os bytes prontos, então o padrão é em dois estágios. Chame
`bump_data_version()` em toda atribuição a `st.session_state.df_resultado`,
senão os portões liberados do alvo anterior continuam valendo.

**O Excel colorido é escrito em streaming.** `export_xlsx_colored` usa
`Workbook(write_only=True)`: cada linha é serializada no `append` e as células
são descartadas. O `Workbook` comum mantém um `Cell` vivo por célula — **622 MB
de heap só para 100 mil linhas x 15 colunas**, medido — e era isso que impunha
um teto de 100 mil linhas ao artefato que o analista abre. Nada nesse caminho
pode voltar a usar `ws.cell()`, `ws.active` ou guardar o workbook em memória.
O teto restante é o do formato (1.048.575 linhas por planilha); acima dele o
resultado continua em `Resultado (2)`, `(3)`... e o retorno
`{'linhas', 'abas'}` existe para a página **declarar isso ao analista**.
Acima de `XLSX_DISK_THRESHOLD` o arquivo é gerado em disco por
`export_xlsx_to_disk` e servido de um handle — dezenas de MB em
`st.cache_data` e no websocket derrubam a sessão.

**Fórmula injetada é problema do export, não do chamador.** Uma célula que
começa com `=`, `+`, `-` ou `@` é avaliada ao abrir a planilha — o valor exibido
deixa de ser o do log. `sanitize_dataframe_for_csv` roda **dentro** de
`export_xlsx_colored`, não em quem chama: foi exatamente por depender do chamador
que o caminho da interface passou a exportar sem sanitizar enquanto o do pipeline
sanitizava. `sanitize_csv_value` prefixa com `'` e é idempotente, então a dupla
passagem do pipeline é inofensiva — e a cópia preguiçosa faz a segunda sair de
graça. Cuidado com o `-`: o critério é `float(valor)` aceitar a string **inteira**,
senão `-2+3+cmd|' /C calc'!A0` passa como se fosse número negativo.

**Booleanos nunca com `str(x).lower() == 'true'`.** Os dados chegam de JSON
(bool nativo), CSV (`'1'`/`'0'`) e Excel pt-BR (`'VERDADEIRO'`). Use
`as_bool` / `bool_series` de [validators.py](validators.py), que registram um
aviso por token desconhecido em vez de classificar errado em silêncio.

**Escritas em disco são atômicas.** Use `helpers/atomic_io.py`
(`atomic_write`, `atomic_write_json`...): cache de IP, sessões, CSV/Excel do
pipeline, histórico, snapshots e cache Tor gravam em temporário + `os.replace`. O padrão truncar-e-escrever já destruiu o cache inteiro
numa falha no meio da gravação — e o carregamento seguinte começava do zero sem
avisar ninguém.

**O cache de IPs tem um leitor só.** Fora do `IPAPIClient`, leia com
`api_client.read_ip_cache()` (desembrulha e verifica o envelope assinado) e, se o
dado for servido como atual, passe por `filter_fresh_cache` (TTL). Caminho:
`api_client.IP_CACHE_PATH` — nunca `'ip_cache.json'` relativo ao diretório de
trabalho. `json.load` direto recebia o envelope `{'payload', 'signature'}` e a
página dizia "sem histórico".

**Chaves de cache levam o filtro.** `cache_key(...)` identifica a sessão e a
versão do dataset; o resto (filtros, colunas) é responsabilidade do chamador. O
tamanho do frame filtrado não identifica quais linhas ele tem. Resultado
calculado sobre o alvo que vive em `session_state` fora dos portões entra em
`_RESULT_KEYS` ([helpers/large_data.py](helpers/large_data.py)), senão sobrevive
à troca de alvo.

**O audit trail nunca é reescrito.** A retenção passa por
`audit_logger.archive_old_events`: arquiva os eventos antigos intactos e ancora a
cadeia com `RETENTION_CHECKPOINT`. Qualquer escrita no trail acontece sob
`audit_logger._LOCK`. `log_audit_event` devolve `_persisted`; quem chama mostra
erro quando for `False`.

**Datas `NN/NN/AAAA` são dia/mês.** `parse_data` decide a ordem olhando a coluna
inteira (`infer_dayfirst`). Nunca `pd.to_datetime(x)` sem formato, nem escolher
o formato pela primeira linha.

**Toda string de interface passa por `t()`** ([i18n.py](i18n.py)), com a
chave nos três `locales/*.json`. Opções de `selectbox`/`multiselect` são
**códigos internos** com `format_func=lambda k: t(...)` — a lógica compara o
código, nunca o texto traduzido (o filtro "Todos" quebrou em inglês por isso).
Valor que vai para o **dado** ou para o **laudo** (Alvo `desconhecido`,
classificação, relatório HTML, prompts da IA) fica em português fixo: o parser
do Discord reconhece `desconhecido`, não `unknown`. `tests/test_i18n.py` exige
paridade de chaves/placeholders e que toda chave usada exista;
`tests/test_paginas.py` renderiza as 15 páginas nos três idiomas.

**Teste nunca grava em dado de caso.** [tests/conftest.py](tests/conftest.py)
desvia audit trail, sessões, histórico e cache de IPs para um temporário e
falha a sessão se algum desses arquivos reais mudar. Foi por falta disso que o
`audit_trail.jsonl` real acumulou dezenas de `test_action` — e o trail não se
reescreve para limpar. Caminho novo de dado de caso entra no conftest. Script de
`AppTest` roda no processo do teste: se trocar atributo de módulo, restaure no
`finally`.

**Texto do laudo só afirma o que os dados mostram.** O resumo narrativo da
análise investigativa afirmava "predominância de IPv6" e uso "antes e depois do
fato" sem conferir. Toda frase gerada tem de sair de uma contagem sobre os dados
selecionados, e a ausência também se declara ("não há registro ... depois").

**Nunca `except Exception: pass`.** Isso engole `MemoryError` e apresenta "sem
dados" como se estivesse tudo bem. Use `logger.exception` e mostre o erro.

## Arquitetura

`app.py` monta a navegação estática (`st.navigation`) sobre `pages_app/`.
Adicionar página exige editar o bloco de imports **e** o dict `pages`.

Fluxo: `pages_app/entrada.py` → `file_handler.processar_log_acesso_async`
(logs de acesso) ou `interception_parser.processar_interceptacao_async`
(ZIPs de interceptação) → ambos por `enrich_service` → `api_client.IPAPIClient`
(ip-api.com, batch, cache com TTL) → `data_processor.processar_resultados`
funde os resultados no DataFrame.

- **`analysis/`** — pacote de análise (substituiu um monólito `analysis.py`).
  `__init__.py` reexporta ~47 nomes para preservar a superfície histórica.
  Mantenha-o **livre de `streamlit`**: `@st.cache_data` fica na página.
- **`data_processor.py`** — fachada pública sobre `data_processing/`
  (`formats`, `parsers/` por plataforma, `merge`); os imports marcados
  `# noqa: F401` são re-exports intencionais, não código morto.
- **`advanced_analysis.py`** — fachada sobre `analysis/heuristics.py` e
  `intel/` (VirusTotal, AbuseIPDB, Shodan, Tor). `analysis/__init__` importa
  direto desses módulos, **nunca** da fachada (import circular). Patch em
  teste vai no módulo onde a função mora (`intel.tor.fetch_tor_exit_nodes`),
  não na fachada — senão não tem efeito.
- **`intel/`** — tudo que sai para a rede passa por
  `helpers.runtime_flags.ensure_network_allowed` (modo air-gapped). O Ollama
  também, quando a URL não é loopback (`ai_assistant.ollama_remote_host`): o
  prompt leva IPs e datas do caso.
- **`helpers/`** — quase tudo é importado **preguiçosamente dentro de funções**.
  Um grep só no topo dos arquivos faz esses módulos parecerem órfãos; não são.
- **`validators.py`** e **`api_client.py`** estão sob `mypy` no CI — anote tipos.

## Armadilhas conhecidas

- `format='mixed'` no `to_datetime` cai no parser por elemento do dateutil.
  O pipeline grava `Data` sempre como `'%Y-%m-%d %H:%M:%S'`; use `parse_data`.
- Largura de elemento é `width='stretch'`, não `use_container_width=True`
  (descontinuado no Streamlit 1.54, com remoção anunciada). O `st_folium` é
  exceção: o parâmetro é da biblioteca dele.
- `pd.set_option` é **global e permanente no processo**. Nunca chame de dentro
  de um render — já houve um caso que desprotegia o Styler de outras páginas.
- `@st.cache_data` com DataFrame como argumento normal **hasheia os bytes do
  frame a cada rerun**, mesmo com acerto de cache. Prefixe com `_` e passe uma
  `cache_key` explícita.
- `iterrows()` e `apply(axis=1)` sobre o frame inteiro: quase sempre há uma
  versão por valor distinto. Geolocalização por IP tem cardinalidade baixíssima
  (4.319 IPs → 59 coordenadas), e é isso que torna várias análises viáveis.
- `SCHEMA_VERSION` em [helpers/persistence.py](helpers/persistence.py): incremente
  quando a forma do DataFrame mudar de modo que uma versão anterior não saiba ler.
- Tiles de mapa **nunca da CARTO**: passaram a exigir chave de API e agora
  respondem `200` com a imagem carimbada `API KEY REQUIRED` por cima do mapa
  inteiro. Nada estoura — o laudo só sai com a figura inutilizada. Os fundos
  sem chave estão em `helpers/geo.TILE_SOURCES`; o ArcGIS serve `{z}/{y}/{x}`
  (linha antes de coluna), e inverter devolve outro lugar do mundo sem erro.
- A coluna **`Porta` é condicional, de propósito**. `is_meta = 'Porta' in
  df.columns` ([file_handler.py](file_handler.py)) escolhe o conjunto de
  colunas do CSV, então incluí-la sempre acrescentaria uma coluna vazia a todo
  laudo de WhatsApp de hoje. O parser do WhatsApp já separa `IP:porta` — hoje
  isso é no-op, e no dia em que o WhatsApp passar a entregar porta como a Meta
  o registro é preservado em vez de reprovado na validação. Não valide o valor
  bruto contra `is_valid_ip`: `203.0.113.7:12538` não é IP válido e o registro
  inteiro some — justamente a porta que identifica o assinante atrás de CGNAT.
- Um IPv6 **sem brackets** é ambíguo (`2001:db8:...:37229`: o último grupo tanto
  pode ser porta quanto parte do endereço). Meta e WhatsApp usam brackets
  sempre que há porta, então `_split_ip_port` lê o valor inteiro como endereço.
  Não tente adivinhar — inventaria dado que o documento não afirma.
- O HTML da Meta e do WhatsApp **parte um campo ao meio na virada de página**:
  o rótulo fica no fim de uma página com o valor vazio e o valor reaparece na
  página seguinte, num bloco sem rótulo dentro de um invólucro novo. Ler os
  blocos `div.t.i` em sequência perde o registro inteiro (num caso real, 25 de
  27 IPs). O remendo mora em `_campos_da_secao` ([html_parser.py](html_parser.py));
  invólucros se reconhecem por conterem outros `div.t.i`, e o rótulo se
  distingue do valor por `contents[0]` ser `NavigableString`.
- Um `.xlsx` gerado em `write_only` **não tem a tag `<dimension>`**: ao reler
  com `load_workbook(read_only=True)`, `ws.max_row` vem `None`. Para contar
  linhas, varra `ws.rows`; e feche o workbook antes de apagar o arquivo, senão
  o Windows recusa com `PermissionError`.
- `helpers/large_data.py` é importado no topo de `app.py`, antes do
  `st.set_page_config`. Não o faça importar `file_handler` nem o pipeline —
  constantes do export moram em [file_handler.py](file_handler.py) e as páginas
  as buscam de lá diretamente.
- Script de `AppTest.from_function` **sem acentos**: no Windows ele é gravado
  em cp1252 e lido como UTF-8, e a página sai vazia sem exceção. Por isso
  `tests/test_paginas.py` também exige que a página renderize algo.
- Coluna nova de provedor tem de entrar em `COLUNAS_EXTRAS_PROVEDOR`
  ([data_processing/formats.py](data_processing/formats.py)), senão
  `processar_resultados` a descarta depois do enriquecimento; e o formato do
  resultado sai de `familia_formato`/`colunas_export_para` — não repita a
  cadeia de `if 'Porta' in df.columns` em página ou pipeline.
- **Google Aggregated Activities** (serviços e conexões) são intervalos
  agregados, não acessos. `Dias_Corridos` conta dias **UTC** de propósito: é a
  base do `Days Active` do Google (em GMT−3 o caso real teria 13 contradições
  entre as duas colunas, em UTC tem 2 — e são do próprio Google). Os dois
  arquivos nunca se fundem: o incremental recusa misturá-los
  (`FormatoSaidaIncompativel`). No laudo HTML, `generate_html_report` declara
  o formato, rotula contagens como linhas e descarta sozinho as análises de
  `ANALISES_NAO_APLICAVEIS_AGREGADO` (e recalcula o risco sem o fator de
  frequência), mesmo que o chamador as passe. Análise nova que conte linhas,
  horários de `Data` ou intervalos entre linhas como acessos entra nessa lista.
- O hash de integridade do relatório aparece em laudos já entregues. Qualquer
  mudança no seu cálculo precisa ser provada byte-a-byte idêntica
  (`tests/test_integrations.py::TestIntegrityHash`).

## Git

Todo o código está rastreado. O que é ignorado é **dado de caso**:
`ip_cache.json`, `cache_backups/`, `logs/` (inclui o `audit_trail*.jsonl`),
`output/`, `data/sessions/`. Um `git clean -fdx` apaga prova e a cadeia de
custódia — nunca rode sem confirmar. Não faça grep recursivo nesses diretórios:
eles contêm IPs e localizações de investigações reais.
