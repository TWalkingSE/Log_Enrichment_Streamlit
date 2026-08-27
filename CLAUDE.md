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
venv/Scripts/python.exe -m ruff check . && venv/Scripts/python.exe -m mypy auth_password.py api_client.py validators.py
```

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

**Escritas em disco são atômicas.** Cache de IP, sessões em parquet e o Excel
colorido gerado em disco gravam em `.part` + `os.replace`. O padrão truncar-e-escrever já destruiu o cache inteiro
numa falha no meio da gravação — e o carregamento seguinte começava do zero sem
avisar ninguém.

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
- **`data_processor.py`** — fachada pública sobre `data_processing/`; os imports
  no topo marcados `# noqa: F401` são re-exports intencionais, não código morto.
- **`helpers/`** — quase tudo é importado **preguiçosamente dentro de funções**.
  Um grep só no topo dos arquivos faz esses módulos parecerem órfãos; não são.
- **`validators.py`** e **`api_client.py`** estão sob `mypy` no CI — anote tipos.

## Armadilhas conhecidas

- `format='mixed'` no `to_datetime` cai no parser por elemento do dateutil.
  O pipeline grava `Data` sempre como `'%Y-%m-%d %H:%M:%S'`; use `parse_data`.
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
- O hash de integridade do relatório aparece em laudos já entregues. Qualquer
  mudança no seu cálculo precisa ser provada byte-a-byte idêntica
  (`tests/test_integrations.py::TestIntegrityHash`).

## Git

O repositório tem muito arquivo **untracked** de um refactor em andamento,
incluindo `analysis/` e vários `helpers/` dos quais `app.py` depende para subir.
Um `git clean -fd` ou um clone novo produz uma aplicação que não inicializa.
Confirme o estado antes de qualquer operação destrutiva do git.
