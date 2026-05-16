# Log Enrichment v5.2 Pro

Ferramenta profissional para extração, análise forense e enriquecimento de endereços IP em logs de acesso e interceptação telemática, utilizando múltiplas fontes de inteligência (IP-API, VirusTotal, AbuseIPDB).

## 📋 Descrição

O **Log Enrichment** é uma aplicação web (Streamlit) que automatiza a análise de logs de acesso e interceptação telemática do WhatsApp. Extrai endereços IP de diversos formatos, consulta APIs de geolocalização e reputação via **batch endpoint** (até 100 IPs por request), e gera relatórios completos com gráficos, mapas, grafos interativos e resumo executivo.

## ⚠️ Alerta de Dados Sensíveis

> **Atenção:** esta ferramenta pode processar **endereços IP, portas lógicas, horários de conexão, localização aproximada, ASN/provedor e metadados correlatos** obtidos de registros de plataformas e serviços como **Google, WhatsApp, Meta, Discord** e provedores de acesso. Em muitos contextos, esses dados podem ser **sensíveis, sigilosos ou juridicamente protegidos**.
>
> Quando você ativa consultas de enriquecimento ou reputação com **API Key**, parte desses dados é enviada para **serviços externos de terceiros**, como **IP-API, VirusTotal, AbuseIPDB e Shodan**, de acordo com a configuração utilizada. No caso do plano pago da IP-API, a chave é enviada no request como **query parameter `?key=`**, conforme a documentação do provedor.
>
> **Antes de processar dados reais:** verifique sua base legal, política institucional, cadeia de custódia e necessidade operacional. Sempre que possível, use ambiente controlado, minimize o conjunto enviado a terceiros e prefira fluxos locais/offline quando a consulta externa não for indispensável.
>
> **Importante:** o **Assistente AI via Ollama** opera localmente e **não envia dados para a nuvem por padrão**, mas as integrações de reputação/geolocalização dependem de comunicação externa quando habilitadas.

## ✨ Funcionalidades

### Enriquecimento de Logs de Acesso
- **10 Formatos de Entrada**: Genérico, Meta Platforms, WhatsApp, Google, Preservation Google, **Discord (PDF)**, CSV/Excel, **HTML WhatsApp** (records.html), **HTML Meta Platforms** (Facebook/Instagram), **HTML Google** (SubscriberInfo.html)
- **Batch API**: Consulta até 100 IPs por request via POST `/batch`, reduzindo tempo de processamento em até 10x
- **rDNS Assíncrono**: Resolução reversa de DNS em paralelo para todos os IPs
- **Detecção Automática de Formato**: Identifica o tipo de log automaticamente
- **Pré-visualização**: Visualize os IPs detectados antes de processar
- **Processamento Incremental**: Adicione novos IPs a arquivos existentes
- **Barra de Progresso Real**: Acompanhe o processamento em tempo real com percentual e contagem
- **Filtro de IPs Privados**: IPs privados/reservados (10.x, 192.168.x, 127.x) são ignorados automaticamente
- **Saída CSV com Reputação Colorida**: Coluna Reputação com texto colorido por categoria
- **Período com Emojis**: ☀️ Diurno / 🌙 Noturno para identificação visual rápida
- **Normalização de Provedores**: Agrupa variantes (Claro S.A./NXT/Net → Claro; Vivo/Telefônica/GVT → Vivo)

### Interceptação Telemática do WhatsApp
- **Processamento de ZIP com 15 dias**: Suporte ao formato oficial de interceptação (ZIP de ZIPs)
- **Upload de HTML único**: Processe um records.html individual
- **Message Log + Call Log**: Extrai dados de mensagens e chamadas
- **Saída CSV**: Colunas adaptadas (FROM, Sender IP, Sender Port, type)
- **Classificação por tipo**: message/text, message/voice, message/image, call/audio, call/video, etc.

### Dashboard de Estatísticas
- **Cards resumo**: Total de registros, IPs únicos, provedores, regiões, % proxy, % móvel
- **Tendência de atividade**: Setas ↑/↓ nos cards comparando primeira vs segunda metade do período
- **Card IP Mais Suspeito**: Destaque visual do IP com maior risco (proxy/VPN)
- **Spotlight por Provedor**: Gráfico linear com o provedor em destaque e os IPs mais recorrentes
- **Horários**: Série linear de atividade por hora, no estilo painel operacional
- **Dias da Semana**: Série linear para leitura rápida de ritmo semanal
- **Mix de Conexão**: Leitura visual de Residencial, Móvel, Proxy/VPN e Hosting
- **Timeline de Atividade**: Série diária com foco em picos e janelas de silêncio
- **Heatmap Temporal**: Hora × Dia da semana para detectar padrão de uso
- **Top IPs Recorrentes**: Ranking visual dos IPs mais frequentes
- **Detecção de Anomalias**: Identifica IPs em localizações incomuns

### 🗺️ Mapa de Geolocalização (Leaflet / Folium)

> **Motor de renderização**: Leaflet via Folium — experiência 2D padrão, leitura mais direta para uso investigativo e compatibilidade ampla no navegador.

**Cinco modos de visualização:**
- **Marcadores**: Pontos 2D com raio proporcional à frequência do IP e popup investigativo rico
- **Clusters**: Agrupamento visual por área com resumo de IPs e provedores por localidade
- **Heatmap Geográfico**: Camada de calor 2D com sobreposição leve dos pontos mais relevantes
- **Rota Temporal**: Linha cronológica entre localizações com início e fim destacados
- **Visão Investigativa**: Marcadores + rota sutil + destaque para proxy/datacenter + locais base (casa 🏠 / trabalho 🏢)

**Cinco estilos de mapa (tiles Carto — sem API key necessário):**
- Escuro (CartoDB dark_matter) · Escuro sem labels · Claro (CartoDB positron) · Voyager · OpenStreetMap

**Controles interativos:**
- **Filtro temporal**: Filtra IPs por intervalo de datas diretamente no mapa
- **Filtros operacionais**: Provedor, cidade, tipo de conexão e estilo do mapa
- **Legenda dinâmica**: Contagem por categoria de infraestrutura no estado filtrado
- **Popups investigativos**: IP, provedor, AS, localização, data, classificação e links externos
- **Geofencing**: Cerca geográfica com detecção de IPs fora do raio

**Replay Temporal 2D:**
- Timeline embutida em Leaflet.js
- Visualização progressiva dos pontos conforme o tempo avança
- Barra de progresso e controle de velocidade
- Consistente com o restante do mapa 2D da aplicação

**Classificação de Infraestrutura:**

O sistema classifica automaticamente cada IP em 6 categorias baseado no ASN e provedor:

| Categoria | Cor no Mapa | Ícone | Descrição |
|-----------|-------------|-------|-----------|
| **Proxy / VPN / Tor** | 🔴 Vermelho | 🛡️ | Flag `proxy=true` da API |
| **Datacenter / VPN** | 🟥 Vermelho suave | 🏢 | ASN de datacenter usado por VPNs (Datacamp, OVH, Hetzner, etc.) |
| **Cloud Pública** | 🟡 Âmbar | ☁️ | AWS, Google Cloud, Azure, Oracle, etc. |
| **Hospedagem** | 🟠 Laranja | 🖥️ | Flag `hosting=true` da API |
| **Rede Móvel** | 🔵 Azul | 📱 | Flag `mobile=true` da API |
| **Residencial** | 🟢 Verde | 🏠 | Conexão residencial/comercial padrão |

**50+ provedores de datacenter/VPN** monitorados, incluindo: Datacamp, OVH, Hetzner, Leaseweb, DigitalOcean, Vultr, Choopa, M247, Contabo, CDN77, NordVPN, ExpressVPN, Mullvad, entre outros.

**7 provedores de cloud pública** monitorados: Amazon AWS, Google Cloud, Microsoft Azure, Alibaba Cloud, Oracle Cloud, Tencent Cloud, Cloudflare, Akamai, entre outros.

**Alertas visuais:**
- **Banner vermelho** acima do mapa para IPs de datacenter/VPN/proxy com lista de IPs e provedores
- **Banner âmbar** para IPs de cloud pública
- **Popup com header colorido** e alerta contextual por categoria
- **Coluna Reputação** na tabela de resultados com classificação por IP

**Popups ricos:**
- Cabeçalho com cor da categoria (vermelho/âmbar/azul/verde)
- Alerta contextual: "ASN associado a datacenter usado por VPNs"
- País, Região, Cidade, Provedor, AS, Data, Classificação
- Links diretos para **Google Maps** e **Street View**

**8 abas de ferramentas abaixo do mapa:**

| Aba | Descrição |
|-----|-----------|
| 🌐 **Exportar** | KML (Google Earth), KML animado, GeoJSON |
| 📍 **Geofencing** | Cerca geográfica com raio configurável e validação de IPs fora do perímetro |
| ⚡ **Anomalias** | Detecção de saltos impossíveis (velocidade > limite) + Detecção de locais base (residência/trabalho) |
| 🧠 **Perfil** | Perfil comportamental automático, timeline de atividade, heatmap hora × dia da semana |
| 📅 **Comparação** | Comparação temporal período A vs B com detecção de mudanças |
| 📊 **Estatísticas** | Distribuição por país/cidade (Top 15), tabela detalhada geográfica |
| 📐 **Área** | Cálculo da área de movimentação (convex hull em km²), raio máximo, mapa com polígono |
| ✈️ **Viagens** | Padrão de viagem entre cidades, mini-mapa 2D com rota e sequência de deslocamentos |

### Relatório PDF
- Resumo geral (alvo, total, data, países)
- Top 10 provedores e regiões
- Distribuição por período e tipo de conexão
- Anomalias detectadas
- Top 10 IPs recorrentes
- **Gráficos embutidos** (provedores e tipo de conexão como imagens)
- Download direto do PDF

### Análise Avançada (7 páginas dedicadas)

O módulo de análise avançada foi reestruturado em **7 páginas agrupadas** com seções especializadas:

**📊 Visão Geral**
- KPIs resumo (IPs únicos, score médio de risco, % VPN/proxy, provedores, saúde dos dados)
- Status rápido (Tor nodes, alertas Shodan, IPs mascarados, alvos armazenados)
- Top 10 IPs por risco

**🛡️ Risco & Ameaças**
- **Risk Score**: Score de risco (0-100) por IP com breakdown de fatores
- **VirusTotal + AbuseIPDB**: Consulta multi-fonte com score unificado de ameaça (0-100). API Keys configuráveis via `.env`
- **Shodan**: Consulta de serviços/portas expostas — detecta portas perigosas, serviços inesperados, org mismatches e CVEs
- **Tor Exit Nodes**: Verificação contra duas fontes oficiais do Tor Project (`torbulkexitlist` + Onionoo), com deduplicação local e cache TTL de 6h

**🕐 Padrões Temporais**
- **Padrões Temporais**: Análise horária, dias mais ativos, score de rotina, gaps de atividade
- **Silêncio Digital**: Identifica gaps suspeitos de atividade (possível troca de dispositivo, viagem ou evasão)
- **Validação de Fuso Horário**: Cruzamento timezone vs geolocalização vs padrão de atividade
- **Timing Provedor**: Fingerprint temporal por provedor — distribuição horária, tipo de uso (always_on/scheduled/sporadic), detecção de padrão VPN, transições A→B→A (sandwich pattern)

**🌐 Geolocalização**
- **Histórico Geo**: Rastreamento de mudanças de geolocalização ao longo do tempo — detecta reassignação de IP
- **Sub-redes**: Análise de padrões por sub-rede (/24 IPv4, /48 IPv6) — score de consistência, sub-redes dominantes, correlação cruzada entre alvos
- **Padrões de Vida**: Clustering DBSCAN para detectar locais frequentados (casa, trabalho, lazer) com desvios de rotina

**🔗 Correlação**
- **Correlação Cruzada**: Encontre IPs em comum entre múltiplos alvos + comparação lado a lado
- **Wi-Fi Compartilhado**: Detecta co-localização exata por timestamps simultâneos na mesma rede
- **Cadeias de Relay**: Detecção de multi-hop VPN/proxy por proximidade temporal de IPs distintos

**🕵️ Comportamento**
- **VPN/Proxy Heurístico**: Detecção comportamental de VPN (rotação de IP, diversidade ASN, salto residencial, mix de infraestrutura)
- **Confiança de IP**: Classifica cada IP como "Real", "Incerto" ou "Mascarado" baseado em recorrência, flags e padrões
- **Números Descartáveis**: Detecta contatos com poucas aparições (interceptação)

**📋 Operacional**
- **Análise Investigativa**: Módulo policial com scoring e seleção de IPs + Assistente AI
- **Comparação Temporal**: Salve snapshots de análises e compare evolução entre datas diferentes
- **Saúde dos Dados**: Dashboard com gauges de cobertura e qualidade do dataset

### Módulos Complementares
- **Relatório Profissional**: Template PDF com capa, sumário executivo, metodologia, cadeia de custódia e hash SHA-256
- **Audit Trail Forense**: Registro JSONL append-only com hash SHA-256, verificação de integridade e recibo de custódia
- **Validação de Dados**: Pipeline de 3 camadas (Schema, Domain, Integrity) + prevenção de CSV injection
- **Multi-Target**: Processamento em lote de múltiplos alvos com detecção de IPs/locais compartilhados e atividade simultânea
- **Grafo de Rede IP** (`components/graph_view.py`): Visualização interativa de grafos IP ↔ ASN ↔ localização usando vis.js embeddido no Streamlit
- **Mapas Modernos** (`components/modern_map.py`): Motor pydeck/deck.gl mantido como base legada/experimental para evoluções futuras
- **Visualizações Avançadas** (`components/visualizations.py`): Gauges de saúde dos dados, comparação lado a lado de alvos, replay temporal 2D em Leaflet.js e tabela de IPs com sparklines

### 🔍 Análise Investigativa

Módulo especializado para uso investigativo policial:

- **Prioridade IPv6** — IPv6 é selecionado preferencialmente (mais rastreável que IPv4 via CGNAT). IPv4 só é usado quando não há IPv6 disponível. Bônus de +5 pts no score para IPv6. Coluna `Tipo_IP` exibida em todas as tabelas
- **Âncoras Temporais** — Para cada provedor, seleciona obrigatoriamente o primeiro e o último registro cronológico, demonstrando continuidade de uso ao longo do tempo
- **Diversificação de Horário** — Garante pelo menos 1 registro noturno (22h-06h) e 1 diurno (06h-18h) por provedor, fortalecendo a tese de acesso residencial
- **IPs por Provedor Flexível** — Slider de 3 a 10 IPs por provedor na interface
- **Score Investigativo (0-100)** — Proximidade temporal (40 pts), recorrência do provedor (20 pts), período (15 pts), continuidade (15 pts), bônus IPv6 (+5 pts), penalidade proxy (-10 pts)
- **Seleção de Provedores (Top 3)** — Regra dos 80%: verifica se os 3 provedores cobrem >80% dos registros válidos
- **IPs de Atenção** — Seção dedicada a outliers: IPs do dia do fato fora dos top 3, IPs com score alto de outros provedores, IPs de datacenter/VPN/proxy
- **Resumo Narrativo** — Texto descritivo gerado automaticamente com estatísticas por provedor, contagem IPv6/IPv4, cidades e padrão de horário
- **Detecção de Usuário Único** — Score 0-100 com 7 indicadores visuais (✅/⚠️/❌)
- **Seleção Interativa** — Multiselect com limite de 10 IPs por provedor, download CSV apenas dos selecionados
- **Agrupamento IPv6 /64** — Agrupa IPs pelo prefixo /64 para identificar IPs do mesmo roteador/rede doméstica
- **Detecção de CGNAT** — Identifica IPs IPv4 na faixa 100.64.0.0/10 (RFC 6598), compartilhados por múltiplos usuários via Carrier-Grade NAT

### ✈️ Análise de Viagens
- **Padrão de viagem** — Detecta deslocamentos entre cidades ao longo do tempo com distância em km
- **Rota visual** — Exibe sequência de cidades visitadas (ex: Joinville → Cuiabá → São Paulo)
- **Distância total** — Calcula km totais percorridos

### 📂 Modo Offline
- Carregue um CSV já enriquecido diretamente na aba **Entrada → Modo Offline**
- Funcionalidades de análise, mapa, estatísticas e investigativa sem chamar a API

### ⚡ Processamento Paralelo
- Batch usa **ThreadPoolExecutor** com até 4 workers simultâneos
- Processa múltiplos arquivos de log em paralelo em vez de sequencialmente
- Barra de progresso mostra contagem e quantidade de workers ativos

### 📦 Exportação Unificada ZIP
- Botão **"Exportar Tudo (ZIP)"** na página Resultados
- Gera ZIP contendo: CSV, JSON, Excel e PDF do relatório em um único download

### Exportação Multi-formato
- **Excel (.xlsx)** — formatado com cores, filtros e cabeçalhos estilizados
- **CSV (;)** — separador ponto-e-vírgula, encoding UTF-8 BOM
- **JSON** — array de objetos
- **PDF** — relatório formatado com gráficos
- **KML** — Google Earth com pontos coloridos
- **GeoJSON** — formato padrão GIS

### 🔒 Segurança
- **Autenticação com Argon2/bcrypt (recomendado)** em `AUTH_PASSWORD_HASH`; hash SHA-256 hex (64 caracteres) ainda aceito como legado
- **Rate limit de login**: 5 tentativas, bloqueio de 5 minutos após exceder
- **`AUTH_PASSWORD`**: apenas para dev; em produção use `AUTH_PASSWORD_HASH` gerado com `python scripts/gen_auth_password_hash.py` (ver [SECURITY.md](../../SECURITY.md))
- **API Key via query parameter**: Key enviada como parâmetro GET `?key=` conforme documentação ip-api.com
- **Arquivos temporários seguros**: Uso de `tempfile.mkstemp()` em vez de nomes previsíveis
- **API Keys via .env**: VirusTotal, AbuseIPDB e Shodan configuráveis via variáveis de ambiente

### 🚀 Performance e Infraestrutura
- **Retry com backoff exponencial**: 3 tentativas automáticas com delays crescentes em falhas
- **Batch endpoint real**: Consulta até 100 IPs por request via POST `/batch`; API paga envia até 5 batches concorrentes (500 IPs simultâneos)
- **Cache com TTL**: Entradas expiram após 30 dias (configurável), cache antigo migrado automaticamente
- **Processamento vetorizado**: `processar_resultados` otimizado com pandas vectorization
- **Filtro de IPs privados**: 10.x, 192.168.x, 172.16.x, 127.x, etc. não são enviados à API
- **Log persistente em arquivo**: Logs diários em `logs/log_enrichment_YYYYMMDD.log`
- **Fuso horário configurável**: Via `TZ_OFFSET_HOURS` no `.env` (padrão: -3)
- **Colunas de País**: `Ip_Pais` e `Ip_Pais_Codigo` adicionadas em todo o pipeline
- **Lookup rDNS**: Função `resolve_rdns()` disponível para consulta reversa de DNS

### ⚙️ Configurações (3 abas)

| Aba | Funcionalidade |
|-----|---------------|
| 🔌 **API & Cache** | Configuração de API Keys (IP-API, Shodan), toggle Tor, botão `Atualizar lista Tor`, limpeza de cache, formatos suportados |
| 🤖 **Assistente AI** | Configuração do Ollama (URL, modelo, tier), teste de conexão |
| 📋 **Audit Trail** | Visualização e verificação de integridade do log forense |

### 📄 Páginas da Aplicação (14 páginas em 4 grupos)

| Grupo | Página | Descrição |
|-------|--------|----------|
| 📥 **Dados** | Entrada de Dados | Upload de arquivos, colagem de texto, modo offline |
| | Resultados | Tabela interativa com busca, filtros e reputação colorida |
| 📊 **Visualização** | Estatísticas | Painel operacional com spotlight por provedor, séries lineares e heatmap |
| | Mapa | Mapa 2D com marcadores, clusters, heatmap, rota temporal e visão investigativa |
| 🔬 **Análise** | Visão Geral | KPIs, status rápido, Top 10 IPs por risco e resumo executivo |
| | Risco & Ameaças | Risk score, VirusTotal, AbuseIPDB, Shodan, Tor exit nodes |
| | Padrões Temporais | Análise horária, silêncio digital, validação de fuso, timing por provedor |
| | Geolocalização | Histórico geo, sub-redes, padrões de vida (clustering DBSCAN) |
| | Correlação | Correlação cruzada entre alvos, WiFi compartilhado, relay chains |
| | Comportamento | Detecção heurística VPN/proxy, confiança de IP, números descartáveis |
| | Operacional | Análise investigativa, comparação temporal, saúde dos dados |
| ⚙️ **Sistema** | Interceptação | Processamento de interceptação telemática WhatsApp |
| | Relatório | Geração de PDF profissional com gráficos embutidos |
| | Configurações | 3 abas (API & Cache, Assistente AI, Audit Trail) |

## 🛠️ Instalação

### Pré-requisitos
- Python 3.10+ (3.11 recomendado)
- pip

### Passos

```bash
# Criar ambiente virtual (recomendado)
python -m venv venv

# Ativar ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

### Configuração local

Crie um arquivo `.env` local a partir do template versionado:

```powershell
Copy-Item .env.example .env
```

```bash
cp .env.example .env
```

### Executar

```bash
streamlit run app.py
```

A aplicação abrirá automaticamente no navegador em `http://localhost:8501`.
Se você quiser usar APIs pagas ou recursos opcionais, complete o arquivo `.env` antes de executar.

## 📖 Uso

### 1. Enriquecimento de Logs de Acesso

1. Acesse a página **📥 Entrada**
2. Preencha o campo **Alvo** (número de telefone ou identificador)
3. Faça upload do arquivo ou cole o texto na aba correspondente
4. O sistema detecta o formato automaticamente e mostra uma pré-visualização
5. Configure as opções (incremental, cache, lote, período)
6. Clique em **▶️ Iniciar Processamento** — acompanhe a barra de progresso em tempo real
7. Visualize os resultados nas abas **📊 Resultados**, **📈 Estatísticas** e **🗺️ Mapa**

### 2. Interceptação Telemática do WhatsApp

1. Acesse a página **📞 Interceptação**
2. Faça upload do arquivo ZIP (15 dias) ou de um HTML individual
3. Configure o lote e período
4. Clique em **▶️ Processar Interceptação**
5. Baixe o resultado em CSV, Excel (.xlsx com reputação colorida) ou JSON

### 3. API IP-API.com (Gratuita e Paga)

O sistema suporta dois modos:

| Modo | URL | Rate Limit | HTTPS | Key |
|------|-----|------------|-------|-----|
| **Gratuito** (sem key) | `http://ip-api.com/json/` | 45 req/min | Não | — |
| **Pago** (com key) | `https://pro.ip-api.com/json/` | Ilimitado | Sim | Query param `?key=` |

> **Aviso operacional:** ao consultar IPs reais por meio dessas integrações, os indicadores submetidos passam a trafegar para infraestrutura externa. Em cenários investigativos, trate isso como envio de metadados potencialmente sensíveis.

**Para usar o plano pago:**
1. Acesse **⚙️ Configurações**
2. Insira sua API Key no campo correspondente, ou configure `IPAPI_KEY` no arquivo `.env`
3. A consulta passa a ser **ilimitada** via HTTPS

### 4. Processamento Batch (Varredura de Pasta)

1. Acesse **🔬 Análise Avançada → 📂 Varredura de Pasta**
2. Informe o caminho da pasta com os arquivos de log
3. Clique em **▶️ Processar Todos os Arquivos**
4. O sistema processa cada arquivo, gera resultado consolidado

## 📄 Formatos de Entrada Suportados

### Formato 1: Genérico (Lista de IPs)
```
191.13.51.97
2804:18:18bf:9681:1:0:70f2:df19
187.37.136.128
```

### Formato 2: Meta Platforms (Instagram/Facebook)
```
IP Address
24.152.81.150:22859
Time
2025-09-29 11:15:01 UTC
```
A porta lógica é extraída como coluna separada (`Porta`).

### Formato 3: WhatsApp (Log de Acesso)
```
Time
2025-12-10 18:58:48 UTC
IP Address
2804:14d:8e90:866e:d4ba:a89a:bcd8:8dc7
```

### Formato 4: Google
```
IP ACTIVITY

Timestamp   IP Address  Activity Type
2023-02-25 04:34:32 Z   2804:214:82ae:6fb1:1:1:b8eb:1d22    Login
```

### Formato 5: Preservation Google (CSV do Google Takeout)
```csv
Gaia ID,Activity Timestamp,IP Address,Proxiedhost IP Address,Is Non-routable IP Address,User Agent String,Product Name
314329686157,2026-03-11 02:49:39 UTC,2804:214:85c1:b496:81e9:9e8e:a396:d027,,No,App : YOUTUBE_APP. App Version : 21.10.2. Os : IOS_OS.,YouTube
314329686157,2026-03-11 02:33:59 UTC,168.0.233.233,,No,App : GMAIL_APP. App Version : 6.0.260302.,Gmail
```
Arquivo CSV gerado pelo Google Takeout (nome padrão: `Activities - A list of Google services accessed by your devices.csv`).
Detectado automaticamente pelas colunas `Activity Timestamp`, `IP Address` e `User Agent String`.
A coluna `User_Agent` é extraída e incluída na saída. IPs não roteáveis são filtrados automaticamente.

### Formato 6: Discord (PDF)
```
User ID:                     1366836644673622076
Username:                    r1ert47#0
Email:                       xxxxxx.6666@gmail.com
Email verified:              Yes
Phone number:                Not found
Registration IP:             Not found
Registration Time (UTC):     2025-04-29 18:00:50
Last Seen Time (UTC):        2025-05-14 01:43:39
Last Seen IP:                89.39.104.194

Session Start (UTC)    IP Address
2025-05-14 00:47:29    89.39.104.194
2025-05-13 23:55:51    179.63.13.130
2025-05-12 08:46:41    179.63.13.130
```
PDF gerado pelo Discord contendo dados do usuário (User ID, Username, Email) e tabela de sessões com timestamps e IPs.
Detectado automaticamente pela presença de `Session Start (UTC)` com `User ID:` ou `Username:`.
As colunas `User_ID`, `Username` e `Email` são extraídas e incluídas na saída.

### Formato 7: Interceptação Telemática (WhatsApp HTML)
Arquivo `records.html` gerado pelo WhatsApp contendo:
- **Message Log**: Mensagens criptografadas (text, voice, image, video, sticker, etc.)
- **Call Log**: Chamadas de áudio e vídeo (offer, accept, terminate, reject)

Suporta upload de ZIP com 15 dias de interceptação (ZIP contendo ZIPs internos com records.html).

## 📊 Colunas de Saída

### Log de Acesso (Excel .xlsx)

| Coluna | Descrição |
|--------|-----------|
| Alvo | Identificador (telefone ou outro) |
| Ip | Endereço IP extraído |
| Porta | Porta lógica (apenas Meta Platforms) |
| User_Agent | User Agent do dispositivo (apenas Preservation Google) |
| Data | Data/hora convertida para o fuso configurado |
| Data_Fuso | Fuso horário configurado |
| Ip_Dono | Provedor/proprietário do IP |
| Ip_AS | Sistema Autônomo (ASN) |
| Ip_Regiao | Estado/Província |
| Ip_Cidade | Cidade |
| Ip_Pais | País |
| Ip_Pais_Codigo | Código ISO do país (BR, US, etc.) |
| Ip_Movel | Conexão móvel |
| Ip_Proxy | Proxy/VPN |
| Ip_Hospedagem | Hospedagem/datacenter |
| Ip_Tor | Tor exit node |
| Periodo | Diurno (6h-18h) / Noturno |
| ISO_Date | Data em formato ISO 8601 |

### Interceptação Telemática (CSV / Excel .xlsx)

| Coluna | Descrição |
|--------|-----------|
| FROM | Número do remetente |
| Sender IP | Endereço IP do remetente |
| Sender Port | Porta lógica do remetente |
| Data | Data/hora convertida para o fuso configurado |
| Data_Fuso | Fuso horário configurado |
| Ip_Dono | Provedor/proprietário do IP |
| Ip_AS | Sistema Autônomo (ASN) |
| Ip_Regiao | Estado/Província |
| Ip_Cidade | Cidade |
| Ip_Pais | País |
| Ip_Pais_Codigo | Código ISO do país |
| Ip_Movel | Conexão móvel |
| Ip_Proxy | Proxy/VPN |
| Ip_Hospedagem | Hospedagem/datacenter |
| Ip_Tor | Tor exit node |
| Reputação | Classificação colorida (Normal, Móvel, Proxy/VPN, Hosting, Cloud) |
| Periodo | ☀️ Diurno (6h-18h) / 🌙 Noturno |
| ISO_Date | Data em formato ISO 8601 |
| type | Tipo: message/text, message/voice, call/audio, etc. |

## 🔧 Dependências

| Pacote | Uso |
|--------|-----|
| streamlit | Interface web |
| pandas | Manipulação de dados |
| openpyxl | Leitura de Excel |
| aiohttp | Cliente HTTP assíncrono (batch API, retry) |
| plotly | Gráficos interativos |
| **pydeck** | **Motor legado/experimental de mapas WebGL mantido no projeto** |
| **h3** | **Suporte geoespacial legado para agregações avançadas** |
| folium | Motor principal dos mapas 2D da aplicação |
| streamlit-folium | Integração Folium/Streamlit |
| fpdf2 | Geração de relatórios PDF |
| kaleido | Renderização de gráficos Plotly como imagem (PDF) |
| beautifulsoup4 | Parsing de HTML (interceptação) |
| simplekml | Exportação KML e KML animado (Google Earth) |
| scipy | Cálculos geodésicos e Convex Hull |
| scikit-learn | Clustering DBSCAN para padrões de vida |
| numpy | Cálculos numéricos |
| python-dotenv | Carregamento de variáveis de ambiente |

| requests | Cliente HTTP para integrações auxiliares |
| shodan | Consulta de serviços/portas (Shodan API) |
| pydantic | Structured output para o Assistente AI |
| matplotlib | Gráficos adicionais para relatórios |
| pdfplumber | Parsing de PDFs (Discord) |
| pytest | Framework de testes unitários |

## ⚙️ Configuração

### Variáveis de Ambiente (.env)
| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `IPAPI_KEY` | API Key do plano pago IP-API.com | (vazio) |
| `VIRUSTOTAL_API_KEY` | API Key do VirusTotal (free: 4 req/min) | (vazio) |
| `ABUSEIPDB_API_KEY` | API Key do AbuseIPDB (free: 1000 checks/dia) | (vazio) |
| `SHODAN_API_KEY` | API Key do Shodan (serviços e portas expostas) | (vazio) |
| `AUTH_PASSWORD` | Senha em texto plano (só desenvolvimento) | (vazio) |
| `AUTH_PASSWORD_HASH` | Hash Argon2/bcrypt (recomendado) ou SHA-256 hex legado | (vazio) |
| `TZ_OFFSET_HOURS` | Offset UTC do fuso horário | `-3` |
| `TZ_LABEL` | Label customizado do fuso | Auto |
| `WATCH_FOLDER` | Pasta para varredura automática | (vazio) |

### Arquivos de Configuração
| Arquivo | Descrição |
|---------|-----------|
| `ip_cache.json` | Cache de IPs com TTL de 30 dias |
| `processing_history.json` | Histórico dos últimos 50 processamentos |
| `infrastructure_providers.json` | Keywords de datacenter/VPN/cloud (externalizável) |

| `analysis_config.json` | Thresholds de análise avançada |
| `logs/` | Diretório de logs persistentes (um arquivo por dia) |
| `.streamlit/config.toml` | Tema escuro e configurações do Streamlit |

### API IP-API.com

| Modo | URL | Rate Limit | HTTPS | Key |
|------|-----|------------|-------|-----|
| **Gratuito** | `http://ip-api.com/json/` | 45 req/min | Não | — |
| **Pago** | `https://pro.ip-api.com/json/` | Ilimitado | Sim | Query param `?key=` |

Sem API Key, o sistema usa automaticamente a API gratuita com rate limit de 45 req/min.
Para o plano pago, configure a variável `IPAPI_KEY` no arquivo `.env`.

## 📁 Estrutura do Projeto

```
Log Enrichment/
├── app.py                         # Config, auth, st.navigation routing
├── ai_assistant.py                # Assistente AI local (Ollama/Qwen3.5) — structured output
├── pages_app/                     # Páginas da interface (multipage Streamlit)
│   ├── entrada.py                 # Upload, colagem de texto, processamento
│   ├── resultados.py              # Tabela interativa, filtros, reputação colorida
│   ├── estatisticas.py            # Painel operacional: spotlight por provedor, séries e heatmap
│   ├── mapa.py                    # Mapa 2D investigativo (Folium/Leaflet)
│   ├── relatorio.py               # Relatório PDF básico e profissional
│   ├── interceptacao.py           # Interceptação WhatsApp (ZIP/HTML)
│   ├── configuracoes.py           # API, AI Ollama, audit trail
│   └── analise/                   # Sub-páginas de análise avançada
│       ├── overview.py            # Dashboard KPIs + Top 10 risco + Resumo Executivo
│       ├── risco.py               # Risk Score, VirusTotal, AbuseIPDB, Shodan, Tor
│       ├── temporal.py            # Padrões temporais, silêncio, timezone, timing
│       ├── geo.py                 # Geo History, subnets, life patterns
│       ├── correlacao.py          # Cross-correlation, WiFi, relay chains
│       ├── comportamento.py       # VPN/Proxy, IP confidence, dispositivos
│       └── operacional.py         # Investigativa, comparação temporal, data health
├── styles/                        # Design system centralizado (v5.2)
│   ├── theme.py                   # Tokens: COLORS, COLORWAY, FONT_SIZES, SPACING, BORDER_RADIUS
│   ├── custom_css.py              # CSS global: sidebar, cards, botões, scrollbar, responsivo
│   └── components.py              # Componentes reutilizáveis: section_header, kpi_row, empty_state, badges
├── helpers/                       # Funções compartilhadas entre páginas
│   ├── __init__.py                # Pacote de helpers
│   ├── shared.py                  # add_log, run_processing, save_history, anomalies
│   ├── pdf_report.py              # Wrapper compatível para o relatório PDF rápido
│   └── geo.py                     # Haversine, popups do mapa
├── html_parser.py                 # Parser HTML: WhatsApp, Meta Platforms, Google
├── api_client.py                  # Cliente IP-API (batch /batch, retry, rDNS async)
├── data_processor.py              # Parsers de log + helpers período (emoji-safe)
├── file_handler.py                # Processamento assíncrono + CSV + XLSX on-demand
├── interception_parser.py         # Parser de interceptação telemática (HTML WhatsApp)
├── analysis.py                    # Análise unificada: risk, VPN, padrões, geo, correlação
├── advanced_analysis.py           # VirusTotal, AbuseIPDB, relay chains
├── tor_updater.py                 # Atualizador local do cache Tor (torbulkexitlist + Onionoo)
├── audit_logger.py                # Audit trail forense (SHA-256, JSONL)
├── validators.py                  # Validação de dados (3 camadas)
├── report_generator.py            # Relatórios profissionais PDF
├── ip_investigativo.py            # Análise investigativa com scoring + AI + seleção temporal
├── components/
│   ├── graph_view.py              # Grafo interativo IP/ASN (vis.js)
│   ├── modern_map.py              # Motor pydeck/deck.gl legado/experimental
│   └── visualizations.py          # Gauges, comparação, replay temporal 2D, sparklines
├── .github/workflows/tests.yml    # CI mínima para executar a suíte automatizada
├── CONTRIBUTING.md                # Guia curto para contribuições
├── LICENSE                        # Licença MIT do projeto
├── SECURITY.md                    # Processo de reporte responsável de vulnerabilidades
├── infrastructure_providers.json  # Keywords de datacenter/VPN/cloud
├── analysis_config.json           # Thresholds de análise + config AI
├── tests/                         # Suíte automatizada organizada por domínio
│   ├── common.py                  # Imports compartilhados e setup de path
│   ├── test_parsers.py            # Parsers, formatos e HTML
│   ├── test_analysis.py           # Análises, geo, sub-redes e timing
│   ├── test_integrations.py       # API, relatórios e smoke tests
│   ├── test_advanced.py           # Recursos avançados e assistente AI
│   └── test_security.py           # Validação, ZIP security e sanitização
├── requirements.txt               # Dependências Python de runtime e testes
├── .env.example                   # Template público de variáveis de ambiente
├── logs/                          # Logs persistentes (diários)
├── output/csv/                    # CSVs de resultado
├── cache_backups/                 # Backups automáticos do cache
├── .streamlit/config.toml         # Tema escuro
├── ALTERNATIVAS_GRATUITAS_IP_API.md # Documento técnico sobre alternativas gratuitas à ip-api.com
├── GUIA.md                        # Guia do usuário
└── README.md                      # Esta documentação
```

### Funções Principais

| Função | Módulo | Descrição |
|--------|--------|-----------|
| `consultar_batch()` | api_client.py | Batch API — até 100 IPs por request |
| `batch_resolve_rdns()` | api_client.py | rDNS assíncrono em paralelo |
| `normalizar_periodo()` | data_processor.py | Comparação de período emoji-safe |
| `periodo_matches()` | data_processor.py | Compara períodos ignorando emojis |
| `compute_unified_reputation()` | analysis.py | Score de reputação unificado (0-100) |
| `detect_vpn_timing()` | analysis.py | Detecção VPN por análise de timing |
| `cross_correlation_temporal()` | analysis.py | Correlação cruzada com sobreposição temporal |
| `detect_usage_profile()` | analysis.py | Detecção residencial vs corporativo |
| `compute_geo_precision()` | analysis.py | Indicador de precisão da geolocalização |
| `export_kml_animated()` | analysis.py | KML com timestamps para Google Earth Pro |

| `run_ai_analysis()` | ai_assistant.py | Orquestrador da análise AI via Ollama |
| `query_ollama()` | ai_assistant.py | Chamada REST ao Ollama com structured output |
| `validate_ai_response()` | ai_assistant.py | Validação da resposta AI contra regras de negócio |
| `check_ollama_status()` | ai_assistant.py | Verifica status e modelos do Ollama |

### 🤖 Assistente AI

Módulo de inteligência artificial local para análise investigativa:

- **100% offline** — dados nunca saem da máquina (Ollama local)
- **3 tiers de modelo**: Lite (4B/8GB), Standard (9B/16GB), Premium (27B/24GB)
- **Structured output** — resposta JSON via Pydantic schema
- **Segunda opinião** — complementa o algoritmo determinístico existente
- **Configurável** — modelo, URL e prompts editáveis via Configurações


## 🧪 Testes

```bash
python -m pytest tests -v
```

**167+ testes automatizados** organizados em `tests/` por domínio, cobrindo: validação de IP, IPs privados, rDNS, fuso horário, parsers (WhatsApp, Meta, Google, genérico e HTML), risk score, padrões temporais, geofencing, correlação cruzada, números descartáveis, cliente API, definição de colunas, **validators** (schema, domain, CSV injection), **VPN heuristics**, **IP confidence**, **life patterns**, **impossible jumps**, **base locations**, **movement area**, **infrastructure classification**, **audit logger**, **report generator** (rápido/profissional), **cache compression**, **relay chains**, **device fingerprinting**, **shared Wi-Fi**, **digital silence**, **timezone validation**, **data health**, **helpers de período**, **score unificado**, **VPN timing**, **correlação temporal**, **perfil de uso**, **precisão geográfica**, **KML animado**, **AI assistant** (prompts, validação, offline), **detecção tipo IP**, **ZIP security** (bomb detection, path traversal), **input sanitization**, **geofence coordinate validation**, updater Tor oficial com fallback de cache e smoke tests cobrindo entrada simples, relatório, exportação XLSX e enriquecimento de interceptação.

## 🔐 Governança

- **Licença**: MIT
- **Segurança**: reporte responsável descrito em `SECURITY.md`
- **Contribuição**: fluxo básico descrito em `CONTRIBUTING.md`
- **CI**: workflow em `.github/workflows/tests.yml` para rodar a suíte automatizada

## 📜 Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para o texto completo.

## 🔄 Changelog

### v5.2 (2025)

**Mapa — Visualização Inteligente de IPs**
- **Scatter proporcional**: Raio logarítmico baseado na frequência do IP (IPs recorrentes são visivelmente maiores) + opacidade proporcional (IPs raros mais translúcidos)
- **Slider temporal**: Filtro de período no mapa — arraste o slider para mostrar apenas IPs de um intervalo de datas
- **Colorir por** (4 modos): Infraestrutura (padrão) | Provedor (top 10 com cores únicas, rest cinza) | Temporal (gradiente azul→vermelho) | Risco (gradiente verde→amarelo→vermelho)
- **Visão Investigativa**: Novo modo composto com 4 camadas simultâneas — scatter proporcional + rota cronológica + alert rings proxy/VPN + locais base (casa/trabalho) detectados automaticamente
- **Legenda dinâmica**: HTML visual com contagem por categoria, gradiente para modos temporal/risco, cores por provedor

**UI — Design System Centralizado**
- Novo pacote `styles/` com design tokens, CSS global e componentes reutilizáveis
- `styles/theme.py`: ~25 tokens de cor (COLORS), paleta Plotly (COLORWAY), tipografia (FONT_SIZES), espaçamento (SPACING), bordas (BORDER_RADIUS), transições (TRANSITIONS)
- `styles/custom_css.py`: CSS injetado uma única vez — sidebar com gradiente, cards com hover glow, botões com efeitos translateY, scrollbar estilizada, responsivo, auth page com gradiente animado
- `styles/components.py`: Componentes Streamlit reutilizáveis — `section_header()`, `empty_state()`, `status_badge()`, `kpi_row()`, `sidebar_brand()`, `sidebar_data_summary()`, `sidebar_api_status()`, `sidebar_footer()`, `auth_header()`
- Cores hardcoded centralizadas em todas as páginas e componentes (visualizations, graph_view, pdf_report, ip_investigativo)
- consolidação da camada visual em `styles/` e remoção de referências obsoletas no fluxo atual
- 14 páginas refatoradas para usar `section_header()` e `empty_state()`

### v5.1 (2025)

**Segurança**
- Proteção contra ZIP bombs no parser de interceptação (limite de ratio, tamanho e profundidade)
- Prevenção de path traversal em entradas ZIP (rejeita `../` e caminhos absolutos)
- Sanitização de inputs de texto em campos de identificação de alvo
- Validação de limites de coordenadas e rejeição de Null Island (0,0) no geofencing

**Qualidade de Código**
- Correção de race condition no rate limiter do api_client (prune antes de check)
- Cap de 60s em wait times de rate limiting e retry backoff
- Limpeza de arquivos temporários com `try/finally` no gerador de PDF
- Substituição de `errors='ignore'` por `errors='replace'` em todas as decodificações
- Extração de regex de IP duplicado para constante `IP_REGEX_PATTERN`
- Correção de `pd.io.common.StringIO()` depreciado → `io.StringIO()`
- Log de exceções ao invés de `except: pass` silencioso na exportação ZIP

**Novos Recursos**
- Assistente AI integrado à página Operacional (execução de análise via Ollama com exibição completa de resultados)

- Null checks em parsers HTML do WhatsApp e Meta (previne `IndexError` em `div.contents` vazio)

- Warning visual quando alvo não é preenchido

**Testes**
- Novos testes para segurança ZIP (bomb, path traversal)
- Novos testes para sanitização de inputs
- Novos testes para validação de coordenadas no geofencing

**Documentação**
- README atualizado com o novo mapa 2D, dashboard estatístico redesenhado e ajustes do Ollama
- Documento técnico adicional: [ALTERNATIVAS_GRATUITAS_IP_API.md](ALTERNATIVAS_GRATUITAS_IP_API.md)
- GUIA atualizado com seção de Assistente AI, troubleshooting e FAQ

**Limpeza**
- Removido `_analise_avancada_deprecated.py` (sem referências)
- Versão do footer PDF atualizada de v3.0 para v5.0

## 🛠️ Troubleshooting

### Ollama / Assistente AI
- **Ollama não conecta**: Verifique se o Ollama está instalado e rodando (`ollama serve`). URL padrão: `http://localhost:11434`
- **Modelo não disponível**: Execute `ollama pull qwen3.5:4b` (lite), `ollama pull qwen3.5:9b-q8_0` (standard) ou `ollama pull qwen3.5:27b-q4_K_M` (premium)
- **Resposta lenta**: O tier lite (4B) é mais rápido; premium (27B) exige GPU com 24GB+ VRAM

### API e Rate Limiting
- **Erro 429 (Too Many Requests)**: O sistema aplica rate limiting automático com backoff. Considere adquirir API key paga
- **Timeout nas consultas**: Verifique sua conexão; o sistema tenta 3 vezes com backoff exponencial
- **Cache não funciona**: Verifique permissões de escrita no diretório do projeto

### Tor Exit Nodes
- **Lista Tor desatualizada**: Use o botão `Atualizar lista Tor` em Configurações → API & Cache para forçar refresh imediato via `torbulkexitlist` + Onionoo
- **Atualização agendada**: Execute `venv\Scripts\python.exe tor_updater.py --skip-if-fresh` em cron/Task Scheduler a cada 6–12 horas
- **Falha parcial de fonte**: Se uma fonte oficial estiver indisponível, o app ainda usa a outra e preserva o cache anterior como fallback

## 👨‍💻 Autor

**Desenvolvido por TWalking com ajuda da AI**
