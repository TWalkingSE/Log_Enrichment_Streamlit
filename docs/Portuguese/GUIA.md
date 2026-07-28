# 📘 Guia do Usuário — Log Enrichment v5.2 Pro

## Índice

1. [Entendendo os Tipos de IP](#-entendendo-os-tipos-de-ip)
2. [Por que isso importa na investigação?](#-por-que-isso-importa-na-investigação)
3. [Como a ferramenta identifica cada tipo](#-como-a-ferramenta-identifica-cada-tipo)
4. [Funcionalidades Principais](#-funcionalidades-principais)
5. [Fluxo de Trabalho Recomendado](#-fluxo-de-trabalho-recomendado)
6. [Dicas para Investigação](#-dicas-para-investigação)
7. [Perguntas Frequentes (FAQ)](#-perguntas-frequentes-faq)

---

## ⚠️ Aviso Importante sobre Sigilo e Serviços Externos

Antes de usar a ferramenta com dados reais, considere que ela pode manipular **IPs, portas, horários, ASN/provedor, localização aproximada e outros metadados** extraídos de registros de **Google, WhatsApp, Meta, Discord, TikTok** e provedores de acesso. Esses elementos podem ser **sensíveis, protegidos por sigilo** e sujeitos a regras legais e institucionais específicas.

Quando o app consulta **IP-API, VirusTotal, AbuseIPDB ou Shodan**, os identificadores processados são enviados para **serviços externos de terceiros**. Se houver **API Key** configurada, essa autenticação acompanha a requisição; no plano pago da **IP-API**, por exemplo, a chave é transmitida como **query parameter `?key=`**.

Use a ferramenta com a mesma cautela de um sistema pericial:
- valide a base legal e a necessidade operacional antes de submeter dados reais;
- minimize o volume de indicadores enviados a terceiros;
- prefira ambiente controlado e dados de teste quando estiver validando fluxos;
- lembre que o **Ollama** roda localmente, mas as integrações de reputação e geolocalização dependem de tráfego externo quando habilitadas.

---

## 🌐 Entendendo os Tipos de IP

Quando um dispositivo se conecta à internet, ele recebe um endereço IP que revela informações sobre **como** e **de onde** essa conexão foi feita. Existem 6 tipos principais:

### 🏠 Residencial (Wi-Fi / Banda Larga)

**O que é:** IP atribuído por um provedor de internet residencial (Vivo, Claro, TIM, Oi, etc.) a uma conexão fixa — normalmente um roteador Wi-Fi doméstico ou empresarial.

**Características:**
- Associado a um endereço físico (residência ou empresa)
- Geolocalização geralmente precisa (cidade/bairro)
- ASN pertence a um provedor de telecomunicações
- **Não** possui flags de proxy, hosting ou mobile

**Valor investigativo: ⭐⭐⭐⭐⭐ (Máximo)**
- Permite identificar a região/cidade do acesso com boa precisão
- O provedor mantém registros de qual assinante usava aquele IP naquele momento
- Mediante requisição judicial, o provedor pode informar o titular da conexão
- Se o IP for **IPv6**, a identificação é ainda mais precisa (sem compartilhamento via CGNAT)

**Exemplo no mapa:** 🟢 Marcador verde

---

### 📱 Rede Móvel (4G/5G)

**O que é:** IP atribuído por uma operadora de telefonia celular (Vivo, Claro, TIM) quando o dispositivo usa dados móveis (4G/5G), sem estar conectado a Wi-Fi.

**Características:**
- Geolocalização menos precisa (pode indicar a cidade, mas não o bairro exato)
- A localização indica a torre/ERB (Estação Rádio Base) mais próxima, não o local exato do usuário
- Frequentemente usa **CGNAT** (IPv4 compartilhado entre vários usuários)
- ASN pertence a uma operadora móvel

**Valor investigativo: ⭐⭐⭐⭐ (Alto)**
- Confirma que o acesso foi feito via celular
- A operadora pode, com ordem judicial, **vincular o IP + porta + horário a um número de telefone**
- Se usar **IPv6**, a identificação é direta (sem compartilhamento)
- Se usar **IPv4 com CGNAT** (faixa 100.64.x.x), é necessário informar a **porta lógica** para identificar o usuário

> **⚠️ CGNAT (Carrier-Grade NAT):** Quando vários usuários compartilham o mesmo IPv4 público. Para individualizar, a operadora precisa do IP + porta + horário exato. IPs na faixa `100.64.0.0/10` são indicativos de CGNAT.

**Exemplo no mapa:** 🔵 Marcador azul

---

### 🏢 Datacenter / VPN

**O que é:** IP pertencente a um datacenter (OVH, Hetzner, DigitalOcean, Vultr, etc.) frequentemente utilizado por serviços de VPN comerciais (NordVPN, ExpressVPN, Surfshark, etc.).

**Características:**
- ASN pertence a empresa de infraestrutura, não a um provedor de internet
- O IP pode estar em outro país (o usuário real pode estar em qualquer lugar)
- A geolocalização indica onde está o **servidor**, não o **usuário**
- Provedores de VPN geralmente não mantêm logs ou operam fora de jurisdições brasileiras

**Valor investigativo: ⭐⭐ (Baixo)**
- A geolocalização **NÃO** representa a localização real do usuário
- Indica que o usuário **está deliberadamente ocultando** seu IP verdadeiro
- O fato de usar VPN pode ser relevante em si (consciência de anonimato)
- Em alguns casos, o provedor de VPN pode ser intimado, mas muitos alegam política "no-logs"

**Exemplo no mapa:** 🔴 Marcador vermelho com anel pulsante + alerta

---

### 🖥️ Hosting (Hospedagem)

**O que é:** IP pertencente a um serviço de hospedagem de sites ou servidores. Diferente de VPN — aqui o IP é usado para hospedar websites, APIs ou serviços online.

**Características:**
- Flag `hosting=true` retornada pela API
- Pode ser um servidor web, bot automatizado, ou acesso via proxy corporativo
- Não necessariamente indica ocultação intencional

**Valor investigativo: ⭐⭐⭐ (Médio)**
- Pode indicar acesso automatizado (bot, scraper)
- Pode indicar proxy corporativo (empresa usando IP de datacenter para funcionários)
- O provedor de hosting geralmente tem dados do cliente que contratou o servidor
- Com ordem judicial, é possível obter dados do titular do servidor

**Exemplo no mapa:** 🟠 Marcador laranja

---

### ☁️ Cloud Pública

**O que é:** IP pertencente a grandes provedores de nuvem — Amazon AWS, Google Cloud, Microsoft Azure, Oracle Cloud, Alibaba Cloud, etc.

**Características:**
- ASN pertence a gigante de tecnologia (Amazon, Google, Microsoft)
- Pode ser um serviço legítimo (API, aplicação web) ou uma VPN/proxy improvisada
- IPs são frequentemente rotacionados entre clientes

**Valor investigativo: ⭐⭐ (Baixo a Médio)**
- Se for AWS/Google/Azure: requisição judicial pode obter dados da conta que alugou o servidor
- Frequentemente usado por atacantes para anonimização via instâncias temporárias
- Às vezes é tráfego legítimo de aplicações (ex: backup, sincronização de apps)

**Exemplo no mapa:** 🟡 Marcador âmbar com alerta

---

### 🛡️ Proxy / VPN / Tor

**O que é:** IP explicitamente identificado como **proxy, VPN ou nó Tor** pela API. É a classificação mais forte de anonimização.

**Características:**
- Flag `proxy=true` retornada pela API de geolocalização
- Inclui proxies abertos, VPNs conhecidas e nós de saída da rede Tor
- A geolocalização é **completamente irrelevante** — mostra onde está o proxy, não o usuário

**Valor investigativo: ⭐ (Mínimo)**
- **Tor:** Quase impossível rastrear (tráfego criptografado em múltiplas camadas)
- **Proxy aberto:** O operador do proxy pode ter logs, mas geralmente não coopera
- O fato de usar Tor/proxy é altamente relevante para demonstrar **intenção de anonimato**
- Em análise de interceptação, alterne entre IPs mascarados e residenciais para encontrar vazamentos

**Exemplo no mapa:** 🔴 Marcador vermelho com anel pulsante + alerta em banner

---

## 🎯 Por que isso importa na investigação?

| Tipo de IP | Localização confiável? | Identifica o usuário? | Ação investigativa |
|:-----------|:----------------------:|:---------------------:|:-------------------|
| 🏠 Residencial | ✅ Sim (cidade/bairro) | ✅ Via provedor + ordem judicial | Requisitar dados cadastrais ao provedor |
| 📱 Móvel | ⚠️ Aproximada (torre) | ✅ Via operadora (IP + porta + hora) | Requisitar com porta lógica se CGNAT |
| 🖥️ Hosting | ❌ Local do servidor | ⚠️ Titular do servidor | Requisitar ao provedor de hosting |
| ☁️ Cloud | ❌ Local do datacenter | ⚠️ Titular da conta cloud | Requisitar ao provedor (AWS, Google, etc.) |
| 🏢 Datacenter/VPN | ❌ Local do servidor | ❌ VPNs não costumam guardar logs | Registrar como indício de anonimização |
| 🛡️ Proxy/Tor | ❌ Irrelevante | ❌ Rastreamento muito difícil | Documentar uso de anonimização |

### Estratégia: Buscar os IPs Residenciais e Móveis

Na prática investigativa, os IPs mais valiosos são os **residenciais** e **móveis**, pois:

1. A geolocalização é confiável
2. O provedor pode identificar o assinante
3. Padrões de horário revelam rotina (casa, trabalho)
4. IPv6 permite identificação direta sem porta lógica

Os IPs de VPN/proxy/datacenter servem como **indicadores de comportamento** — mostram que o alvo usa ferramentas de anonimização, o que pode ser relevante para a narrativa do caso.

---

## 🔍 Como a ferramenta identifica cada tipo

O Log Enrichment usa um sistema de classificação em 6 camadas, na seguinte ordem de prioridade:

```
1️⃣ Proxy/VPN/Tor  →  Flag proxy=true da API (prioridade máxima)
2️⃣ Datacenter/VPN  →  ASN conhecidos de datacenter (50+ provedores monitorados)
3️⃣ Cloud Pública   →  ASN de AWS, Google Cloud, Azure, etc.
4️⃣ Hosting         →  Flag hosting=true da API
5️⃣ Rede Móvel      →  Flag mobile=true da API
6️⃣ Residencial     →  Nenhum dos acima (conexão padrão)
```

Cada tipo recebe uma **cor no mapa** e **ícone** para identificação visual rápida.

---

## 🛠️ Funcionalidades Principais

### 📥 1. Entrada de Dados

A ferramenta aceita múltiplas fontes de dados:

| Fonte | Como usar |
|-------|-----------|
| **Texto colado** | Cole uma lista de IPs diretamente na interface |
| **Arquivo de log** | Upload de arquivo `.txt` ou `.log` com IPs |
| **CSV/Excel** | Upload de planilha já formatada |
| **Preservation Google** | CSV do Google Takeout com User Agent |
| **HTML WhatsApp** | Upload de `records.html` do WhatsApp Business Record |
| **HTML Meta Platforms** | Upload de `records.html` do Facebook/Instagram — com porta (IG) ou sem (FB) |
| **HTML Google** | Upload de `SubscriberInfo.html` com tabela IP Activity |
| **Discord (PDF)** | Upload de PDF do Discord com Session Start/IP Address + User ID/Username/Email |
| **TikTok (PDF)** | Upload de PDF "Events IP Data" do TikTok com Date/IP/Event/Country (coluna `Evento` na saída) |
| **ZIP de Interceptação** | Upload do ZIP de 15 dias do WhatsApp |
| **HTML de Interceptação** | Upload de `records.html` individual |
| **Modo Offline** | Carregue CSV já enriquecido (sem chamar API) |

**Formatos de log detectados automaticamente:** Genérico, Meta Platforms, WhatsApp, Google, Preservation Google, Discord (PDF), TikTok (PDF), HTML WhatsApp, HTML Meta Platforms, HTML Google.

---

### 📊 2. Resultados e Estatísticas

Após o processamento, a ferramenta apresenta:

- **Tabela interativa** com busca, filtros por provedor/região/tipo e sparklines de frequência
- **Cards de resumo**: total de registros, IPs únicos, provedores, regiões, % proxy e % móvel
- **Spotlight por provedor**: gráfico principal com os IPs mais recorrentes do provedor em destaque
- **Séries operacionais**: atividade por hora e por dia da semana, com leitura rápida de ritmo
- **Mix de conexão**: visão comparativa entre Residencial, Móvel, Proxy/VPN e Hosting
- **Timeline diária**: série temporal para picos de atividade e janelas de silêncio
- **Heatmap temporal**: hora × dia da semana para identificar padrão de uso
- **Top IPs recorrentes e anomalias**: ranking visual e destaque para localizações incomuns

---

### 🗺️ 3. Mapa de Geolocalização (Leaflet / Folium)

> **Motor atual:** Leaflet via Folium. A experiência do produto foi simplificada para 2D, com leitura mais direta para uso operacional e compatibilidade melhor no navegador.

Cinco modos de visualização:

| Modo | Melhor para | Implementação |
|------|-------------|---------------|
| **Marcadores** | Ver cada ponto com raio proporcional à recorrência do IP | Folium com CircleMarker |
| **Clusters** | Consolidar muitos registros por área | Folium MarkerCluster |
| **Heatmap** | Identificar zonas de concentração geográfica | Folium HeatMap |
| **Rota Temporal** | Ler deslocamentos cronológicos entre cidades/localizações | Folium PolyLine + marcadores de início/fim |
| **Visão Investigativa** | Combinar marcadores, rota sutil, alertas e locais base | Composição 2D em Folium |

**Controles interativos:**
- 📅 **Filtro temporal** — Limita os pontos exibidos por intervalo de datas
- 🧭 **Filtros operacionais** — Provedor, cidade, tipo de conexão e estilo do mapa
- 🗺️ **5 estilos de tile** — Escuro, Escuro sem labels, Claro, Voyager e OpenStreetMap
- 🏷️ **Legenda dinâmica** — Resume a distribuição por infraestrutura no recorte atual
- 📌 **Popups investigativos** — Exibem IP, provedor, AS, localização, data, classificação e atalhos externos

**Ferramentas do mapa (8 abas):**
- 🌐 **Exportar** — KML, KML animado e GeoJSON
- 📍 **Geofencing** — Define um raio e identifica IPs fora da cerca
- ⚡ **Anomalias** — Detecta saltos impossíveis e ajuda a localizar pontos-base
- 🧠 **Perfil** — Consolida perfil comportamental e padrões temporais
- 📅 **Comparação** — Compara períodos A vs B para detectar mudanças
- 📊 **Estatísticas** — Resume distribuição geográfica por país e cidade
- 📐 **Área** — Calcula área de movimentação (km²) e raio máximo
- ✈️ **Viagens** — Resume deslocamentos entre cidades com mini-mapa 2D

**Replay Temporal 2D:**
- Executado em Leaflet.js, consistente com o restante do mapa
- Exibe os pontos progressivamente conforme o tempo avança
- Mantém leitura operacional direta, sem dependência de visualização 3D

> **Dica:** Use **Clusters** para conjuntos grandes, **Rota Temporal** para sustentar deslocamentos cronológicos e **Visão Investigativa** quando precisar combinar contexto de infraestrutura, rota e possíveis locais-base em uma única leitura.

---

### 🔬 4. Análise Avançada (7 Páginas)

O módulo de análise foi reestruturado em **7 páginas dedicadas** com seções especializadas:

| Página | Seções |
|--------|--------|
| 📊 **Visão Geral** | KPIs resumo (IPs únicos, score risco, % VPN, provedores, saúde), status rápido (Tor, Shodan, IPs mascarados), Top 10 IPs por risco e Resumo Executivo |
| 🛡️ **Risco & Ameaças** | Risk Score (0-100), VirusTotal + AbuseIPDB (score unificado), Shodan (portas/serviços/CVEs), Tor Exit Nodes |
| 🕐 **Padrões Temporais** | Análise horária/rotina/gaps, Silêncio Digital, Validação de Fuso, Timing por Provedor (fingerprint, sandwich A→B→A), Transições |
| 🌐 **Geolocalização** | Histórico Geo (mudanças de localização), Sub-redes (/24 e /48, consistência, correlação cruzada), Padrões de Vida (DBSCAN clustering) |
| 🔗 **Correlação** | Correlação Cruzada entre alvos + comparação lado a lado, Wi-Fi Compartilhado (co-localização), Cadeias de Relay (multi-hop VPN) |
| 🕵️ **Comportamento** | VPN/Proxy Heurístico (score 0-100), Confiança de IP (Real/Incerto/Mascarado), Números Descartáveis (interceptação) |
| 📋 **Operacional** | Análise Investigativa (scoring + AI via Ollama), Comparação Temporal (snapshots), Saúde dos Dados (gauges) |

---

### 🔍 5. Análise Investigativa (Destaque)

Módulo especializado para investigação policial:

- **Prioridade IPv6** — IPv6 é preferido por ser mais rastreável (sem CGNAT)
- **Âncoras Temporais** — Primeiro e último registro por provedor para demonstrar continuidade
- **Diversificação de Horário** — Garantia de registros noturnos e diurnos (acesso residencial)
- **Score Investigativo (0-100)** — Avalia a qualidade de cada IP para fins de requisição
- **Regra dos 80%** — Seleciona os 3 provedores que cobrem >80% dos registros
- **IPs de Atenção** — Outliers e IPs suspeitos separados
- **Resumo Narrativo** — Texto automático com estatísticas por provedor
- **Detecção de Usuário Único** — Score com 7 indicadores visuais
- **Agrupamento IPv6 /64** — IPs do mesmo roteador/rede doméstica

---

### ⚙️ 7. Configurações (3 abas)

| Aba | Funcionalidades |
|-----|----------------|
| 🔌 **API & Cache** | API Key IP-API (plano pago), toggle cache, toggle Tor, botão Atualizar lista Tor, Shodan status, formatos suportados |
| 🤖 **Assistente AI** | URL do Ollama, teste de conexão, teste de inferência e seleção de tier (Lite/Standard/Premium) |
| 📋 **Audit Trail** | Últimos 50 eventos, verificação de integridade do log forense |

**Segurança:**
- Autenticação com Argon2/bcrypt (recomendado) ou hash SHA-256 legado, rate limit contra brute force
- API Keys via `.env`: IP-API, VirusTotal, AbuseIPDB, Shodan
- Log forense append-only com hash SHA-256
- Toggle para verificação automática de Tor exit nodes e atualização manual sob demanda

---

### 🔎 8. Configuração de Features Avançadas

#### Shodan
1. Obtenha uma API Key em [https://shodan.io](https://shodan.io)
2. Configure em **⚙️ Configurações → API & Cache → Shodan API Key** ou via `.env`: `SHODAN_API_KEY=sua_chave`
3. Na página **🔬 Risco & Ameaças → Shodan**, clique em **Consultar Shodan**
4. O sistema verifica portas expostas, serviços inesperados, CVEs e mismatches de organização

#### Tor Exit Nodes
1. Ative em **⚙️ Configurações → API & Cache → Verificar Tor Exit Nodes**
2. Se quiser forçar o refresh, use **⚙️ Configurações → API & Cache → Atualizar lista Tor**
3. Na página **🔬 Risco & Ameaças → Tor Exit Nodes**, clique em **Verificar IPs contra Tor**
4. A lista é consolidada a partir de `torbulkexitlist` + Onionoo, deduplicada e cacheada localmente por 6 horas
5. Para automação local, agende `venv\Scripts\python.exe tor_updater.py --skip-if-fresh` a cada 6–12 horas (cron ou Task Scheduler)

#### Sub-redes
- Na página **🔬 Geolocalização → Sub-redes**, ajuste as máscaras IPv4 (/16 a /32) e IPv6 (/32 a /64)
- Score de consistência: alto = uso residencial estável, baixo = VPN ou roaming
- Com 2+ alvos armazenados, use **Correlação de Sub-redes entre Alvos** para encontrar conexões por sub-rede

#### Timing Provedor
- Na página **🔬 Padrões Temporais → Timing Provedor**, ajuste o mínimo de registros
- Detecta automaticamente padrão VPN: horas exclusivas de uso de VPN vs residencial
- Padrão sandwich (A→B→A) indica sessão VPN dentro de uso residencial normal

#### Assistente AI
1. Instale o [Ollama](https://ollama.ai) localmente. Ele é um serviço externo e **não faz parte do `requirements.txt`**, porque o projeto fala com ele via HTTP.
2. Baixe pelo menos um modelo compatível, de preferência começando pelo Lite: `ollama pull qwen3.5:4b`
3. Se quiser outros tiers, use também `ollama pull qwen3.5:9b-q8_0` ou `ollama pull qwen3.5:27b-q4_K_M`
4. Configure a URL em **⚙️ Configurações → Assistente AI** (padrão: `http://localhost:11434`)
5. Rode **Testar Conexão** e depois **Teste de Inferência** para validar geração real do modelo
6. O app prioriza o tier configurado e pode fazer fallback automático para um modelo mais leve em caso de indisponibilidade ou timeout
7. Na página **📋 Operacional → Análise Investigativa**, a AI fornece uma segunda opinião sobre a seleção de IPs
8. **100% offline** — dados investigativos não saem da máquina

---

### 📤 9. Exportação

| Formato | Uso |
|---------|-----|
| **CSV** | Formato principal de saída (reputação colorida na interface) |
| **JSON** | Integração com sistemas |
| **PDF** | Relatório profissional com gráficos |
| **KML** | Visualização no Google Earth |
| **KML Animado** | Rota temporal animada no Google Earth Pro |
| **GeoJSON** | Integração com GIS |
| **ZIP** | Download completo (CSV + JSON + PDF) |

---

## 📋 Fluxo de Trabalho Recomendado

```
1. 📥 ENTRADA
   └─ Upload de log ou interceptação

2. 📊 VISÃO GERAL
   ├─ Resultados → Ver tabela, filtrar por tipo
   ├─ Estatísticas → Identificar padrões
   └─ Mapa → Visualizar geolocalização

3. 🔬 ANÁLISE PROFUNDA
   ├─ Visão Geral → KPIs, Top 10 risco e Resumo Executivo
   ├─ Risco & Ameaças → VirusTotal, Shodan, Tor
   ├─ Padrões Temporais → Horários, silêncio, timing
   ├─ Geolocalização → Sub-redes, padrões de vida, geofencing
   ├─ Correlação → Cruzar com outros alvos
   └─ Comportamento → VPN heurístico, confiança de IP

4. 🤖 ANÁLISE AI (OPCIONAL)
   └─ Operacional → Executar Análise AI com Ollama
      └─ Obter segunda opinião sobre seleção de IPs

5. 📄 PRODUÇÃO
   ├── Operacional → Investigativa + Comparação Temporal
   ├─ Relatório → Exportar PDF
   └─ ZIP → Download completo
```

---

## 💡 Dicas para Investigação

### Foque nos IPs Residenciais
IPs com classificação 🏠 **Residencial** são os mais valiosos. Eles indicam Wi-Fi fixo com endereço vinculado a um assinante.

### Atenção ao IPv6
IPs **IPv6** não passam por CGNAT — a identificação do usuário é direta, sem necessidade de porta lógica. A ferramenta prioriza IPv6 automaticamente no módulo investigativo.

### Padrão Noturno = Residencial
Acessos entre **22h e 06h** usando IP residencial são fortes indicadores de uso doméstico (casa do investigado).

### VPN Não é Necessariamente Criminosa
Muitas pessoas usam VPN por privacidade. Porém, o **padrão** de uso importa: se o alvo alterna entre IPs residenciais e VPN, os residenciais vazam a localização real.

### CGNAT: Não Esqueça a Porta
Para IPs IPv4 móveis (4G/5G), ao requisitar dados à operadora, inclua sempre a **porta lógica** junto com o IP e o horário. Sem a porta, a operadora pode não conseguir individualizar o usuário.

### Use a Correlação Cruzada
Se tiver dados de **múltiplos alvos**, use a página de **Correlação** para encontrar IPs compartilhados — pode revelar que duas pessoas usam a mesma rede Wi-Fi.

### Verifique a Saúde dos Dados
Antes de fazer qualquer análise, cheque a seção **Saúde dos Dados** na página **Operacional** para garantir que o dataset tem cobertura suficiente de IP, geolocalização e datas.

### Use o Assistente AI
Na página **Operacional**, o Assistente AI (Ollama) oferece uma segunda opinião sobre a seleção de IPs. Ele opera 100% offline — dados investigativos nunca saem da máquina.

---

## ❓ Perguntas Frequentes (FAQ)

**P: Preciso de internet para usar a ferramenta?**
R: Sim, para a consulta de geolocalização (IP-API) e verificação de ameaças (VirusTotal, AbuseIPDB, Shodan). Porém, com o **Modo Offline**, você pode carregar um CSV já enriquecido e usar todas as análises sem internet. O Assistente AI também funciona 100% offline via Ollama local.

**P: Os dados saem da minha máquina?**
R: Depende da funcionalidade usada. Os IPs e metadados correlatos podem ser enviados para APIs externas de geolocalização/reputação, como IP-API, VirusTotal, AbuseIPDB e Shodan. Se houver API Key configurada, ela acompanha a requisição; no caso da IP-API paga, a chave vai no parâmetro `?key=`. Já o Assistente AI via Ollama roda localmente e não envia dados para a nuvem por padrão. Os resultados processados pelo app ficam salvos localmente.

**P: O geofencing está rejeitando minha busca.**
R: Verifique se as coordenadas do centro estão dentro dos limites válidos (latitude: -90 a 90, longitude: -180 a 180) e não são (0, 0) — esta coordenada (Null Island) é rejeitada por ser um erro comum.

**P: O Ollama não conecta.**
R: Verifique: (1) Ollama está instalado (`ollama --version`), (2) o serviço está ativo (`ollama serve`), (3) a URL está correta nas Configurações (padrão: `http://localhost:11434`), (4) o modelo foi baixado (`ollama pull qwen3.5:4b`), (5) o botão **Teste de Inferência** responde com sucesso. O fato de o Ollama não aparecer no `requirements.txt` não é, por si só, um erro.

**P: O processamento está lento.**
R: Considere: (1) usar API paga do IP-API (sem rate limit; o sistema envia até 5 batches concorrentes de 100 IPs = 500 IPs simultâneos), (2) ativar o cache para evitar reconsultas, (3) usar o tier Lite do AI (modelo menor), (4) reduzir o número de IPs por processamento.

**P: Posso usar com dados de mais de uma plataforma ao mesmo tempo?**
R: Sim. Processe cada fonte separadamente com o mesmo nome de alvo e ative o modo **incremental** — os novos IPs serão adicionados ao resultado existente.

**P: Preciso instalar alguma biblioteca Python extra para usar o Ollama?**
R: **Não para este projeto.** O aplicativo usa a biblioteca `requests`, já presente nas dependências, para acessar o serviço local do Ollama por HTTP. O que precisa estar instalado separadamente é o próprio runtime do Ollama e pelo menos um modelo local.

**P: Os mapas exigem aceleração 3D ou WebGL avançado?**
R: **Não.** A experiência principal do produto está em Leaflet/Folium 2D. Se o mapa não carregar, normalmente o problema está ligado ao navegador, ao bloqueio de scripts embutidos ou a dados sem latitude/longitude válidos, e não à falta de suporte 3D.

---

*Log Enrichment v5.2 Pro — Mapa 2D investigativo com Leaflet/Folium e assistente AI local via Ollama*.
