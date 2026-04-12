
# Alternativas Gratuitas à API ip-api.com para Enriquecimento de Dados de IP

## Introdução

O projeto atual usa a ip-api.com como fonte principal de enriquecimento de IP. Na prática, isso significa que o fluxo já está adaptado para receber campos como `country`, `countryCode`, `regionName`, `city`, `org`, `isp`, `as`, `mobile`, `proxy`, `hosting`, `lat` e `lon`, e convertê-los para o contrato interno usado pelo sistema.

Quando surge a necessidade de buscar uma alternativa gratuita, a primeira armadilha é olhar apenas para a cota. Cota alta ajuda, mas não resolve sozinha. Para este projeto, a pergunta correta não é apenas "qual API gratuita consulta mais?", mas sim "qual API gratuita entrega dados suficientemente compatíveis com o que o sistema já usa hoje?".

Em resumo: existe alternativa com limite mais flexível que a versão gratuita da ip-api.com, mas nenhuma delas é substituição perfeita sem adaptação.

## Resumo Executivo

| Alternativa | Uso gratuito sem cadastro | Uso gratuito com cadastro | Aderência ao projeto atual | Principal trade-off |
| --- | --- | --- | --- | --- |
| IPinfo Lite | Não é o modelo principal de uso; normalmente depende de token | Ilimitado, sem limite diário ou mensal documentado | Baixa | Entrega só país, continente e ASN básico no gratuito |
| ipwho.is / ipwhois.io | 1 requisição por segundo, no máximo 60 por 60 segundos, sem limite mensal documentado, backend-only | Não há ganho gratuito claramente documentado só por cadastro | Média | Boa geografia, mas com restrições de uso e sem equivalência garantida da camada de segurança |
| MaxMind GeoLite | Não é prático sem conta/licença | Até 1000 lookups por dia por web service e 30 downloads de base por dia | Média | Melhor para uso local/offline, mas integração é menos direta e a precisão gratuita é menor |
| IP2Location.io | 1000 consultas por dia no modo keyless | 50 mil consultas de geolocalização por mês no plano Free | Média-alta | Melhor encaixe HTTP com cadastro, mas o plano gratuito ainda não repõe todos os sinais investigativos |

## Quanto é possível consultar com cadastro gratuito

Se a comparação for feita olhando especificamente para "quanto é possível consultar com uma conta gratuita", o cenário fica assim:

- **IPinfo Lite**: todo usuário IPinfo tem acesso ao Lite API com uso ilimitado, sem limite diário ou mensal documentado. Além disso, o endpoint batch aceita até 1000 IPs por chamada.
- **ipwho.is / ipwhois.io**: o endpoint público gratuito continua sendo a principal referência de uso grátis. A documentação informa 1 requisição por segundo por IP cliente, com no máximo 60 requisições em qualquer janela de 60 segundos e sem limite mensal documentado. Não há um benefício gratuito claramente documentado apenas por criar conta.
- **MaxMind GeoLite**: exige conta e license key. No modo web service, a camada GeoLite gratuita permite até 1000 consultas por dia por serviço. Para bases locais, a conta gratuita permite até 30 downloads por dia. Depois que a base é baixada, as consultas locais passam a depender da sua infraestrutura, não de uma cota por request no serviço HTTP.
- **IP2Location.io**: sem cadastro, há modo keyless com até 1000 consultas por dia. Com conta gratuita, o plano Free oferece 50 mil consultas de geolocalização por mês. É a melhor elevação de cota entre as opções aqui comparadas que continuam em um modelo simples de API HTTP.

## 1. IPinfo Lite

### O que oferece

O IPinfo Lite é a opção mais agressiva em volume dentro do recorte gratuito. A documentação pública informa que ele está disponível para todo usuário IPinfo e fornece acesso gratuito com uso ilimitado, entregando dados básicos de geolocalização por país e ASN.

No plano Lite, a resposta inclui, em linhas gerais:

- IP consultado
- ASN
- Nome da organização do ASN
- Domínio associado ao ASN
- País
- Código do país
- Continente
- Código do continente

Também há endpoint batch, com até 1000 IPs por chamada.

### Vantagens

- Excelente para cenários de alto volume.
- Tem contrato simples e previsível.
- ASN e identificação básica de organização continuam disponíveis.
- O batch gratuito melhora bastante a eficiência operacional.

### Desvantagens

- No plano gratuito, não entrega cidade, região, latitude e longitude.
- Não entrega os sinais que hoje alimentam colunas como `Ip_Movel`, `Ip_Proxy` e `Ip_Hospedagem`.
- Para este projeto, a perda funcional é relevante, porque mapa, análise geográfica fina e parte das heurísticas investigativas ficam empobrecidos.

### Quando faz sentido

Faz sentido se o objetivo for reduzir custo e manter apenas enriquecimento básico por país e ASN, aceitando perda importante de profundidade analítica.

## 2. ipwho.is / ipwhois.io

### O que oferece

Entre as alternativas gratuitas sem chave, esta é a que mais se aproxima do formato de uso atual do projeto no quesito geolocalização. A documentação pública informa que o endpoint gratuito não exige API key, não tem limite mensal documentado e aplica limite de 1 requisição por segundo por IP cliente, com teto de 60 requisições em qualquer janela de 60 segundos.

Na resposta pública, aparecem campos como:

- Continente e país
- Região e cidade
- Latitude e longitude
- CEP/postal code
- Timezone
- ASN, organização, ISP e domínio em `connection`

### Vantagens

- Entrega cidade, região, latitude e longitude no endpoint gratuito.
- Usa HTTPS no endpoint público.
- Não depende de chave para integração básica.
- A estrutura cobre boa parte do que o projeto já precisa para análise geográfica e relatórios.

### Desvantagens

- O endpoint gratuito é restrito a uso não comercial.
- O endpoint gratuito deve ser consumido do backend, não diretamente do navegador.
- A estrutura da resposta muda em relação ao contrato atual: por exemplo, `asn`, `org` e `isp` aparecem aninhados em `connection`, e não como campos planos.
- A documentação separa detecção de ameaças e camada de segurança mais robusta como recurso de planos superiores, então não é prudente tratar o gratuito como substituto estável para os indicadores investigativos de `proxy`, `vpn`, `tor` e `hosting`.
- A oferta gratuita não é a melhor para cenários com bursts maiores ou processamento muito concentrado no tempo.

### Quando faz sentido

É a melhor candidata quando a prioridade é preservar cidade, região e coordenadas com uma troca relativamente viável, desde que o uso seja compatível com as restrições do plano gratuito e que a ausência de equivalência total na camada de segurança seja aceitável.

## 3. MaxMind GeoLite / maxmind.com

### O que oferece

A MaxMind oferece a linha **GeoLite** como alternativa gratuita, com dois caminhos de integração: **web services** e **bases locais**. Na camada gratuita, a documentação pública informa **até 1000 lookups por dia por serviço** para os web services GeoLite e também disponibiliza download de bases **GeoLite City**, **GeoLite Country** e **GeoLite ASN** para uso local.

Para usar o ecossistema GeoLite, é necessário criar conta e gerar uma **license key**. Nos web services, a autenticação exige credenciais MaxMind em HTTPS. Para as bases locais, a MaxMind entrega formatos **`.mmdb`** e **CSV**, com atualização autenticada por license key.

Em termos de dados, a linha GeoLite pode fornecer, a depender do serviço ou da base usada:

- País e código do país
- Região e cidade
- CEP/postal code
- Latitude e longitude
- ASN
- Organização do ASN

A própria MaxMind ressalta dois pontos importantes: a geolocalização é uma **área aproximada**, não um endereço exato, e a oferta gratuita **GeoLite City** é consideravelmente menos precisa que a linha paga **GeoIP City**.

### Vantagens

- É um fornecedor maduro e amplamente conhecido no ecossistema de geolocalização por IP.
- Pode entregar cidade, região, latitude, longitude, ASN e organização, preservando parte importante da análise geográfica do projeto.
- Oferece dois modelos úteis: **API/web service** e **base local**, o que abre espaço para uso offline e redução de exposição de dados a terceiros.
- Depois do download da base, a consulta local não depende de cota por request no serviço HTTP.

### Desvantagens

- A integração é menos direta para o projeto atual do que uma API REST simples no estilo ip-api.com.
- O web service gratuito tem **limite diário de 1000 consultas por serviço**, o que pode ser apertado para processamento contínuo.
- A camada gratuita não repõe de forma equivalente os sinais hoje usados em `Ip_Movel`, `Ip_Proxy` e `Ip_Hospedagem`.
- A MaxMind deixa claro que a geolocalização gratuita é aproximada e deve ser interpretada com cuidado.
- Para aproveitar bem o ecossistema MaxMind, o projeto provavelmente precisaria suportar também leitura de base local `.mmdb` ou CSV, o que aumenta a complexidade da integração.

### Quando faz sentido

Faz sentido quando a prioridade é usar uma fonte tradicional de GeoIP, com possibilidade de **uso local/offline**, aceitando que a troca não será transparente e que os sinais de risco do fluxo atual continuarão incompletos na camada gratuita.

## 4. IP2Location.io

### O que oferece

Entre as opções gratuitas com cadastro, o IP2Location.io é a alternativa mais forte para quem quer continuar em um modelo simples de API HTTP, sem migrar o projeto para leitura de base local.

A documentação pública mostra dois modos de uso:

- modo keyless com até 1000 consultas por dia;
- plano Free com cadastro, oferecendo 50 mil consultas de geolocalização por mês.

No exemplo oficial do plano gratuito, a resposta inclui:

- IP consultado
- País e código do país
- Região e cidade
- Latitude e longitude
- CEP
- Timezone
- ASN
- AS
- `is_proxy`

O plano gratuito é posicionado com **11 atributos de IP** e exige **atribuição**. Recursos mais ricos, como ISP, domínio, net speed, uso móvel, classificação de hosting e proxy intelligence mais detalhada, ficam concentrados nos planos superiores.

### Vantagens

- Entrega cidade, região, latitude e longitude no plano gratuito.
- Já fornece ASN, AS e um indicador booleano básico de proxy na camada gratuita.
- O formato é mais próximo de uma integração HTTP simples do que o modelo baseado em base local da MaxMind.
- A cota de 50 mil consultas por mês com cadastro gratuito é bastante prática para uso recorrente.
- Entre as opções gratuitas com conta, é a melhor candidata para um adapter relativamente direto no projeto atual.

### Desvantagens

- O plano gratuito não repõe integralmente os sinais hoje usados em `Ip_Movel`, `Ip_Hospedagem` e na camada mais rica de risco.
- O exemplo gratuito não inclui `isp` nem `domain`, então parte da compatibilidade com o contrato atual ainda ficaria incompleta.
- Há diferença de nomes de campos em relação ao contrato atual, então ainda seria necessário adapter de normalização.
- O plano gratuito exige atribuição.
- A detecção avançada de proxy, VPN, Tor, datacenter e mobile data está concentrada em planos superiores.

### Quando faz sentido

Faz sentido quando a prioridade é manter uma integração por API HTTP com boa geolocalização, ASN e um sinal básico de proxy, aceitando que a compatibilidade com o contrato atual ainda será parcial e exigirá adaptação.

## Aviso Técnico Importante: a troca não é trivial

Trocar a API aqui é menos como trocar uma lâmpada e mais como trocar um chicote elétrico: o objetivo continua o mesmo, mas os conectores mudam de posição.

Hoje, o projeto espera um contrato interno relativamente estável, com colunas como:

- `Ip_Dono`
- `Ip_AS`
- `Ip_Regiao`
- `Ip_Cidade`
- `Ip_Pais`
- `Ip_Pais_Codigo`
- `Ip_Movel`
- `Ip_Proxy`
- `Ip_Hospedagem`
- `Ip_Lat`
- `Ip_Lon`

A integração atual converte a resposta da ip-api.com para esse formato. O problema é que as alternativas gratuitas não entregam exatamente o mesmo conjunto de dados:

- O IPinfo Lite perde cidade, região e coordenadas.
- O ipwho.is preserva bem a parte geográfica, mas a documentação gratuita não oferece equivalência contratual segura para a mesma camada de segurança investigativa.
- O MaxMind GeoLite preserva boa parte da geografia e do ASN, mas exige adaptação maior de integração e também não repõe os mesmos sinais de risco.
- O IP2Location.io é o que mais se aproxima de uma troca prática por API HTTP com cadastro gratuito, mas ainda não repõe de forma equivalente os indicadores de móvel, hospedagem e inteligência mais rica de risco.

Ou seja: trocar a API sem criar uma camada de adaptação produziria quebra funcional, dados vazios ou indicadores analíticos distorcidos.

## Impactos no projeto atual

Uma mudança de provedor afetaria diretamente os seguintes pontos:

- `api_client.py`: precisaria ser refeito para autenticação, URL, tratamento de erro, rate limit, parsing de resposta e normalização de campos.
- `data_processor.py`, `file_handler.py` e `interception_parser.py`: dependem do contrato interno estar completo e consistente, inclusive nos valores padrão quando um campo não existe.
- `validators.py`: valida latitude, longitude e tipos booleanos; qualquer mudança de schema precisaria preservar esse comportamento.
- `advanced_analysis.py`, `ip_investigativo.py` e `ai_assistant.py`: usam provedor, cidade, país, proxy, hospedagem e coordenadas para métricas, score, filtros e explicações analíticas.
- Relatórios, mapas e exportações: sem latitude e longitude, a experiência visual perde precisão; sem proxy e hosting, parte dos alertas investigativos perde força.

Em termos práticos, uma migração bem feita exigiria:

- criação de uma camada de adapter por provedor;
- manutenção de um schema interno fixo, independente da API externa;
- definição explícita de fallback para campos ausentes;
- atualização dos testes para cenários degradados;
- revisão das heurísticas que hoje assumem a existência de `Ip_Proxy` e `Ip_Hospedagem`.

## Conclusão

Se o critério principal for volume gratuito, o **IPinfo Lite** é o mais vantajoso, mas também o mais limitado em profundidade de dados.

Se o critério principal for usar uma API pública simples, sem chave e sem limite mensal documentado, o **ipwho.is** continua sendo a opção mais direta, com a ressalva importante de uso não comercial, limite por segundo e camada de segurança incompleta para o nível de análise que este projeto espera.

Se a necessidade for uma alternativa gratuita mais tradicional, com opção de uso local e boa cobertura geográfica básica, o **MaxMind GeoLite** é tecnicamente interessante, especialmente para cenários offline, mas não deve ser tratado como substituto transparente da ip-api.com sem refatoração da camada de integração.

Se o critério principal for encontrar a melhor alternativa gratuita com cadastro, ainda no modelo de API HTTP e com boa aderência ao fluxo atual, o **IP2Location.io** passa a ser a melhor candidata entre as opções analisadas. Ele não é um drop-in replacement, mas é o que entrega a combinação mais equilibrada entre cota, geografia detalhada e compatibilidade prática de integração.

Para este projeto, a conclusão técnica mais honesta continua sendo direta: não existe hoje, entre essas opções gratuitas, uma troca totalmente transparente para a ip-api.com. A estratégia correta não é substituir endpoint por endpoint, e sim introduzir uma abstração de provedor, manter um contrato interno estável e aceitar que algumas capacidades talvez precisem ser degradadas ou migradas para plano pago.