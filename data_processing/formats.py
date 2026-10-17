"""Colunas do modelo, colunas de export por plataforma e exemplos de formato.

Separado de `data_processor` (que continua sendo a fachada pública). Os
`FORMATO_*` são os exemplos que a página de Entrada oferece em "Carregar
exemplo" — e que os testes usam como fixture.
"""

# Padrão regex de IP reutilizável (IPv4 + IPv6)
IP_REGEX_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6}):?(?::[0-9a-fA-F]{1,4}){1,7}'

# Definição das colunas do modelo (interno, inclui Lat/Lon para mapa)
COLUNAS_MODELO = [
    'Alvo', 'Ip', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade', 'Ip_Pais', 'Ip_Pais_Codigo',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Periodo', 'ISO_Date'
]

# Colunas para exportação (com Lat/Lon para mapa de geolocalização)
COLUNAS_EXPORT = [
    'Alvo', 'Ip', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação TikTok (com Evento)
COLUNAS_EXPORT_TIKTOK = [
    'Alvo', 'Ip', 'Evento', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas extras específicas de cada provedor, inseridas logo após 'Ip' na saída.
# Coluna que não está aqui nem em COLUNAS_MODELO é descartada por
# `processar_resultados` depois do enriquecimento.
COLUNAS_EXTRAS_PROVEDOR = [
    'Porta', 'Evento', 'User_ID', 'Username', 'Email', 'User_Agent',
    # Google Aggregated Activities (conexões, depois serviços)
    'Vinculado_Tipo', 'Vinculado_Valor', 'Primeiro_Uso', 'Ultimo_Uso',
    'Dias_Ativos_Google', 'Dias_Corridos', 'Canal_Autenticacao', 'Multilogin',
]

# Colunas para exportação Meta Platforms (com Porta lógica)
COLUNAS_EXPORT_META = [
    'Alvo', 'Ip', 'Porta', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação Preservation Google (com User_Agent)
COLUNAS_EXPORT_PRESERVATION_GOOGLE = [
    'Alvo', 'Ip', 'User_Agent', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Colunas para exportação Discord (com User_ID, Username e Email)
COLUNAS_EXPORT_DISCORD = [
    'Alvo', 'Ip', 'User_ID', 'Username', 'Email', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Google Aggregated Activities — serviços: uma linha por IP com o intervalo
# agregado que o Google informa. `Data` repete o último uso: é a coluna que as
# análises leem.
COLUNAS_EXPORT_GOOGLE_ATIVIDADES = [
    'Alvo', 'Ip', 'Primeiro_Uso', 'Ultimo_Uso', 'Dias_Ativos_Google', 'Dias_Corridos',
    'Canal_Autenticacao', 'Multilogin', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Google Aggregated Activities — conexões: uma linha por par IP ↔ identificador
# visto junto na mesma sessão, com a janela daquele par.
COLUNAS_EXPORT_GOOGLE_CONEXOES = [
    'Alvo', 'Ip', 'Vinculado_Tipo', 'Vinculado_Valor', 'Primeiro_Uso', 'Ultimo_Uso',
    'Dias_Corridos', 'Data', 'Data_Fuso', 'Ip_Dono', 'Ip_AS',
    'Ip_Regiao', 'Ip_Cidade',
    'Ip_Movel', 'Ip_Proxy',
    'Ip_Hospedagem', 'Ip_Tor', 'Ip_Lat', 'Ip_Lon', 'Reputação', 'Periodo', 'ISO_Date'
]

# Formatos cujas linhas são intervalos agregados, não acessos — e que nunca se
# misturam com outro resultado no mesmo arquivo de saída.
FAMILIAS_GOOGLE_AGREGADO = ('google_atividades', 'google_conexoes')


def familia_formato(colunas):
    """Formato de um resultado, deduzido das colunas extras que ele carrega.

    A ordem é a de precedência: as colunas dos formatos agregados do Google são
    exclusivas deles e vêm primeiro; depois a precedência que o pipeline já
    usava (Discord, Preservation Google, TikTok, Meta).
    """
    nomes = set(getattr(colunas, 'columns', colunas))
    if 'Vinculado_Tipo' in nomes:
        return 'google_conexoes'
    if 'Dias_Ativos_Google' in nomes:
        return 'google_atividades'
    if 'User_ID' in nomes:
        return 'discord'
    if 'User_Agent' in nomes:
        return 'preservation_google'
    if 'Evento' in nomes:
        return 'tiktok'
    if 'Porta' in nomes:
        return 'meta'
    return 'padrao'


_EXPORT_POR_FAMILIA = {
    'google_conexoes': COLUNAS_EXPORT_GOOGLE_CONEXOES,
    'google_atividades': COLUNAS_EXPORT_GOOGLE_ATIVIDADES,
    'discord': COLUNAS_EXPORT_DISCORD,
    'preservation_google': COLUNAS_EXPORT_PRESERVATION_GOOGLE,
    'tiktok': COLUNAS_EXPORT_TIKTOK,
    'meta': COLUNAS_EXPORT_META,
    'padrao': COLUNAS_EXPORT,
}


def colunas_export_para(colunas):
    """Conjunto de colunas de export do formato de `colunas` (DataFrame ou lista).

    Lista completa do formato; quem exporta um frame filtra pelo que existe.
    Um ponto só para o pipeline e para a tabela de Resultados — antes cada um
    repetia a cadeia de `if`, e a tabela não conhecia o TikTok.
    """
    return list(_EXPORT_POR_FAMILIA[familia_formato(colunas)])

# Exemplos dos formatos suportados
FORMATO_1 = """Endereços IP
198.51.100.20
2001:db8:18bf:9681:1:0:70f2:df19
2001:db8:1054:5f90:1:2:3be4:cd25
2001:db8:1149:ae06:1796:ad93:296c:cbe4
"""

FORMATO_2 = """Ip Addresses Definition
IP Addresses: IP addresses and source port/port numbers associated with the account.
Ip Addresses
IP Address
198.51.100.10:22859
Time
2025-09-29 11:15:01 UTC
IP Address
[2001:0db8:1354:6500:29a9:2a7f:ee68:d955]:59483
Time
2025-09-21 23:01:39 UTC
"""

FORMATO_3 = """Ip Addresses Definition
IP Addresses: IP addresses an account holder has connected from.
Ip Addresses
Time
2025-12-10 18:58:48 UTC
IP Address
2001:db8:8e90:866e:d4ba:a89a:bcd8:8dc7
Time
2025-12-05 19:35:57 UTC
IP Address
2001:db8:a04d:49b8:97e0:c894:9e09:859c
"""

FORMATO_4 = """GOOGLE SUBSCRIBER INFORMATION

Google Account ID: 1000000000002
Name: Lorem Silva
e-Mail: lorem.silva@example.com

IP ACTIVITY

Timestamp   IP Address  Activity Type   Android ID  Apple iOS IDFV  Raw User Agents
2023-02-25 04:34:32 Z   2001:db8:82ae:6fb1:1:1:b8eb:1d22    Login
2023-02-24 22:54:13 Z   2001:db8:82ae:6fb1:1:1:b8eb:1d22    Login
2023-02-24 17:56:18 Z   198.51.100.18    Login
"""

FORMATO_DISCORD = """User ID:                     1234567890123456789
Username:                    usuario_exemplo#0
Email:                       usuario@example.com
Email verified:              Yes
Phone number:                Not found
Registration IP:             Not found
Registration Time (UTC):     2025-04-29 18:00:50
Last Seen Time (UTC):        2025-05-14 01:43:39
Last Seen IP:                198.51.100.13

Session Start (UTC)    IP Address
2025-05-14 00:47:29    198.51.100.13
2025-05-13 23:55:51    198.51.100.16
2025-05-12 08:46:41    198.51.100.16
2025-05-11 18:07:57    198.51.100.12
2025-05-11 13:56:56    198.51.100.16
"""

FORMATO_PRESERVATION_GOOGLE = """Gaia ID,Activity Timestamp,IP Address,Proxiedhost IP Address,Is Non-routable IP Address,User Agent String,Product Name
100000000001,2026-03-11 02:49:39 UTC,2001:db8:85c1:b496:81e9:9e8e:a396:d027,,No,App : YOUTUBE_APP. App Version : 21.10.2. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,YouTube
100000000001,2026-03-11 02:33:59 UTC,2001:db8:85c1:b496:81e9:9e8e:a396:d027,,No,App : GMAIL_APP. App Version : 6.0.260302. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,Gmail
100000000001,2026-03-11 00:04:30 UTC,198.51.100.14,,No,App : GMAIL_APP. App Version : 6.0.260302.1803824. Os : IOS_OS. Os Version : 26.3. Device Type : MOBILE.,Gmail
"""

FORMATO_TIKTOK = """Events IP Data
Date: 27/07/2026 03:04:43PM (UTC +00)
IP: 203.0.113.45
Event: video_play
Country: Brazil
Date: 27/07/2026 03:04:31PM (UTC +00)
IP: 203.0.113.45
Event: like
Country: Brazil
Date: 27/07/2026 02:48:12PM (UTC +00)
IP: 203.0.113.45
Event: publish
Country: Brazil
"""

# Google Aggregated Activities — os dois CSVs vêm no mesmo pacote e cada um é
# parseado sozinho. Dados sintéticos (GAIA ID de 21 dígitos, IPs de
# documentação); cobrem as armadilhas reais: campo entre aspas com vírgula,
# linhas que não são de IP, intervalo que cruza a meia-noite UTC, `Days Active`
# maior que o intervalo (o Google às vezes informa 2 dias para um único
# instante) e IP em qualquer um dos lados do par.
FORMATO_GOOGLE_ATIVIDADES = """GAIA ID,Last Activity Timestamp,First Activity Timestamp,Days Active,Identifier Type,ID,Multilogin Used,Authentication Channel
100000000000000000001,2025-11-03 01:40:10 UTC,2025-10-15 12:00:00 UTC,15,IP address,2001:db8:5a1e:6400:1:2:3:aa55,NO,
100000000000000000001,2025-11-03 01:40:10 UTC,2024-01-10 08:00:00 UTC,300,User agent,App : SAFARI. Os : IOS_OS. Device Type : MOBILE.,NO,
100000000000000000001,2025-11-02 21:30:00 UTC,2025-05-01 10:00:00 UTC,90,WebGL renderer name,"ANGLE (Exemplo, Placa de Video Exemplo Direct3D11 vs_5_0 ps_5_0, D3D11)",NO,
100000000000000000001,2025-11-01 17:50:00 UTC,2019-01-20 15:00:00 UTC,700,IP address,198.51.100.20,NO,PASSWORD + PASSWORD
100000000000000000001,2025-10-30 22:20:00 UTC,2018-06-05 19:30:00 UTC,800,IP address,198.51.100.21,NO,OAUTH + PASSWORD
100000000000000000001,2025-10-29 23:10:00 UTC,2021-03-10 17:40:00 UTC,1200,Product,SEARCH,NO,
100000000000000000001,2025-10-20 23:35:36 UTC,2025-10-20 23:35:36 UTC,2,IP address,2001:db8:93f7:c75b:1:2:3:f652,NO,
"""

FORMATO_GOOGLE_CONEXOES = """GAIA ID,Last Connection Timestamp,First Connection Timestamp,Identifier Type 1,ID 1,Identifier Type 2,ID 2
100000000000000000001,2025-11-03 01:25:51 UTC,2025-08-02 17:15:15 UTC,SID cookie authentication time,2025-08-02 15:16:39 UTC,OAuth login ID,349
100000000000000000001,2025-11-03 01:25:51 UTC,2025-10-15 20:16:56 UTC,IP address,2001:db8:5a1e:6400:1:2:3:aa55,SID cookie authentication time,2025-08-02 15:16:39 UTC
100000000000000000001,2025-11-02 21:38:11 UTC,2025-10-15 15:12:13 UTC,Font fingerprint,1234567890123456789,IP address,2001:db8:5a1e:6400:1:2:3:aa55
100000000000000000001,2025-11-02 21:38:11 UTC,2025-10-15 15:12:13 UTC,WebGL renderer name,"ANGLE (Exemplo, Placa de Video Exemplo Direct3D11 vs_5_0 ps_5_0, D3D11)",IP address,2001:db8:5a1e:6400:1:2:3:aa55
100000000000000000001,2025-11-02 21:38:11 UTC,2025-10-15 15:12:13 UTC,Screen resolution,Width : 1920. Height : 1080.,IP address,2001:db8:5a1e:6400:1:2:3:aa55
100000000000000000001,2025-10-28 14:55:05 UTC,2025-09-30 15:31:08 UTC,IP address,198.51.100.20,SID cookie authentication time,2025-09-11 00:43:19 UTC
100000000000000000001,2025-09-19 22:12:01 UTC,2025-08-25 15:32:33 UTC,IP address,198.51.100.21,Other device ID,00000000-0000-4000-8000-000000000001
"""
