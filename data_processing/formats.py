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
COLUNAS_EXTRAS_PROVEDOR = [
    'Porta', 'Evento', 'User_ID', 'Username', 'Email', 'User_Agent'
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
