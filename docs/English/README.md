# Log Enrichment v5.2 Pro

> 🇧🇷 [Português](../Portuguese/README.md) · 🇪🇸 [Español](../Spanish/README.md)

Professional tool for extraction, forensic analysis, and enrichment of IP addresses in access logs and telematic interception, using multiple intelligence sources (IP-API, VirusTotal, AbuseIPDB).

## 📋 Description

**Log Enrichment** is a web application (Streamlit) that automates the analysis of access logs and WhatsApp telematic interception. It extracts IP addresses from various formats, queries geolocation and reputation APIs via **batch endpoint** (up to 100 IPs per request), and generates complete reports with charts, maps, interactive graphs, and executive summaries.

## ⚠️ Sensitive Data Warning

> **Attention:** this tool may process **IP addresses, logical ports, connection times, approximate location, ASN/provider, and related metadata** obtained from platform and service records such as **Google, WhatsApp, Meta, Discord**, and access providers. In many contexts, this data may be **sensitive, confidential, or legally protected**.
>
> When you enable enrichment or reputation queries with an **API Key**, part of this data is sent to **third-party external services** such as **IP-API, VirusTotal, AbuseIPDB, and Shodan**, according to the configuration used.
>
> **Before processing real data:** verify your legal basis, institutional policy, chain of custody, and operational necessity. Whenever possible, use a controlled environment, minimize the set sent to third parties, and prefer local/offline flows when external queries are not indispensable.

## ✨ Features

### Access Log Enrichment
- **10 Input Formats**: Generic, Meta Platforms, WhatsApp, Google, Preservation Google, Discord (PDF), CSV/Excel, HTML WhatsApp, HTML Meta Platforms, HTML Google
- **Batch API**: Queries up to 100 IPs per request via POST `/batch`
- **Async rDNS**: Parallel reverse DNS resolution for all IPs
- **Automatic Format Detection**: Automatically identifies log type
- **Preview**: View detected IPs before processing
- **Incremental Processing**: Add new IPs to existing files

### Statistics Dashboard
- Summary cards, activity trends, provider spotlight, connection mix, temporal heatmap, top recurring IPs

### 🗺️ Geolocation Map (Leaflet / Folium)
Five visualization modes: Markers, Clusters, Heatmap, Temporal Route, Investigative View

### PDF Report
- General summary, top providers, anomalies, recurring IPs, embedded charts

### Advanced Analysis (7 dedicated pages)
- **Overview**: KPIs, risk scores, executive summary
- **Risk & Threats**: Risk score, VirusTotal, AbuseIPDB, Shodan, Tor exit nodes
- **Temporal Patterns**: Hourly analysis, digital silence, timezone validation
- **Geolocation**: Geo history, subnets, life patterns (DBSCAN clustering)
- **Correlation**: Cross-target correlation, shared WiFi, relay chains
- **Behavior**: VPN/proxy heuristic detection, IP confidence, disposable numbers
- **Operational**: Investigative analysis, temporal comparison, data health

### 🔍 Investigative Analysis
Specialized module for police investigative use with IPv6 priority, temporal anchors, investigative scoring (0-100), and AI assistant.

### 🌐 Multilingual Support
- Interface available in **Portuguese**, **English**, and **Spanish**
- Language selector in the sidebar for real-time switching
- Documentation available in all three languages under `docs/`

## 🛠️ Installation

### Prerequisites
- Python 3.10+ (3.11 recommended)
- pip

### Steps

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
streamlit run app.py
```

The application will open automatically at `http://localhost:8501`.

## 📁 Project Structure

```
Log_Enrichment/
├── app.py                         # Config, auth, navigation, language selector
├── i18n.py                        # Internationalization module
├── locales/                       # Translation files
│   ├── pt.json                    # Portuguese (reference)
│   ├── en.json                    # English
│   └── es.json                    # Spanish
├── docs/                          # Translated documentation
│   ├── Portuguese/
│   ├── English/
│   └── Spanish/
├── pages_app/                     # UI pages (multipage Streamlit)
├── styles/                        # Centralized design system
├── helpers/                       # Shared functions
├── components/                    # Reusable visual components
├── tests/                         # Automated test suite (167+ tests)
└── ...
```

## 🧪 Tests

```bash
python -m pytest tests -v
```

**167+ automated tests** organized in `tests/` by domain.

## 📜 License

This project is distributed under the MIT license. See `LICENSE` for the full text.

## 👨‍💻 Author

**Developed by TWalking with AI assistance**
