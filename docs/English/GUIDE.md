# 📘 User Guide — Log Enrichment v5.2 Pro

## Index

1. [Understanding IP Types](#-understanding-ip-types)
2. [Why does this matter for investigation?](#-why-does-this-matter-for-investigation)
3. [How the tool identifies each type](#-how-the-tool-identifies-each-type)
4. [Main Features](#-main-features)
5. [Recommended Workflow](#-recommended-workflow)
6. [Investigation Tips](#-investigation-tips)
7. [Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)

---

## ⚠️ Important Notice on Confidentiality and External Services

Before using the tool with real data, consider that it may handle **IPs, ports, timestamps, ASN/provider, approximate location, and other metadata** extracted from records of **Google, WhatsApp, Meta, Discord, TikTok**, and access providers. These elements may be **sensitive, protected by confidentiality**, and subject to specific legal and institutional rules.

When the app queries **IP-API, VirusTotal, AbuseIPDB, or Shodan**, the processed identifiers are sent to **third-party external services**. If an **API Key** is configured, this authentication accompanies the request.

Use the tool with the same caution as a forensic system:
- validate the legal basis and operational necessity before submitting real data;
- minimize the volume of indicators sent to third parties;
- prefer controlled environments and test data when validating workflows;
- remember that **Ollama** runs locally, but the reputation and geolocation integrations depend on external traffic when enabled.

---

## 🌐 Understanding IP Types

### Residential IP
The IP assigned by the home internet provider. Typically stable for long periods if the provider does not use CGNAT.

### Mobile IP
Assigned by the mobile carrier. More dynamic and may change between cell towers.

### Proxy / VPN
IP belonging to a VPN or proxy service. Indicates the user may be hiding their real IP.

### Datacenter / Hosting
IP belonging to a cloud or hosting provider (AWS, OVH, DigitalOcean, etc.). Unusual for regular user access.

---

## 🔄 Recommended Workflow

1. **Upload** the file in the Data Input page
2. **Process** with the "Start Processing" button
3. **Review** results in the Results tab
4. **Analyze** statistics, map, and advanced analysis
5. **Generate** PDF report
6. **Export** in the desired format (CSV, Excel, JSON, KML, GeoJSON)

---

## ❓ Frequently Asked Questions (FAQ)

**Q: Is an API key required?**
A: No, the tool works with the free IP-API (45 req/min). A paid key removes rate limits, enables HTTPS, and sends up to 5 concurrent batches of 100 IPs (500 IPs simultaneously).

**Q: Is data sent to the cloud?**
A: Enrichment queries are sent to external APIs when enabled. The AI assistant (Ollama) runs locally.

**Q: What file formats are supported?**
A: TXT, CSV, XLSX, XLS, PDF, HTML, HTM — with automatic format detection for WhatsApp, Meta, Google, Discord, TikTok, and generic IP lists.
