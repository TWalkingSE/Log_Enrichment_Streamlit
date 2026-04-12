# 📘 Guía del Usuario — Log Enrichment v5.2 Pro

## Índice

1. [Entendiendo los Tipos de IP](#-entendiendo-los-tipos-de-ip)
2. [¿Por qué importa en la investigación?](#-por-qué-importa-en-la-investigación)
3. [Cómo la herramienta identifica cada tipo](#-cómo-la-herramienta-identifica-cada-tipo)
4. [Funcionalidades Principales](#-funcionalidades-principales)
5. [Flujo de Trabajo Recomendado](#-flujo-de-trabajo-recomendado)
6. [Consejos para Investigación](#-consejos-para-investigación)
7. [Preguntas Frecuentes (FAQ)](#-preguntas-frecuentes-faq)

---

## ⚠️ Aviso Importante sobre Confidencialidad y Servicios Externos

Antes de usar la herramienta con datos reales, considere que puede manipular **IPs, puertos, horarios, ASN/proveedor, ubicación aproximada y otros metadatos** extraídos de registros de **Google, WhatsApp, Meta, Discord** y proveedores de acceso. Estos elementos pueden ser **sensibles, protegidos por confidencialidad** y sujetos a reglas legales e institucionales específicas.

Cuando la app consulta **IP-API, VirusTotal, AbuseIPDB o Shodan**, los identificadores procesados se envían a **servicios externos de terceros**.

Use la herramienta con la misma cautela de un sistema pericial:
- valide la base legal y la necesidad operacional antes de enviar datos reales;
- minimice el volumen de indicadores enviados a terceros;
- prefiera ambientes controlados y datos de prueba al validar flujos;
- recuerde que **Ollama** corre localmente, pero las integraciones de reputación y geolocalización dependen de tráfico externo cuando están habilitadas.

---

## 🌐 Entendiendo los Tipos de IP

### IP Residencial
El IP asignado por el proveedor de internet doméstico. Normalmente estable por largos períodos si el proveedor no usa CGNAT.

### IP Móvil
Asignado por el operador móvil. Más dinámico y puede cambiar entre torres celulares.

### Proxy / VPN
IP perteneciente a un servicio de VPN o proxy. Indica que el usuario puede estar ocultando su IP real.

### Datacenter / Hosting
IP perteneciente a un proveedor de nube o hosting (AWS, OVH, DigitalOcean, etc.). Inusual para acceso de usuario regular.

---

## 🔄 Flujo de Trabajo Recomendado

1. **Suba** el archivo en la página Entrada de Datos
2. **Procese** con el botón "Iniciar Procesamiento"
3. **Revise** resultados en la pestaña Resultados
4. **Analice** estadísticas, mapa y análisis avanzado
5. **Genere** informe PDF
6. **Exporte** en el formato deseado (CSV, Excel, JSON, KML, GeoJSON)

---

## ❓ Preguntas Frecuentes (FAQ)

**P: ¿Se necesita una API key?**
R: No, la herramienta funciona con la API gratuita de IP-API (45 req/min). Una key paga elimina los límites de tasa, habilita HTTPS y envía hasta 5 batches concurrentes de 100 IPs (500 IPs simultáneos).

**P: ¿Se envían datos a la nube?**
R: Las consultas de enriquecimiento se envían a APIs externas cuando están habilitadas. El asistente AI (Ollama) corre localmente.

**P: ¿Qué formatos de archivo son soportados?**
R: TXT, CSV, XLSX, XLS, PDF, HTML, HTM — con detección automática de formato para WhatsApp, Meta, Google, Discord y listas genéricas de IP.
