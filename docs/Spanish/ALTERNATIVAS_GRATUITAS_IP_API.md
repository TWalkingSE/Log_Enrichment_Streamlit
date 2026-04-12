# Alternativas Gratuitas a la API ip-api.com para Enriquecimiento de Datos IP

> Esta es una traducción resumida del documento original en portugués. Para el análisis técnico completo, vea la [versión en portugués](../Portuguese/ALTERNATIVAS_GRATUITAS_IP_API.md).

## Introducción

El proyecto actual usa ip-api.com como fuente principal de enriquecimiento de IP. En la práctica, el flujo ya está adaptado para recibir campos como `country`, `countryCode`, `regionName`, `city`, `org`, `isp`, `as`, `mobile`, `proxy`, `hosting`, `lat` y `lon`, y convertirlos al contrato interno del sistema.

Cuando surge la necesidad de buscar una alternativa gratuita, la pregunta correcta no es solo "¿cuál API gratuita consulta más?", sino "¿cuál API gratuita entrega datos suficientemente compatibles con lo que el sistema ya usa hoy?"

**En resumen**: existen alternativas con límites más flexibles que la versión gratuita de ip-api.com, pero ninguna es sustitución perfecta sin adaptación.

## Resumen Ejecutivo

| Alternativa | Uso gratuito sin registro | Uso gratuito con registro | Adherencia al proyecto | Principal trade-off |
| --- | --- | --- | --- | --- |
| IPinfo Lite | No es el modelo principal; normalmente requiere token | Ilimitado, sin límite diario/mensual documentado | Baja | Solo entrega país, continente y ASN básico en el gratuito |
| ipwho.is / ipwhois.io | 1 req/seg, máx 60 por ventana de 60 seg, sin límite mensual, solo backend | Sin beneficio gratuito documentado por registro | Media | Buena geografía, pero con restricciones y sin equivalencia de capa de seguridad |
| MaxMind GeoLite | No es práctico sin cuenta/licencia | Hasta 1000 lookups/día por web service, 30 descargas de base/día | Media | Mejor para uso local/offline, pero integración menos directa |
| IP2Location.io | 1000 consultas/día en modo sin key | 50 mil consultas geo/mes en plan Free | Media-alta | Mejor ajuste HTTP con registro, pero plan gratuito no repone todas las señales investigativas |

## Comparación de Cuotas Gratuitas con Registro

- **IPinfo Lite**: Uso ilimitado, sin límite diario/mensual documentado. Endpoint batch acepta hasta 1000 IPs por llamada.
- **ipwho.is / ipwhois.io**: 1 solicitud por segundo por IP cliente, máximo 60 solicitudes en cualquier ventana de 60 segundos, sin límite mensual documentado.
- **MaxMind GeoLite**: Requiere cuenta y license key. GeoLite gratuito permite hasta 1000 consultas web service/día. Consultas locales dependen de su infraestructura.
- **IP2Location.io**: Sin registro: 1000 consultas/día. Con cuenta gratuita: 50 mil consultas geo/mes. Mejor elevación de cuota entre opciones de API HTTP simple.

## Recomendación

Para este proyecto, el camino más práctico cuando la cuota gratuita de ip-api.com es insuficiente:

1. **Registrarse en IP2Location.io Free** — 50K consultas/mes con buena cobertura de campos
2. **Descargar MaxMind GeoLite2 DB** — para enriquecimiento offline/local sin límites de cuota
3. **Mantener ip-api.com como primario** — el plan pago ($15/mes) ofrece consultas HTTPS ilimitadas y sigue siendo la opción más compatible

El plan pago de ip-api.com continúa siendo el mejor costo-beneficio para uso investigativo dada la integración existente.
