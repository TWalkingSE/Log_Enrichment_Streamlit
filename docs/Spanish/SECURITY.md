# Política de Seguridad

## Versiones Soportadas

El enfoque de correcciones de seguridad es la branch principal y la versión más reciente publicada en GitHub.

## Reportando una Vulnerabilidad

No abra una issue pública para reportar vulnerabilidades.

Use un canal privado del mantenedor o, si el repositorio tiene GitHub Security Advisories habilitado, abra un reporte privado allí. En el reporte, incluya:

- Impacto observado
- Pasos mínimos de reproducción
- Versión o commit afectado
- Dependencias relevantes
- Evidencias sanitizadas, sin datos confidenciales

## Expectativas de Respuesta

- Confirmación inicial: hasta 5 días hábiles
- Triaje inicial: hasta 10 días hábiles
- Corrección o mitigación: según severidad y reproducibilidad

## Autenticación de la aplicación (Streamlit)

Autenticación **opcional** vía `.env`:

- **`AUTH_PASSWORD_HASH` (recomendado):** hash **Argon2** o **bcrypt** generado localmente. Los hashes de versiones anteriores (con `passlib`) siguen siendo válidos.
- **SHA-256 legado (64 caracteres hex): ya no se acepta** desde la v5.4 — sin sal, es rápido de atacar por fuerza bruta. La pantalla de login lo explica y bloquea el acceso hasta regenerar el hash.
- **`AUTH_PASSWORD`:** texto plano — solo desarrollo.

```bash
python -c "from auth_password import hash_password; print(hash_password(input('Contraseña: ')))"
```

O el script del repositorio:

```bash
python scripts/gen_auth_password_hash.py
```

## Notas de Alcance

Este proyecto procesa datos potencialmente sensibles. Al reportar problemas:

- Remueva IPs reales, identificadores personales y credenciales
- No adjunte archivos de producción sin sanitización
- Describa el contexto operacional solo al nivel necesario para reproducir

## Controles de seguridad implementados

CSV injection, XSS, path sandbox, cadena de audit + HMAC, caché firmado, air-gapped, auth Argon2, logs rotativos, retención. Ver [DEPLOY.md](../DEPLOY.md) y [AUDITORIA_TECNICA.md](../AUDITORIA_TECNICA.md).
