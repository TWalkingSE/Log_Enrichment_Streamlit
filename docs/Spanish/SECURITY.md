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

- **`AUTH_PASSWORD_HASH` (recomendado):** hash **Argon2** o **bcrypt** generado localmente (passlib).
- **Legado:** digest **SHA-256** hexadecimal (64 caracteres), UTF-8.
- **`AUTH_PASSWORD`:** texto plano — solo desarrollo.

```bash
python -c "from passlib.hash import argon2; print(argon2.hash(input('Contraseña: ')))"
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
