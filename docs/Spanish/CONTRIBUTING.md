# Contribuyendo

## Alcance

Las contribuciones son bienvenidas para correcciones de bugs, hardening, tests, documentación y mejoras incrementales. Cambios grandes de arquitectura deben ser discutidos antes vía issue.

## Ambiente Local

```bash
python -m venv venv
pip install -r requirements.txt
python -m pytest tests -q
```

En Windows PowerShell, active el ambiente con `venv\Scripts\Activate.ps1` antes de ejecutar los comandos.

## Reglas Prácticas

- No publique secretos, datos sensibles o archivos `.env`.
- Preserve el estilo actual del proyecto y prefiera cambios pequeños y enfocados.
- Actualice `README.md`, `GUIA.md` o ejemplos cuando el comportamiento público cambie.
- Incluya o ajuste tests cuando el cambio altere el comportamiento observable.
- Evite commitear artefactos generados en `logs/`, `output/` y `cache_backups/`.
- **i18n**: Al agregar nuevas strings visibles al usuario, agregue la clave correspondiente en los tres archivos de locale (`locales/pt.json`, `locales/en.json`, `locales/es.json`).

## Pull Requests

Antes de abrir un PR, confirme:

- La suite `pytest tests -q` pasó.
- La aplicación aún inicia con `streamlit run app.py`.
- Los archivos alterados no introducen dependencias faltantes.
- La descripción del PR explica el problema, la solución y cualquier impacto operacional.
