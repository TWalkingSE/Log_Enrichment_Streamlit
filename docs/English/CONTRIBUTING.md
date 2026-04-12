# Contributing

## Scope

Contributions are welcome for bug fixes, hardening, tests, documentation, and incremental improvements. Major architectural changes should be discussed beforehand via issue.

## Local Environment

```bash
python -m venv venv
pip install -r requirements.txt
python -m pytest tests -q
```

On Windows PowerShell, activate the environment with `venv\Scripts\Activate.ps1` before running the commands.

## Practical Rules

- Do not publish secrets, sensitive data, or `.env` files.
- Preserve the project's current style and prefer small, focused changes.
- Update `README.md`, `GUIA.md`, or examples when public behavior changes.
- Include or adjust tests when the change alters observable behavior.
- Avoid committing generated artifacts in `logs/`, `output/`, and `cache_backups/`.
- **i18n**: When adding new user-facing strings, add the corresponding key to all three locale files (`locales/pt.json`, `locales/en.json`, `locales/es.json`).

## Pull Requests

Before opening a PR, confirm:

- The `pytest tests -q` suite passed.
- The application still starts with `streamlit run app.py`.
- Changed files do not introduce missing dependencies.
- The PR description explains the problem, solution, and any operational impact.
