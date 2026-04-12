# Contribuindo

> 🇺🇸 [English](docs/English/CONTRIBUTING.md) · 🇪🇸 [Español](docs/Spanish/CONTRIBUTING.md)

## Escopo

Contribuições são bem-vindas para correções de bugs, hardening, testes, documentação e melhorias incrementais. Mudanças grandes de arquitetura devem ser discutidas antes via issue.

## Ambiente local

```bash
python -m venv venv
pip install -r requirements.txt
python -m pytest tests -q
```

No Windows PowerShell, ative o ambiente com `venv\Scripts\Activate.ps1` antes de rodar os comandos.

## Regras práticas

- Não publique segredos, dados sensíveis ou arquivos `.env`.
- Preserve o estilo atual do projeto e prefira mudanças pequenas e focadas.
- Atualize `README.md`, `GUIA.md` ou exemplos quando o comportamento público mudar.
- Inclua ou ajuste testes quando a mudança alterar comportamento observável.
- Evite commitar artefatos gerados em `logs/`, `output/` e `cache_backups/`.
- **i18n**: Ao adicionar novas strings voltadas ao usuário, adicione a chave correspondente nos 3 arquivos de locale (`locales/pt.json`, `locales/en.json`, `locales/es.json`).

## Pull requests

Antes de abrir um PR, confirme:

- A suíte `pytest tests -q` passou.
- A aplicação ainda sobe com `streamlit run app.py`.
- Os arquivos alterados não introduzem dependências faltantes.
- A descrição do PR explica o problema, a solução e qualquer impacto operacional.