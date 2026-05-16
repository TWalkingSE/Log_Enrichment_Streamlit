# Security Policy

> [English](docs/English/SECURITY.md) · [Español](docs/Spanish/SECURITY.md)

## Supported Versions

O foco de correções de segurança é a branch principal e a versão mais recente publicada no GitHub.

## Reporting a Vulnerability

Não abra uma issue pública para relatar vulnerabilidades.

Use um canal privado do mantenedor ou, se o repositório estiver com GitHub Security Advisories habilitado, abra um reporte privado por lá. No reporte, inclua:

- impacto observado
- passos mínimos de reprodução
- versão ou commit afetado
- dependências relevantes
- evidências sanitizadas, sem dados sigilosos

## Response Expectations

- Confirmação inicial: até 5 dias úteis
- Triagem inicial: até 10 dias úteis
- Correção ou mitigação: conforme severidade e reprodutibilidade

## Autenticação da aplicação (Streamlit)

A UI usa autenticação **opcional** via `.env`:

- **`AUTH_PASSWORD_HASH` (recomendado):** coloque um hash **Argon2** ou **bcrypt** gerado localmente (passlib). O valor nunca deve ser uma senha em claro.
- **Legado:** um hash **SHA-256** em hexadecimal (64 caracteres), da senha em UTF-8, ainda é aceito para compatibilidade; a comparação usa `secrets.compare_digest`.
- **`AUTH_PASSWORD`:** senha em texto plano no `.env` — só para desenvolvimento; comparação via digest SHA-256 com comparação em tempo constante. **Não use em produção.**

Gerar hash Argon2 para colar no `.env` (substitua `sua_senha` ou use prompt interativo):

```bash
python -c "from passlib.hash import argon2; print(argon2.hash(input('Senha: ')))"
```

Ou, com o script do repositório:

```bash
python scripts/gen_auth_password_hash.py
```

## Scope Notes

Este projeto processa dados potencialmente sensíveis. Ao reportar problemas:

- remova IPs reais, identificadores pessoais e credenciais
- não anexe arquivos de produção sem sanitização
- descreva o contexto operacional apenas no nível necessário para reproduzir