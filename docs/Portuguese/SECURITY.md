# Security Policy

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


## Controles de segurança implementados

Ver tabela completa em [`SECURITY.md`](../../SECURITY.md) na raiz (CSV injection, XSS, path sandbox, audit chain/HMAC, cache assinado, air-gapped, retenção). Deploy: [`DEPLOY.md`](../DEPLOY.md).

## Scope Notes

Este projeto processa dados potencialmente sensíveis. Ao reportar problemas:

- remova IPs reais, identificadores pessoais e credenciais
- não anexe arquivos de produção sem sanitização
- descreva o contexto operacional apenas no nível necessário para reproduzir