"""Isola os dados de caso durante a suíte de testes.

`logs/audit_trail.jsonl` é a cadeia de custódia de casos reais. Testes que
chamavam `log_audit_event` e `generate_integrity_receipt` sem desviar o
caminho anexavam `test_action` e recibos de `test_target` nela a cada
execução — dezenas de eventos de teste entremeados com os de casos. O trail
não é reescrito (a cadeia de hash é a prova), então o que já entrou fica; o
que se evita é entrar mais.

Antes do primeiro teste, audit trail, sessões persistidas, histórico e cache
de IPs passam a apontar para um temporário da sessão de testes. No fim, a
sessão acusa erro se algum desses arquivos reais tiver mudado — um teste
novo que escape do desvio aparece na hora, não semanas depois no trail.
"""
import os
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parent.parent

# Dados de caso que a suíte nunca pode alterar.
_ARQUIVOS_REAIS = [
    _RAIZ / 'logs' / 'audit_trail.jsonl',
    _RAIZ / 'ip_cache.json',
    _RAIZ / 'processing_history.json',
]
_DIRETORIOS_REAIS = [
    _RAIZ / 'data' / 'sessions',
]


def _assinatura():
    """(tamanho, mtime) de cada arquivo real — sem ler o conteúdo."""
    estado = {}
    for arquivo in _ARQUIVOS_REAIS:
        if arquivo.exists():
            st = arquivo.stat()
            estado[str(arquivo)] = (st.st_size, st.st_mtime_ns)
    for diretorio in _DIRETORIOS_REAIS:
        if diretorio.is_dir():
            for caminho in diretorio.rglob('*'):
                if caminho.is_file():
                    st = caminho.stat()
                    estado[str(caminho)] = (st.st_size, st.st_mtime_ns)
    return estado


@pytest.fixture(scope='session', autouse=True)
def _isolar_dados_de_caso(tmp_path_factory):
    import api_client
    import audit_logger
    import helpers.persistence as persistence
    import helpers.shared as shared

    tmp = tmp_path_factory.mktemp('dados_de_caso')
    antes = _assinatura()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(audit_logger, 'AUDIT_LOG_DIR', str(tmp / 'logs'))
        mp.setattr(audit_logger, 'AUDIT_LOG_FILE', str(tmp / 'logs' / 'audit_trail.jsonl'))
        mp.setattr(persistence, 'DATA_DIR', tmp / 'sessions')
        mp.setattr(shared, 'HISTORY_FILE', str(tmp / 'processing_history.json'))
        mp.setattr(api_client, 'IP_CACHE_PATH', str(tmp / 'ip_cache.json'))
        yield tmp
    depois = _assinatura()
    alterados = sorted(p for p in set(antes) | set(depois) if antes.get(p) != depois.get(p))
    if alterados:
        # Com o app rodando ao mesmo tempo, um evento legítimo também muda o
        # trail; nesse caso, rode a suíte com o app fechado para confirmar.
        raise AssertionError(
            'A suíte alterou dados de caso reais (nenhum teste pode gravar neles): '
            + ', '.join(os.path.relpath(p, _RAIZ) for p in alterados))
