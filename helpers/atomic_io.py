"""
Escrita atômica em disco: arquivo temporário no mesmo diretório + `os.replace`.

O padrão truncar-e-escrever (`open(path, 'w')` + dump) apaga o arquivo ANTES
de escrever: uma falha no meio deixa JSON inválido e o carregamento seguinte
começa do zero sem avisar ninguém — já destruiu o cache de IPs inteiro.

Sem `streamlit` de propósito: é usado pelo pipeline headless
(`scripts/enrich_worker.py`) e pelo cliente da API.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import IO, Any, Callable

logger = logging.getLogger(__name__)


def atomic_write(path: str | os.PathLike[str], write_fn: Callable[[IO[Any]], Any],
                 mode: str = 'w', **open_kwargs: Any) -> None:
    """Escreve via temporário + `os.replace` (atômico em NTFS e POSIX).

    `write_fn` recebe o handle aberto em `mode`. Em qualquer falha o
    temporário é removido e o arquivo original permanece intacto.
    """
    target = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(target)) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.tmp_cache_', suffix='.part')
    os.close(fd)
    try:
        with open(tmp, mode, **open_kwargs) as f:
            write_fn(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                logger.exception("Falha ao remover o temporário %s", tmp)


def atomic_write_text(path: str | os.PathLike[str], text: str, encoding: str = 'utf-8') -> None:
    atomic_write(path, lambda f: f.write(text), mode='w', encoding=encoding)


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    atomic_write(path, lambda f: f.write(data), mode='wb')


def atomic_write_json(path: str | os.PathLike[str], obj: Any, **dump_kwargs: Any) -> None:
    atomic_write(path, lambda f: json.dump(obj, f, **dump_kwargs), mode='w', encoding='utf-8')
