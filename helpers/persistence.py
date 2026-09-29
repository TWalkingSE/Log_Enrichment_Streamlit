"""
Optional disk persistence for enriched DataFrames outside Streamlit session_state.
Prefers parquet (pyarrow/fastparquet); falls back to pickle.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import pandas as pd

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "data" / "sessions"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# Versão do esquema das sessões persistidas. Incrementar sempre que a forma do
# DataFrame mudar de maneira que uma versão anterior não saiba interpretar
# (colunas renomeadas, mudança de dtype, semântica alterada).
#
# v2: coerção de booleanos corrigida — 'Ip_Proxy'/'Ip_Movel'/'Ip_Hospedagem'
#     gravados por versões <= v1 podem conter '1'/'0' ou 'VERDADEIRO' que
#     aquelas versões liam como False.
SCHEMA_VERSION = 2


def _safe_name(name: str) -> str:
    cleaned = _SAFE_NAME.sub("_", (name or "current").strip())[:80]
    return cleaned or "current"


def session_paths(name: str = "current") -> dict:
    base = DATA_DIR / _safe_name(name)
    return {
        "parquet": base.with_suffix(".parquet"),
        "pickle": base.with_suffix(".pkl"),
        "meta": base.with_suffix(".meta.json"),
    }


def _sha256_file(path: Path) -> Optional[str]:
    """SHA-256 do arquivo de dados — proveniência: prova que o que se
    carrega é byte-a-byte o que foi gravado, e denuncia arquivo trocado."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logger.warning("Não foi possível hashear %s: %s", path, exc)
        return None


def _write_meta(meta_path: Path, df: pd.DataFrame, data_path: str) -> None:
    """Grava o manifesto da sessão ao lado do parquet."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "rows": int(len(df)),
        "columns": [str(c) for c in df.columns],
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "data_file": os.path.basename(data_path),
        "sha256": _sha256_file(Path(data_path)),
    }
    try:
        tmp = meta_path.with_suffix(".json.part")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, meta_path)
    except OSError as exc:
        logger.warning("Não foi possível gravar metadados da sessão: %s", exc)


def read_meta(name: str = "current") -> Optional[dict]:
    """Manifesto da sessão persistida, ou None se ausente/ilegível."""
    meta_path = session_paths(name)["meta"]
    if not meta_path.exists():
        return None
    try:
        with open(meta_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("Metadados ilegíveis em %s: %s", meta_path, exc)
        return None


def _check_schema(meta_path: Path, name: str) -> List[str]:
    """Confere o manifesto da sessão; devolve os avisos para a interface.

    Sessões antigas continuam sendo carregadas — recusá-las inutilizaria dados
    de investigações em andamento —, mas divergências de esquema, manifesto
    ilegível e sha256 que não confere são devolvidos ao chamador. Antes iam só
    para o log: "possível adulteração" nunca chegava ao analista.
    """
    avisos: List[str] = []
    if not meta_path.exists():
        return avisos
    try:
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.exception("Manifesto ilegível em %s", meta_path)
        avisos.append(f"Manifesto da sessão ilegível ({exc}): a integridade do "
                      "arquivo restaurado NÃO pôde ser conferida.")
        return avisos
    versao = meta.get("schema_version")
    if versao is not None and versao != SCHEMA_VERSION:
        logger.warning(
            "Sessão '%s' foi gravada com schema v%s, mas esta versão usa v%d. "
            "Reprocesse o arquivo original se as classificações parecerem inconsistentes.",
            name, versao, SCHEMA_VERSION)
        avisos.append(f"Sessão gravada com schema v{versao} (atual: v{SCHEMA_VERSION}). "
                      "Reprocesse o arquivo original se as classificações parecerem "
                      "inconsistentes.")
    # Proveniência: o arquivo de dados precisa ser byte-a-byte o que o
    # manifesto declara — divergência = arquivo trocado ou corrompido.
    sha_meta = meta.get("sha256")
    data_file = meta.get("data_file")
    if sha_meta and data_file:
        data_path = meta_path.parent / data_file
        if data_path.exists():
            atual = _sha256_file(data_path)
            if atual and atual != sha_meta:
                logger.warning(
                    "Sessão '%s': arquivo de dados diverge do manifesto "
                    "(sha256 esperado %s, atual %s) — possível adulteração "
                    "ou gravação interrompida.", name, sha_meta[:12], atual[:12])
                avisos.append(
                    f"O arquivo da sessão restaurada diverge do manifesto (sha256 "
                    f"esperado {sha_meta[:12]}…, atual {atual[:12]}…): possível "
                    "adulteração ou gravação interrompida. Reprocesse o arquivo original.")
    return avisos


def save_dataframe(df: Optional[pd.DataFrame], name: str = "current") -> Optional[str]:
    """Persist DataFrame; returns path written or None."""
    if df is None or getattr(df, "empty", True):
        return None
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    paths = session_paths(name)
    try:
        # Escrita atômica: to_parquet direto no destino deixa um arquivo
        # truncado se o processo morrer no meio, e o load cairia num .pkl
        # possivelmente de outra execução.
        tmp = paths["parquet"].with_suffix(".parquet.part")
        df.to_parquet(tmp, index=False)
        os.replace(tmp, paths["parquet"])
        # O parquet é agora a fonte da verdade; um .pkl antigo só serviria
        # para ser servido silenciosamente como se fosse atual.
        try:
            paths["pickle"].unlink(missing_ok=True)
        except OSError:
            pass
        _write_meta(paths["meta"], df, str(paths["parquet"]))
        logger.info("DataFrame salvo em %s (%s linhas, schema v%d)",
                    paths["parquet"], len(df), SCHEMA_VERSION)
        return str(paths["parquet"])
    except Exception as e:
        logger.warning("Parquet indisponível (%s); usando pickle", e)
        try:
            # Mesma garantia atômica do parquet: um pickle truncado por falha
            # no meio da gravação era servido depois como se fosse válido.
            tmp = paths["pickle"].with_suffix(".pkl.part")
            df.to_pickle(tmp)
            os.replace(tmp, paths["pickle"])
            _write_meta(paths["meta"], df, str(paths["pickle"]))
            logger.info("DataFrame salvo em %s (%s linhas)", paths["pickle"], len(df))
            return str(paths["pickle"])
        except Exception:
            logger.exception("Falha ao persistir DataFrame")
            return None


def load_dataframe(name: str = "current") -> Optional[pd.DataFrame]:
    """Load last persisted DataFrame if present.

    Avisos de integridade do manifesto vão em
    `df.attrs['persistence_warnings']` para a interface exibi-los.
    """
    paths = session_paths(name)
    avisos = _check_schema(paths["meta"], name)
    df: Optional[pd.DataFrame] = None
    if paths["parquet"].exists():
        try:
            df = pd.read_parquet(paths["parquet"])
        except Exception as e:
            # Não cair para o pickle aqui: ele pode ser de outro alvo ou de uma
            # execução anterior, e entregar dado obsoleto apresentado como atual
            # é pior do que não entregar dado nenhum numa análise pericial.
            logger.error("Falha ao ler parquet %s: %s", paths["parquet"], e)
            raise
    elif paths["pickle"].exists():
        try:
            df = pd.read_pickle(paths["pickle"])
        except Exception:
            logger.exception("Falha ao ler pickle %s", paths["pickle"])
    if df is not None:
        df.attrs['persistence_warnings'] = avisos
    return df


def clear_dataframe(name: str = "current") -> None:
    paths = session_paths(name)
    for p in paths.values():
        try:
            if p.exists():
                p.unlink()
        except OSError as e:
            logger.warning("Não foi possível remover %s: %s", p, e)
