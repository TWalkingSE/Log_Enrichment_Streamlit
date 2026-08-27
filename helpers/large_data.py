"""
Guarda-corpos para datasets grandes.

Princípio: numa ferramenta pericial, **toda truncagem é visível**. Nada é
omitido em silêncio — se a interface mostra uma parte dos dados, ela diz
quantos registros existem no total.

Segundo princípio: trabalho pesado (exports, grafos, análises que varrem o
DataFrame inteiro) **nunca roda implicitamente num rerun**. O Streamlit
reexecuta o script inteiro a cada interação — inclusive o corpo de abas que
não estão visíveis — e serializar centenas de MB a cada tecla digitada é o
que derruba o websocket com `WebSocketClosedError`.
"""

import hashlib
import logging

import streamlit as st

logger = logging.getLogger(__name__)

# Acima deste número de linhas, trabalho pesado exige clique explícito.
LARGE_ROW_THRESHOLD = 50_000
# Linhas exibidas numa prévia truncada.
PREVIEW_ROWS = 1_000
# Acima deste tamanho o Excel colorido é gerado em disco, com progresso, em vez
# de virar dezenas de MB de bytes em cache de sessão trafegando pelo websocket.
# O teto por aba do formato XLSX vive em `file_handler.XLSX_SHEET_ROWS` — aqui
# só mora a política de interface, para este módulo não arrastar o pipeline
# inteiro para dentro do import de `app.py`.
XLSX_DISK_THRESHOLD = 50_000
# Tetos de renderização do grafo de rede.
MAX_GRAPH_NODES = 500
MAX_GRAPH_EDGES = 5_000


def row_count(df) -> int:
    """Número de linhas, tolerante a None."""
    try:
        return 0 if df is None else len(df)
    except TypeError:
        return 0


def is_large(df, threshold: int = LARGE_ROW_THRESHOLD) -> bool:
    return row_count(df) > threshold


def fmt(n) -> str:
    """Formata inteiro no padrão pt-BR: 202128 -> '202.128'."""
    try:
        return '{:,}'.format(int(n)).replace(',', '.')
    except (TypeError, ValueError):
        return str(n)


def truncation_notice(shown: int, total: int, unit: str = 'linhas') -> str:
    return f"Exibindo {fmt(shown)} de {fmt(total)} {unit}."


def show_truncation(shown: int, total: int, unit: str = 'linhas') -> None:
    """Renderiza a legenda de truncagem quando há dados omitidos."""
    if shown < total:
        st.caption(f"⚠️ {truncation_notice(shown, total, unit)} "
                   "Use os filtros para analisar o restante.")
    else:
        st.caption(f"Exibindo {fmt(total)} {unit} (total).")


def data_version() -> int:
    return st.session_state.get('_data_version', 0)


def bump_data_version() -> None:
    """Invalida os portões e preparos quando o dataset muda.

    Sem isso, o analista carrega um novo alvo e continua vendo o resultado
    já liberado do alvo anterior.
    """
    st.session_state['_data_version'] = data_version() + 1
    stale = [k for k in st.session_state
             if isinstance(k, str) and (k.startswith('_gate_') or k.startswith('_prep_'))]
    for key in stale:
        del st.session_state[key]
    if stale:
        logger.info("large_data: %d portões invalidados por troca de dataset", len(stale))


def cache_key(*parts) -> str:
    """Chave de cache curta e barata, derivada da versão dos dados.

    Serve para não passar o DataFrame como argumento hasheado ao
    `st.cache_data` — o Streamlit hasheia os bytes do frame a cada rerun,
    mesmo quando há acerto de cache.
    """
    raw = '|'.join([str(data_version())] + [str(p) for p in parts])
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


def gate(label: str, df, key: str, *, threshold: int = LARGE_ROW_THRESHOLD,
         help: str = None) -> bool:
    """True quando o trabalho pesado pode rodar.

    Datasets pequenos rodam implicitamente (UX inalterada). Datasets grandes
    exigem um clique — e uma vez liberado, permanece liberado até o dataset
    mudar.
    """
    n = row_count(df)
    if n <= threshold:
        return True
    flag = f"_gate_{key}"
    if st.session_state.get(flag):
        return True
    st.info(f"Dataset grande — {fmt(n)} linhas. "
            "Esta análise não roda automaticamente para preservar memória.")
    if st.button(label, key=f"btn_gate_{key}", help=help):
        st.session_state[flag] = True
        st.rerun()
    return False


def prepare_button(label: str, df, key: str, *,
                   threshold: int = LARGE_ROW_THRESHOLD,
                   help: str = None) -> bool:
    """Portão em dois estágios para downloads.

    `st.download_button` exige os bytes prontos no momento da renderização,
    então não há como gerá-los preguiçosamente. Em datasets grandes o fluxo
    passa a ser: "Preparar X" -> rerun -> botão de download real.
    """
    n = row_count(df)
    if n <= threshold:
        return True
    flag = f"_prep_{key}"
    if st.session_state.get(flag):
        return True
    if st.button(label, key=f"btn_prep_{key}",
                 help=help or f"{fmt(n)} linhas — gerado sob demanda"):
        st.session_state[flag] = True
        st.rerun()
    return False


def estimate_xlsx_seconds(n_linhas: int, n_colunas: int = 15) -> int:
    """Estimativa grosseira do tempo de geração do Excel colorido.

    Calibrada em 200 mil linhas x 15 colunas = 120 s no modo write_only. Serve
    só para o texto de ajuda do botão: sem ela o analista clica em "Preparar
    Excel", espera dois minutos sem retorno visual e conclui que travou.
    """
    try:
        return max(1, int(int(n_linhas) * max(int(n_colunas), 1) * 4e-5))
    except (TypeError, ValueError):
        return 1


def fmt_duracao(segundos) -> str:
    """'~2 min' / '~45 s', para o texto de ajuda dos botões de preparo."""
    try:
        segundos = int(segundos)
    except (TypeError, ValueError):
        return "?"
    if segundos < 90:
        return f"~{segundos} s"
    return f"~{round(segundos / 60)} min"
