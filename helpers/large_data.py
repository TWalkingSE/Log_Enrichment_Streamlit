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
import uuid
from typing import Optional

import streamlit as st

from i18n import t

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

# Resultados calculados sobre o alvo atual que vivem em `session_state` fora
# dos portões. Sem apagá-los na troca de dataset, a página continua exibindo a
# análise de IA, o VirusTotal ou o Tor do alvo ANTERIOR ao lado dos dados novos.
_RESULT_KEYS = (
    'inv_result', 'inv_ai_result', 'ai_result',
    'vt_scores', 'shodan_results', 'shodan_risk', 'tor_result',
    '_xlsx_disco',
)


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


def truncation_notice(shown: int, total: int, unit: Optional[str] = None) -> str:
    return t('guards.showing_of', shown=fmt(shown), total=fmt(total),
             unit=unit or t('guards.unit_rows'))


def show_truncation(shown: int, total: int, unit: Optional[str] = None) -> None:
    """Renderiza a legenda de truncagem quando há dados omitidos."""
    if shown < total:
        st.caption(f"⚠️ {truncation_notice(shown, total, unit)} {t('guards.use_filters')}")
    else:
        st.caption(t('guards.showing_total', total=fmt(total), unit=unit or t('guards.unit_rows')))


def data_version() -> int:
    return st.session_state.get('_data_version', 0)


def data_token() -> str:
    """Identidade aleatória do dataset atual desta sessão.

    `st.cache_data` é global ao processo, e `data_version` recomeça em 0 em
    toda sessão: com ela sozinha, duas sessões com datasets do mesmo tamanho
    compartilhavam entradas de cache — um analista recebia o export do outro.
    """
    token = st.session_state.get('_data_token')
    if not token:
        token = uuid.uuid4().hex
        st.session_state['_data_token'] = token
    return token


def bump_data_version() -> None:
    """Invalida portões, preparos e resultados quando o dataset muda.

    Sem isso, o analista carrega um novo alvo e continua vendo o resultado
    já liberado — ou já calculado — do alvo anterior.
    """
    st.session_state['_data_version'] = data_version() + 1
    st.session_state['_data_token'] = uuid.uuid4().hex
    stale = [k for k in st.session_state
             if isinstance(k, str) and (k.startswith('_gate_') or k.startswith('_prep_'))]
    stale += [k for k in _RESULT_KEYS if k in st.session_state]
    for key in stale:
        del st.session_state[key]
    if stale:
        logger.info("large_data: %d portões/resultados invalidados por troca de dataset",
                    len(stale))


def cache_key(*parts) -> str:
    """Chave de cache curta e barata, derivada da identidade dos dados.

    Serve para não passar o DataFrame como argumento hasheado ao
    `st.cache_data` — o Streamlit hasheia os bytes do frame a cada rerun,
    mesmo quando há acerto de cache. Por isso o chamador precisa passar em
    `parts` tudo o que muda o conteúdo — filtros inclusive: o tamanho do
    frame filtrado não identifica quais linhas ele tem.
    """
    raw = '|'.join([data_token(), str(data_version())] + [str(p) for p in parts])
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


def gate(label: str, df, key: str, *, threshold: int = LARGE_ROW_THRESHOLD,
         help: Optional[str] = None) -> bool:
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
    st.info(t('guards.large_dataset', rows=fmt(n)))
    if st.button(label, key=f"btn_gate_{key}", help=help):
        st.session_state[flag] = True
        st.rerun()
    return False


def prepare_button(label: str, df, key: str, *,
                   threshold: int = LARGE_ROW_THRESHOLD,
                   help: Optional[str] = None) -> bool:
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
                 help=help or t('guards.on_demand', rows=fmt(n))):
        st.session_state[flag] = True
        st.rerun()
    return False


def declare_sheets(resumo) -> None:
    """Declara quantas linhas foram gravadas no Excel e em quantas abas.

    Acima de 1.048.575 linhas o resultado continua em `Resultado (2)`, `(3)`...
    Sem essa legenda o analista abre a planilha, vê a primeira aba cheia e não
    tem como saber que existe continuação.
    """
    if not resumo:
        return
    if resumo.get('abas', 1) > 1:
        st.caption(t('guards.sheets_multi', rows=fmt(resumo['linhas']), sheets=resumo['abas']))
    else:
        st.caption(t('guards.sheets_single', rows=fmt(resumo['linhas'])))


def xlsx_progress_bar():
    """Barra de progresso do Excel em disco e o callback `(feitas, total)`."""
    barra = st.progress(0.0, text=t('guards.xlsx_progress_start'))

    def _progresso(feitas, total):
        barra.progress(min(feitas / max(total, 1), 1.0),
                       text=t('guards.xlsx_progress', done=fmt(feitas), total=fmt(total)))
    return barra, _progresso


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
