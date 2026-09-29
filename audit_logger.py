"""
Log Enrichment - Módulo de Auditoria Forense
Cadeia de custódia digital: logging estruturado, hashing de integridade,
rastreabilidade de operações para uso em contexto policial/jurídico.
"""

import json
import hashlib
import hmac
import os
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

AUDIT_LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, 'audit_trail.jsonl')
AUDIT_HMAC_SECRET = os.getenv('AUDIT_HMAC_SECRET', '').strip()

# Ler o `prev_hash`, anexar o evento e podar o arquivo precisam ser uma coisa
# só: duas sessões do Streamlit (threads do mesmo processo) liam o mesmo
# último hash e gravavam dois eventos com o mesmo `prev_hash` — uma quebra de
# cadeia fabricada pela concorrência. Reentrante porque o arquivamento grava o
# seu próprio evento de checkpoint.
_LOCK = threading.RLock()

CHECKPOINT_ACTION = 'RETENTION_CHECKPOINT'


def _compute_hash(data):
    """Computa SHA-256 de dados (string, bytes ou dict)."""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True, default=str)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _compute_hmac(event_hash: str):
    """Optional HMAC-SHA256 over event_hash when AUDIT_HMAC_SECRET is set."""
    if not AUDIT_HMAC_SECRET or not event_hash:
        return None
    return hmac.new(
        AUDIT_HMAC_SECRET.encode('utf-8'),
        event_hash.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def _compute_file_hash(filepath):
    """Computa SHA-256 de um arquivo."""
    if not filepath or not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _last_event_hash():
    """Return hash of the last audit event for chain linking, or None."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return None
    try:
        last = None
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last:
            return json.loads(last).get('event_hash')
    except (OSError, ValueError):
        # O próximo evento sai sem `prev_hash` e a verificação acusa a quebra
        # — o problema fica visível, não mascarado.
        logger.exception("Não foi possível ler prev_hash do audit trail")
    return None


def log_audit_event(action, details=None, user=None, input_file=None,
                    output_file=None, record_count=None):
    """
    Registra evento de auditoria no log forense (append-only JSONL).
    Cada evento inclui prev_hash (hash do evento anterior) para cadeia de integridade.
    """
    with _LOCK:
        return _log_audit_event_locked(action, details, user, input_file,
                                       output_file, record_count)


def _log_audit_event_locked(action, details, user, input_file, output_file, record_count):
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)

    event = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user or os.getenv('USERNAME', os.getenv('USER', 'unknown')),
        'hostname': os.getenv('COMPUTERNAME', os.getenv('HOSTNAME', 'unknown')),
        'prev_hash': _last_event_hash(),
    }

    if details:
        event['details'] = details
    if input_file:
        event['input_file'] = os.path.basename(input_file)
        event['input_hash'] = _compute_file_hash(input_file)
    if output_file:
        event['output_file'] = os.path.basename(output_file)
        event['output_hash'] = _compute_file_hash(output_file)
    if record_count is not None:
        event['record_count'] = record_count

    event['event_hash'] = _compute_hash(event)
    event_hmac = _compute_hmac(event['event_hash'])
    if event_hmac:
        event['event_hmac'] = event_hmac

    line = json.dumps(event, ensure_ascii=False, default=str) + '\n'
    # `_persisted` é anexado DEPOIS de serializar: não faz parte do evento
    # gravado nem do hash. Diz ao chamador se o evento chegou ao disco —
    # antes, uma falha de escrita ia só para o log e o evento voltava como se
    # tivesse sido registrado.
    try:
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
        logger.info(f"Audit: {action} | hash={event['event_hash'][:12]}")
        event['_persisted'] = True
    except (OSError, TypeError, ValueError):
        logger.exception("Erro ao registrar evento de auditoria %s", action)
        event['_persisted'] = False

    return event


def generate_integrity_receipt(input_file, output_file, alvo, record_count,
                               processing_params=None):
    """
    Gera recibo de integridade do processamento.

    Retorna dict com hashes e metadados que servem como prova de integridade.
    """
    receipt = {
        'generated_at': datetime.now().isoformat(),
        'alvo': alvo,
        'record_count': record_count,
        'input_file': os.path.basename(input_file) if input_file else None,
        'input_hash': _compute_file_hash(input_file),
        'output_file': os.path.basename(output_file) if output_file else None,
        'output_hash': _compute_file_hash(output_file),
        'operator': os.getenv('USERNAME', os.getenv('USER', 'unknown')),
        'hostname': os.getenv('COMPUTERNAME', os.getenv('HOSTNAME', 'unknown')),
    }

    if processing_params:
        receipt['parameters'] = processing_params

    # Hash final do recibo
    receipt['receipt_hash'] = _compute_hash(receipt)

    event = log_audit_event('INTEGRITY_RECEIPT', details=receipt, input_file=input_file,
                            output_file=output_file, record_count=record_count)
    # Chave privada (fora do hash, não exibida): permite ao chamador avisar
    # que o recibo não entrou no audit trail.
    receipt['_audit_event'] = event

    return receipt


def archive_old_events(max_age_days, max_lines):
    """Retenção do audit trail SEM quebrar a cadeia de custódia.

    Os eventos podados vão, inalterados, para `audit_trail.<data>.jsonl`; o
    arquivo ativo mantém os demais byte a byte; e um evento
    RETENTION_CHECKPOINT encadeado registra o arquivamento, o sha256 dele e o
    hash do último evento arquivado (a âncora que `verify_audit_integrity`
    aceita como predecessor do primeiro evento ativo).

    Antes, a retenção reescrevia o arquivo e a verificação seguinte acusava
    adulteração no primeiro evento que sobrou.
    """
    from pathlib import Path
    from helpers.retention import prune_jsonl_by_age_and_lines

    with _LOCK:
        r = prune_jsonl_by_age_and_lines(Path(AUDIT_LOG_FILE), max_age_days=max_age_days,
                                         max_lines=max_lines)
        archive = r.get('archive')
        if r.get('removed') and archive:
            evento = log_audit_event(CHECKPOINT_ACTION, details={
                'archive_file': os.path.basename(archive),
                'archive_sha256': _compute_file_hash(archive),
                'archived_count': r['removed'],
                'anchor_hash': r.get('anchor_hash'),
            })
            r['checkpoint_persisted'] = evento.get('_persisted', False)
        return r


def count_audit_events():
    """Total de linhas de evento no audit trail ativo (sem carregar o JSON)."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return 0
    with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
        return sum(1 for line in f if line.strip())


def get_audit_trail(limit=100):
    """
    Lê os últimos N eventos do log de auditoria.

    Returns:
        Lista de dicts com eventos de auditoria.
    """
    if not os.path.exists(AUDIT_LOG_FILE):
        return []

    events = []
    try:
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logger.error(f"Erro ao ler trail de auditoria: {e}")
        return []

    return events[-limit:]


def _checkpoint_anchors(events):
    """{anchor_hash: detalhes} declarados por eventos RETENTION_CHECKPOINT."""
    anchors = {}
    for _, event in events:
        if event.get('action') == CHECKPOINT_ACTION:
            det = event.get('details') or {}
            if det.get('anchor_hash'):
                anchors[det['anchor_hash']] = det
    return anchors


def verify_audit_integrity():
    """
    Verifica integridade do log de auditoria:
    - recalcula event_hash de cada evento
    - valida prev_hash contra o event_hash do evento anterior (quando presente)
    - valida event_hmac quando AUDIT_HMAC_SECRET está configurado

    Lê o arquivo INTEIRO: com `limit=10000`, acima de 10 mil eventos o
    primeiro da janela tinha `prev_hash` e acusava quebra de cadeia falsa.
    Linha que não é JSON válido conta como inválida — antes era pulada.

    Retenção: o primeiro evento do arquivo ativo aponta para o último
    evento arquivado. Isso é aceito se, e somente se, um RETENTION_CHECKPOINT
    do próprio arquivo declarar esse hash como âncora; se o arquivo de
    arquivamento existir, o sha256 dele também é conferido.
    """
    events = []
    corrupt = []
    if os.path.exists(AUDIT_LOG_FILE):
        with open(AUDIT_LOG_FILE, 'r', encoding='utf-8') as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append((lineno, json.loads(line)))
                except json.JSONDecodeError as exc:
                    corrupt.append((lineno, str(exc)))

    result = {
        'total': len(events) + len(corrupt),
        'valid': 0,
        'invalid': len(corrupt),
        'chain_breaks': 0,
        'hmac_failures': 0,
        'checkpoints': 0,
        'archive_failures': 0,
        'archives_missing': 0,
        'details': [{'line': ln, 'error': f'JSON inválido: {msg}'} for ln, msg in corrupt],
    }

    anchors = _checkpoint_anchors(events)
    for det in anchors.values():
        result['checkpoints'] += 1
        archive = os.path.join(AUDIT_LOG_DIR, os.path.basename(det.get('archive_file') or ''))
        if not det.get('archive_file') or not os.path.exists(archive):
            result['archives_missing'] += 1
        elif _compute_file_hash(archive) != det.get('archive_sha256'):
            result['archive_failures'] += 1
            result['invalid'] += 1
            result['details'].append({'archive_file': det.get('archive_file'),
                                      'error': 'sha256 do arquivamento não confere'})

    prev_hash = None
    for i, (lineno, event) in enumerate(events):
        stored_hash = event.pop('event_hash', None)
        stored_hmac = event.pop('event_hmac', None)
        event_prev = event.get('prev_hash')
        recalculated = _compute_hash(event)
        event['event_hash'] = stored_hash  # restore
        if stored_hmac is not None:
            event['event_hmac'] = stored_hmac

        ok = stored_hash == recalculated
        chain_ok = True
        # Only enforce chain when prev_hash field is present (new events)
        if 'prev_hash' in event:
            if i == 0:
                chain_ok = event_prev in (None, '') or event_prev in anchors
            else:
                chain_ok = event_prev == prev_hash
            if not chain_ok:
                result['chain_breaks'] += 1

        hmac_ok = True
        if AUDIT_HMAC_SECRET and stored_hmac:
            expected = _compute_hmac(stored_hash or '')
            hmac_ok = bool(expected) and hmac.compare_digest(stored_hmac, expected)
            if not hmac_ok:
                result['hmac_failures'] += 1
        elif AUDIT_HMAC_SECRET and stored_hash and not stored_hmac:
            # Secret configured but event predates HMAC — do not fail hard
            hmac_ok = True

        if ok and chain_ok and hmac_ok:
            result['valid'] += 1
        else:
            result['invalid'] += 1
            result['details'].append({
                'index': i,
                'line': lineno,
                'timestamp': event.get('timestamp'),
                'action': event.get('action'),
                'stored_hash': stored_hash,
                'recalculated_hash': recalculated,
                'chain_ok': chain_ok,
                'hmac_ok': hmac_ok,
            })
        prev_hash = stored_hash

    return result
