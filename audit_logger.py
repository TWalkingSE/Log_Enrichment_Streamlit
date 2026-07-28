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
from datetime import datetime

logger = logging.getLogger(__name__)

AUDIT_LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, 'audit_trail.jsonl')
AUDIT_HMAC_SECRET = os.getenv('AUDIT_HMAC_SECRET', '').strip()


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
    except Exception as e:
        logger.warning(f"Não foi possível ler prev_hash do audit trail: {e}")
    return None


def log_audit_event(action, details=None, user=None, input_file=None,
                    output_file=None, record_count=None):
    """
    Registra evento de auditoria no log forense (append-only JSONL).
    Cada evento inclui prev_hash (hash do evento anterior) para cadeia de integridade.
    """
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

    try:
        with open(AUDIT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event, ensure_ascii=False, default=str) + '\n')
        logger.info(f"Audit: {action} | hash={event['event_hash'][:12]}")
    except Exception as e:
        logger.error(f"Erro ao registrar auditoria: {e}")

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

    log_audit_event('INTEGRITY_RECEIPT', details=receipt, input_file=input_file,
                    output_file=output_file, record_count=record_count)

    return receipt


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


def verify_audit_integrity():
    """
    Verifica integridade do log de auditoria:
    - recalcula event_hash de cada evento
    - valida prev_hash contra o event_hash do evento anterior (quando presente)
    - valida event_hmac quando AUDIT_HMAC_SECRET está configurado
    """
    events = get_audit_trail(limit=10000)
    result = {
        'total': len(events),
        'valid': 0,
        'invalid': 0,
        'chain_breaks': 0,
        'hmac_failures': 0,
        'details': [],
    }

    prev_hash = None
    for i, event in enumerate(events):
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
                chain_ok = event_prev in (None, '')
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
                'timestamp': event.get('timestamp'),
                'action': event.get('action'),
                'stored_hash': stored_hash,
                'recalculated_hash': recalculated,
                'chain_ok': chain_ok,
                'hmac_ok': hmac_ok,
            })
        prev_hash = stored_hash

    return result
