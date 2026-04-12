"""
Log Enrichment - Módulo de Auditoria Forense
Cadeia de custódia digital: logging estruturado, hashing de integridade,
rastreabilidade de operações para uso em contexto policial/jurídico.
"""

import json
import hashlib
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

AUDIT_LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, 'audit_trail.jsonl')


def _compute_hash(data):
    """Computa SHA-256 de dados (string, bytes ou dict)."""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True, default=str)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _compute_file_hash(filepath):
    """Computa SHA-256 de um arquivo."""
    if not filepath or not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def log_audit_event(action, details=None, user=None, input_file=None,
                    output_file=None, record_count=None):
    """
    Registra evento de auditoria no log forense (append-only JSONL).

    Args:
        action: Tipo de ação (ex: 'PROCESS_START', 'PROCESS_COMPLETE', 'EXPORT')
        details: Detalhes adicionais (dict)
        user: Identificador do operador
        input_file: Arquivo de entrada processado
        output_file: Arquivo de saída gerado
        record_count: Número de registros processados
    """
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)

    event = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'user': user or os.getenv('USERNAME', os.getenv('USER', 'unknown')),
        'hostname': os.getenv('COMPUTERNAME', os.getenv('HOSTNAME', 'unknown')),
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

    # Hash do próprio evento para integridade da cadeia
    event['event_hash'] = _compute_hash(event)

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
    Verifica integridade do log de auditoria.
    Recalcula hashes de cada evento e compara com o registrado.

    Returns:
        dict com 'total', 'valid', 'invalid', 'details'
    """
    events = get_audit_trail(limit=10000)
    result = {'total': len(events), 'valid': 0, 'invalid': 0, 'details': []}

    for i, event in enumerate(events):
        stored_hash = event.pop('event_hash', None)
        recalculated = _compute_hash(event)
        event['event_hash'] = stored_hash  # restore

        if stored_hash == recalculated:
            result['valid'] += 1
        else:
            result['invalid'] += 1
            result['details'].append({
                'index': i,
                'timestamp': event.get('timestamp'),
                'action': event.get('action'),
                'stored_hash': stored_hash,
                'recalculated_hash': recalculated,
            })

    return result
