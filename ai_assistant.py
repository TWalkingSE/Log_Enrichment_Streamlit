"""
Log Enrichment - Módulo de Assistente AI para Seleção de IPs
Integração com Ollama (modelos locais) para análise investigativa assistida.
Usa requests para API REST — sem dependência da lib ollama.
"""

import json
import logging
import time
import os
import requests
import pandas as pd
from datetime import datetime
from typing import Optional, Tuple, List

from api_client import is_cgnat_ip
from validators import as_bool, bool_series, parse_data

logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURAÇÃO DE MODELOS POR TIER
# ============================================================

AI_MODELS = {
    "lite": {
        "model": "qwen3.5:4b",
        "label": "Qwen3.5 4B (8GB VRAM)",
        "description": "GPU com 8GB — rápido, boa qualidade",
        "vram": "~3-4 GB",
        "options": {"temperature": 0, "num_ctx": 16384},
    },
    "standard": {
        "model": "qwen3.5:9b-q8_0",
        "label": "Qwen3.5 9B Q8 (16GB VRAM)",
        "description": "RTX 5070 Ti — equilíbrio ideal",
        "vram": "~11 GB",
        "options": {"temperature": 0, "num_ctx": 32768},
    },
    "premium": {
        "model": "qwen3.5:27b-q4_K_M",
        "label": "Qwen3.5 27B Q4 (24GB VRAM)",
        "description": "RTX ADA Generation — máxima qualidade",
        "vram": "~17 GB",
        "options": {"temperature": 0, "num_ctx": 65536},
    },
}

DEFAULT_OLLAMA_URL = "http://localhost:11434"
TIER_ORDER = ("lite", "standard", "premium")

# ============================================================
# PYDANTIC SCHEMAS (structured output)
# ============================================================
try:
    from pydantic import BaseModel, Field

    class IPSelecionado(BaseModel):
        ip: str = Field(description="Endereço IP")
        tipo: str = Field(description="IPv4 ou IPv6")
        data: str = Field(description="Data/hora do registro")
        provedor: str = Field(description="Nome do provedor/ISP")
        score: float = Field(description="Score investigativo (0-100)")
        motivo: str = Field(description="Por que este IP foi selecionado")

    class ProvedorSelecionado(BaseModel):
        nome: str = Field(description="Nome do provedor/ISP")
        registros_total: int = Field(description="Total de registros deste provedor")
        percentual_cobertura: float = Field(description="Percentual do total")
        ips_selecionados: List[IPSelecionado] = Field(description="IPs selecionados (min 3, max 10)")
        justificativa: str = Field(description="Justificativa da seleção")

    class AnaliseAI(BaseModel):
        provedores: List[ProvedorSelecionado] = Field(description="Provedores selecionados (max 3)")
        cobertura_total: float = Field(description="Percentual total coberto")
        resumo_narrativo: str = Field(description="Resumo narrativo (português formal)")
        alertas: List[str] = Field(description="Alertas relevantes")
        confianca: str = Field(description="alta, media ou baixa")
        motivo_confianca: str = Field(description="Justificativa da confiança")

    HAS_PYDANTIC = True
    AI_JSON_SCHEMA = AnaliseAI.model_json_schema()

except ImportError:
    HAS_PYDANTIC = False
    AI_JSON_SCHEMA = {
        "type": "object",
        "properties": {
            "provedores": {"type": "array", "items": {"type": "object"}},
            "cobertura_total": {"type": "number"},
            "resumo_narrativo": {"type": "string"},
            "alertas": {"type": "array", "items": {"type": "string"}},
            "confianca": {"type": "string"},
            "motivo_confianca": {"type": "string"},
        },
        "required": ["provedores", "cobertura_total", "resumo_narrativo", "alertas", "confianca", "motivo_confianca"],
    }


# ============================================================
# LOAD CONFIG
# ============================================================
def _load_ai_config():
    """Carrega configuração AI do analysis_config.json com fallback."""
    config_path = os.path.join(os.path.dirname(__file__), 'analysis_config.json')
    defaults = {
        "default_tier": "lite",
        "ollama_url": DEFAULT_OLLAMA_URL,
        "timeout_seconds": {"lite": 45, "standard": 90, "premium": 180},
        "healthcheck_timeout_seconds": {"lite": 20, "standard": 35, "premium": 60},
        "fallback_to_lighter_model": True,
        "max_ips_in_prompt": 30,
        "max_ips_per_provider_in_prompt": 20,
        "system_prompt_template": None,
    }
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {**defaults, **data.get('ai_assistant', {})}
    except Exception as e:
        logger.warning(f"Erro ao carregar config AI: {e}")
    return defaults


# ============================================================
# OLLAMA STATUS
# ============================================================
def check_ollama_status(base_url: str = DEFAULT_OLLAMA_URL) -> dict:
    """Verifica se o Ollama está rodando e quais modelos estão disponíveis."""
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        models = data.get('models', [])
        return {
            'online': True,
            'models': models,
            'model_names': [m.get('name', '') for m in models],
            'error': None,
        }
    except requests.ConnectionError:
        return {'online': False, 'models': [], 'model_names': [], 'error': 'Ollama não está rodando. Execute: ollama serve'}
    except requests.Timeout:
        return {'online': False, 'models': [], 'model_names': [], 'error': 'Timeout ao conectar ao Ollama'}
    except Exception as e:
        return {'online': False, 'models': [], 'model_names': [], 'error': str(e)}


def check_model_available(model_name: str, base_url: str = DEFAULT_OLLAMA_URL) -> bool:
    """Verifica se um modelo específico está baixado localmente."""
    status = check_ollama_status(base_url)
    if not status['online']:
        return False
    return any(model_name in name for name in status['model_names'])


def get_default_ai_tier() -> str:
    """Retorna o tier padrão configurado, garantindo valor válido."""
    configured_tier = _load_ai_config().get('default_tier', 'lite')
    return configured_tier if configured_tier in AI_MODELS else 'lite'


def _get_timeout_for_model(model_name: str, purpose: str = 'analysis') -> int:
    """Resolve timeout por modelo para análise completa ou healthcheck."""
    config = _load_ai_config()
    if purpose == 'healthcheck':
        default_map = {'lite': 20, 'standard': 35, 'premium': 60}
        timeout_map = {**default_map, **config.get('healthcheck_timeout_seconds', {})}
    else:
        default_map = {'lite': 45, 'standard': 90, 'premium': 180}
        timeout_map = {**default_map, **config.get('timeout_seconds', {})}

    if '27b' in model_name or '32b' in model_name:
        tier = 'premium'
    elif ':4b' in model_name:
        tier = 'lite'
    else:
        tier = 'standard'
    return int(timeout_map.get(tier, default_map['standard']))


def _fallback_tier_order(requested_tier: str) -> list:
    """Retorna ordem de fallback priorizando modelos mais leves quando possível."""
    if requested_tier == 'premium':
        return ['premium', 'standard', 'lite']
    if requested_tier == 'standard':
        return ['standard', 'lite', 'premium']
    return ['lite', 'standard', 'premium']


def _get_available_model_for_tier(tier: str, available_model_names: list):
    """Retorna config do primeiro modelo disponível para um tier."""
    model_info = AI_MODELS.get(tier)
    if not model_info:
        return None
    if any(model_info['model'] in model_name for model_name in available_model_names):
        return model_info
    return None


def test_ollama_inference(model_name: str, base_url: str = DEFAULT_OLLAMA_URL, timeout_seconds: int = None) -> dict:
    """Executa um smoke test de inferência curta no Ollama para validar geração real."""
    status = check_ollama_status(base_url)
    if not status['online']:
        return {
            'success': False,
            'response': None,
            'error': status.get('error', 'Ollama offline'),
            'elapsed_seconds': 0,
            'model_used': model_name,
        }

    if not any(model_name in name for name in status['model_names']):
        return {
            'success': False,
            'response': None,
            'error': f"Modelo '{model_name}' não está instalado localmente.",
            'elapsed_seconds': 0,
            'model_used': model_name,
        }

    url = f"{base_url}/api/generate"
    timeout = timeout_seconds or _get_timeout_for_model(model_name, purpose='healthcheck')
    payload = {
        'model': model_name,
        'prompt': 'Responda apenas OK',
        'stream': False,
        'options': {
            'temperature': 0,
            'num_ctx': 256,
            'num_predict': 8,
        },
    }

    start_time = time.time()
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        content = str(data.get('response', '')).strip()
        if not content:
            return {
                'success': False,
                'response': None,
                'error': 'O modelo respondeu sem conteúdo no teste de inferência.',
                'elapsed_seconds': round(time.time() - start_time, 1),
                'model_used': model_name,
            }

        return {
            'success': True,
            'response': content,
            'error': None,
            'elapsed_seconds': round(time.time() - start_time, 1),
            'model_used': model_name,
        }
    except requests.Timeout:
        return {
            'success': False,
            'response': None,
            'error': f"Timeout ({timeout}s) no teste de inferência. O Ollama está online, mas o modelo demorou para responder.",
            'elapsed_seconds': round(time.time() - start_time, 1),
            'model_used': model_name,
        }
    except requests.ConnectionError:
        return {
            'success': False,
            'response': None,
            'error': 'Falha ao conectar ao endpoint de geração do Ollama.',
            'elapsed_seconds': round(time.time() - start_time, 1),
            'model_used': model_name,
        }
    except requests.HTTPError as exc:
        return {
            'success': False,
            'response': None,
            'error': f"Erro HTTP no teste de inferência: {exc}",
            'elapsed_seconds': round(time.time() - start_time, 1),
            'model_used': model_name,
        }
    except Exception as exc:
        return {
            'success': False,
            'response': None,
            'error': str(exc),
            'elapsed_seconds': round(time.time() - start_time, 1),
            'model_used': model_name,
        }


# ============================================================
# PROMPTS
# ============================================================
SYSTEM_PROMPT_TEMPLATE = """Você é um assistente especializado em análise investigativa de endereços IP para fins de investigação policial no Brasil. Você auxilia investigadores a selecionar os IPs mais relevantes para identificação de usuários junto a provedores de internet.

## SUA METODOLOGIA

Você segue rigorosamente esta metodologia de seleção:

1. PROVEDORES: Selecionar no MÁXIMO 3 provedores (ISPs) que, juntos, representem pelo menos 80% dos registros de IP válidos. Excluir provedores marcados como proxy/VPN/hosting.

2. IPs POR PROVEDOR: Selecionar entre 3 (mínimo) e {ips_por_provedor} (máximo configurado) IPs por provedor.

3. PRIORIDADE IPv6: SEMPRE priorizar endereços IPv6 sobre IPv4. IPv6 identifica o usuário de forma mais precisa (sem compartilhamento via CGNAT). Se existirem IPs IPv6 de um provedor, usar APENAS IPv6 desse provedor.

4. ÂNCORAS TEMPORAIS: Para cada provedor, OBRIGATORIAMENTE incluir:
   - O PRIMEIRO IP cronológico (demonstra início de uso da conexão)
   - O ÚLTIMO IP cronológico (demonstra continuidade de uso)

5. DATA DO FATO: Priorizar IPs registrados no dia do fato investigado ({data_fato}). Se não houver IPs no dia do fato, selecionar os mais próximos temporalmente.

6. DIVERSIFICAÇÃO HORÁRIA: Garantir ao menos 1 registro em horário diurno (06h-18h) e 1 em horário noturno (18h-06h) quando disponível.

7. CGNAT: Alertar quando IPs IPv4 estiverem na faixa 100.64.0.0/10 (CGNAT), pois requerem porta lógica + horário exato para identificação.

8. IPs DE ATENÇÃO: Sinalizar IPs fora dos top 3 provedores que tenham score alto ou que apareçam no dia do fato.

## FORMATO DE RESPOSTA

Responda EXCLUSIVAMENTE no formato JSON conforme o schema fornecido. Não inclua texto fora do JSON. Escreva o campo resumo_narrativo em português formal, adequado para documentação investigativa.

## CONTEXTO LEGAL

A seleção se fundamenta no Art. 10, §3º da Lei 12.965/2014 (Marco Civil da Internet) c/c Art. 17-B da Lei 9.613/1998."""


def build_system_prompt(ips_por_provedor: int = 5, data_fato: str = '') -> str:
    """Monta o system prompt com os parâmetros da análise."""
    config = _load_ai_config()
    template = config.get('system_prompt_template') or SYSTEM_PROMPT_TEMPLATE
    return template.format(
        ips_por_provedor=ips_por_provedor,
        data_fato=data_fato or 'não informada',
    )


def build_user_prompt(
    df_scored: pd.DataFrame,
    provedores_sel: list,
    contagem_prov: dict,
    dt_fato: datetime,
    periodo_fato: str,
    janela_horas: int,
    ips_por_provedor: int,
    alvo: str = ''
) -> str:
    """Monta o user prompt com os dados da análise."""
    config = _load_ai_config()
    max_ips = config.get('max_ips_in_prompt', 30)

    ip_col = 'Ip' if 'Ip' in df_scored.columns else 'Sender IP'
    total = len(df_scored)
    ips_unicos = df_scored[ip_col].nunique() if ip_col in df_scored.columns else 0

    # Contagem IPv4/IPv6
    n_ipv6 = df_scored[ip_col].apply(lambda x: ':' in str(x)).sum() if ip_col in df_scored.columns else 0
    n_ipv4 = total - n_ipv6

    # IPs no dia do fato
    n_dia_fato = 0
    if 'Data' in df_scored.columns and dt_fato:
        try:
            dt_series = parse_data(df_scored['Data'])
            fato_date = dt_fato.date() if hasattr(dt_fato, 'date') else dt_fato
            n_dia_fato = (dt_series.dt.date == fato_date).sum()
        except Exception:
            pass

    # Proxy/CGNAT counts
    n_proxy = 0
    if 'Ip_Proxy' in df_scored.columns:
        n_proxy = bool_series(df_scored, 'Ip_Proxy').sum()
    n_cgnat = 0
    if ip_col in df_scored.columns:
        n_cgnat = df_scored[ip_col].apply(lambda ip: is_cgnat_ip(str(ip))).sum()

    # Tabela de provedores
    prov_lines = "| Provedor | Registros | IPv6 | IPv4 | % Total |\n|---|---|---|---|---|\n"
    for prov, count in sorted(contagem_prov.items(), key=lambda x: x[1], reverse=True):
        prov_df = df_scored[df_scored.get('Ip_Dono', pd.Series(dtype='str')) == prov]
        pv6 = prov_df[ip_col].apply(lambda x: ':' in str(x)).sum() if ip_col in prov_df.columns else 0
        pv4 = len(prov_df) - pv6
        pct = count / max(total, 1) * 100
        prov_lines += f"| {prov} | {count} | {pv6} | {pv4} | {pct:.1f}% |\n"

    # Top IPs por score
    df_top = df_scored.copy()
    if 'Score' in df_top.columns:
        df_top = df_top.sort_values('Score', ascending=False).head(max_ips)
    else:
        df_top = df_top.head(max_ips)

    ip_lines = "| IP | Tipo | Data | Provedor | Cidade | Score | Proxy | CGNAT |\n|---|---|---|---|---|---|---|---|\n"
    for _, row in df_top.iterrows():
        ip = str(row.get(ip_col, ''))
        tipo = 'IPv6' if ':' in ip else 'IPv4'
        data = str(row.get('Data', ''))[:16]
        prov = str(row.get('Ip_Dono', ''))[:25]
        cidade = str(row.get('Ip_Cidade', ''))
        score = row.get('Score', 0)
        proxy = 'Sim' if as_bool(row.get('Ip_Proxy'), field='Ip_Proxy') else 'Não'
        cgnat = 'Sim' if is_cgnat_ip(ip) else 'Não'
        ip_lines += f"| {ip} | {tipo} | {data} | {prov} | {cidade} | {score:.0f} | {proxy} | {cgnat} |\n"

    data_fato_str = dt_fato.strftime('%d/%m/%Y') if hasattr(dt_fato, 'strftime') else str(dt_fato)

    return f"""Analise os dados abaixo e sugira a seleção de IPs para investigação.

## PARÂMETROS
- Data do fato: {data_fato_str}
- Período do fato: {periodo_fato}
- Janela temporal: {janela_horas}h
- IPs por provedor: mín 3, máx {ips_por_provedor}
- Alvo: {alvo}

## DADOS DOS PROVEDORES (ordenados por volume)
{prov_lines}

## TOP {len(df_top)} IPs POR SCORE
{ip_lines}

## ESTATÍSTICAS
- Total de registros: {total}
- IPs únicos: {ips_unicos}
- IPv6: {n_ipv6} | IPv4: {n_ipv4}
- Provedores distintos: {len(contagem_prov)}
- IPs no dia do fato: {n_dia_fato}
- IPs com proxy/VPN: {n_proxy}
- IPs em CGNAT: {n_cgnat}

Aplique a metodologia e retorne a seleção em JSON."""


# ============================================================
# OLLAMA QUERY
# ============================================================
def query_ollama(
    system_prompt: str,
    user_prompt: str,
    model_name: str,
    json_schema: dict,
    base_url: str = DEFAULT_OLLAMA_URL,
    options: dict = None,
    request_timeout: int = None,
) -> Tuple[Optional[dict], Optional[str]]:
    """Envia consulta ao Ollama e retorna resposta parseada."""
    url = f"{base_url}/api/chat"

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "format": json_schema,
        "options": options or {"temperature": 0},
        "stream": False,
    }

    timeout = request_timeout or _get_timeout_for_model(model_name, purpose='analysis')
    content = ""

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()

        data = resp.json()
        content = data.get("message", {}).get("content", "")

        parsed = json.loads(content)
        return parsed, None

    except requests.ConnectionError:
        return None, "Ollama não está rodando. Execute: ollama serve"
    except requests.Timeout:
        if model_name != AI_MODELS['lite']['model']:
            return None, f"Timeout ({timeout}s). Tente o tier Lite ou aumente o timeout configurado."
        return None, f"Timeout ({timeout}s). Aumente o timeout configurado ou reduza o volume da análise."
    except json.JSONDecodeError as e:
        logger.error(f"JSON inválido do Ollama: {e}\nConteúdo: {content[:500]}")
        return None, f"Resposta inválida do modelo: {e}"
    except requests.HTTPError as e:
        return None, f"Erro HTTP do Ollama: {e}"
    except Exception as e:
        return None, str(e)


# ============================================================
# VALIDATION
# ============================================================
def validate_ai_response(response: dict, df_scored: pd.DataFrame = None) -> Tuple[bool, list]:
    """Valida a resposta da AI contra as regras de negócio."""
    warnings = []

    provedores = response.get('provedores', [])
    if len(provedores) > 3:
        warnings.append(f"AI sugeriu {len(provedores)} provedores (máx: 3)")

    ip_col = 'Ip' if df_scored is not None and 'Ip' in df_scored.columns else 'Sender IP'
    ips_validos = set()
    if df_scored is not None and ip_col in df_scored.columns:
        ips_validos = set(df_scored[ip_col].astype(str).unique())

    for prov in provedores:
        ips = prov.get('ips_selecionados', [])
        nome = prov.get('nome', '?')
        if len(ips) < 3:
            warnings.append(f"{nome}: apenas {len(ips)} IPs (mín: 3)")
        if len(ips) > 10:
            warnings.append(f"{nome}: {len(ips)} IPs (máx: 10)")
        if ips_validos:
            for ip_obj in ips:
                if ip_obj.get('ip', '') not in ips_validos:
                    warnings.append(f"IP {ip_obj.get('ip')} não encontrado nos dados")

    confianca = response.get('confianca', '')
    if confianca not in ('alta', 'media', 'baixa'):
        warnings.append(f"Confiança '{confianca}' inválida (esperado: alta/media/baixa)")

    is_valid = len(warnings) == 0
    return is_valid, warnings


# ============================================================
# MAIN ORCHESTRATOR
# ============================================================
def run_ai_analysis(
    df_scored: pd.DataFrame,
    provedores_sel: list,
    contagem_prov: dict,
    dt_fato: datetime,
    periodo_fato: str,
    janela_horas: int,
    ips_por_provedor: int,
    tier: str = "standard",
    alvo: str = '',
    base_url: str = DEFAULT_OLLAMA_URL,
) -> dict:
    """Função principal — orquestra toda a análise AI."""
    start_time = time.time()
    config = _load_ai_config()
    notes = []

    requested_tier = tier if tier in AI_MODELS else get_default_ai_tier()
    requested_model_info = AI_MODELS.get(requested_tier, AI_MODELS[get_default_ai_tier()])
    requested_model = requested_model_info['model']

    # 1. Verificar Ollama online
    status = check_ollama_status(base_url)
    if not status['online']:
        return {
            'success': False, 'data': None,
            'error': status.get('error', 'Ollama offline'),
            'model_used': requested_model, 'requested_model': requested_model,
            'elapsed_seconds': 0, 'fallback_used': False, 'notes': notes,
        }

    available_model_names = status.get('model_names', [])
    fallback_allowed = bool(config.get('fallback_to_lighter_model', True))
    candidate_tiers = _fallback_tier_order(requested_tier) if fallback_allowed else [requested_tier]

    resolved_tier = None
    model_info = None
    for candidate_tier in candidate_tiers:
        candidate_model_info = _get_available_model_for_tier(candidate_tier, available_model_names)
        if candidate_model_info:
            resolved_tier = candidate_tier
            model_info = candidate_model_info
            break

    if model_info is None:
        available_label = ', '.join(available_model_names[:6]) or 'nenhum modelo detectado'
        return {
            'success': False, 'data': None,
            'error': f"Modelo '{requested_model}' não encontrado. Execute: ollama pull {requested_model}. Modelos visíveis: {available_label}",
            'model_used': requested_model, 'requested_model': requested_model,
            'elapsed_seconds': 0, 'fallback_used': False, 'notes': notes,
        }

    if resolved_tier != requested_tier:
        notes.append(
            f"Modelo do tier '{requested_tier}' indisponível. Usando fallback '{resolved_tier}' ({model_info['model']})."
        )

    model_name = model_info['model']

    # 3. Montar prompts
    data_fato_str = dt_fato.strftime('%d/%m/%Y') if hasattr(dt_fato, 'strftime') else str(dt_fato)
    system_prompt = build_system_prompt(ips_por_provedor, data_fato_str)
    user_prompt = build_user_prompt(
        df_scored, provedores_sel, contagem_prov,
        dt_fato, periodo_fato, janela_horas, ips_por_provedor, alvo
    )

    # 4. Enviar ao Ollama
    parsed, error = query_ollama(
        system_prompt, user_prompt, model_name,
        AI_JSON_SCHEMA, base_url, model_info['options']
    )

    if error and 'Timeout' in error and fallback_allowed and resolved_tier != 'lite':
        lite_model_info = _get_available_model_for_tier('lite', available_model_names)
        if lite_model_info and lite_model_info['model'] != model_name:
            notes.append(
                f"Timeout com {model_name}. Tentando fallback automático no modelo leve {lite_model_info['model']}."
            )
            parsed, error = query_ollama(
                system_prompt,
                user_prompt,
                lite_model_info['model'],
                AI_JSON_SCHEMA,
                base_url,
                lite_model_info['options'],
            )
            if not error:
                model_info = lite_model_info
                model_name = lite_model_info['model']
                resolved_tier = 'lite'

    elapsed = round(time.time() - start_time, 1)

    if error:
        return {
            'success': False, 'data': None,
            'error': error, 'model_used': model_name,
            'requested_model': requested_model,
            'elapsed_seconds': elapsed,
            'fallback_used': model_name != requested_model,
            'notes': notes,
        }

    # 5. Validar resposta
    is_valid, warnings = validate_ai_response(parsed, df_scored)
    if warnings:
        logger.warning(f"Validação AI: {warnings}")
        if 'alertas' not in parsed:
            parsed['alertas'] = []
        parsed['alertas'].extend([f"⚠️ Validação: {w}" for w in warnings])

    return {
        'success': True,
        'data': parsed,
        'error': None,
        'model_used': model_name,
        'requested_model': requested_model,
        'elapsed_seconds': elapsed,
        'fallback_used': model_name != requested_model,
        'notes': notes,
        'validation_warnings': warnings,
    }
