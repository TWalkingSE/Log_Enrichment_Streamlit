import asyncio
import aiohttp
import gzip
import json
import os
import time
import re
import logging
import socket
from ipaddress import ip_address, ip_network

logger = logging.getLogger(__name__)

# TTL padrão do cache: 30 dias (em segundos)
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60

CGNAT_NETWORK = ip_network('100.64.0.0/10')

# Redes privadas/reservadas que não devem ser consultadas na API
PRIVATE_NETWORKS = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('127.0.0.0/8'),
    ip_network('169.254.0.0/16'),
    ip_network('224.0.0.0/4'),
    ip_network('240.0.0.0/4'),
    CGNAT_NETWORK,
    ip_network('::1/128'),
    ip_network('fc00::/7'),
    ip_network('fe80::/10'),
]

# Máximo de retries por consulta
MAX_RETRIES = 3

# Rate limit da API gratuita: 45 req/min
FREE_API_RATE_LIMIT = 45
FREE_API_PERIOD = 60


class IPAPIClient:
    """Cliente para a API IP-API.com (gratuita e paga)"""

    def __init__(self, batch_size=500, period=0, cache_file=None, api_key=None, cache_ttl=None):
        self.api_key = api_key
        self._api_key_lock = asyncio.Lock()

        # API paga (com key) = pro endpoint HTTPS ilimitado
        # API gratuita (sem key) = endpoint HTTP com rate limit 45 req/min
        if api_key:
            self.API_URL = "https://pro.ip-api.com/json/"
            self.batch_size = batch_size
            self.period = period
        else:
            self.API_URL = "http://ip-api.com/json/"
            self.batch_size = min(batch_size, FREE_API_RATE_LIMIT)
            self.period = max(period, FREE_API_PERIOD)

        self.total_requests = 0
        self._request_times = []  # Para rate limiting da API gratuita
        self.cache = {}
        self.cache_file = cache_file
        self.cache_ttl = cache_ttl or CACHE_TTL_SECONDS

        # Cache metrics
        self.cache_hits = 0
        self.cache_misses = 0

        if cache_file and os.path.exists(cache_file):
            self._load_cache(cache_file)

    def _load_cache(self, cache_file):
        """Carrega cache de arquivo JSON, gzip ou zstd"""
        try:
            if cache_file.endswith('.zst') or cache_file.endswith('.zstd'):
                try:
                    import zstandard as zstd
                    with open(cache_file, 'rb') as f:
                        dctx = zstd.ZstdDecompressor()
                        raw = dctx.decompress(f.read())
                        raw_cache = json.loads(raw.decode('utf-8'))
                except ImportError:
                    logger.warning("zstandard não instalado, ignorando cache .zst")
                    return
            elif cache_file.endswith('.gz'):
                with gzip.open(cache_file, 'rt', encoding='utf-8') as f:
                    raw_cache = json.load(f)
            else:
                with open(cache_file, 'r') as f:
                    raw_cache = json.load(f)
            # Migrar cache antigo (sem TTL) e filtrar expirados
            now = time.time()
            for ip_key, entry in raw_cache.items():
                if isinstance(entry, dict):
                    ts = entry.get('_cached_at', 0)
                    if ts == 0 or (now - ts) < self.cache_ttl:
                        if '_cached_at' not in entry:
                            entry['_cached_at'] = now
                        self.cache[ip_key] = entry
            expired_count = len(raw_cache) - len(self.cache)
            logger.info(f"Cache carregado: {len(self.cache)} entradas válidas, {expired_count} expiradas removidas")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
            logger.error(f"Erro ao carregar cache: {e}")

    async def rate_limit(self):
        """Rate limiting: API paga = ilimitado, API gratuita = 45 req/min"""
        self.total_requests += 1

        if self.api_key:
            return  # API paga não tem rate limit

        # Rate limit para API gratuita: 45 req/min
        # Limpar tempos expirados ANTES de verificar o tamanho
        now = time.time()
        self._request_times = [t for t in self._request_times if now - t < FREE_API_PERIOD]

        if len(self._request_times) >= FREE_API_RATE_LIMIT:
            oldest = self._request_times[0]
            wait = min(FREE_API_PERIOD - (now - oldest) + 0.5, 60)  # Cap em 60s
            if wait > 0:
                logger.info(f"Rate limit atingido ({FREE_API_RATE_LIMIT} req/min). Aguardando {wait:.1f}s...")
                await asyncio.sleep(wait)

        self._request_times.append(time.time())

    def _make_error_result(self, message):
        """Retorna dict padrão de erro para evitar repetição"""
        return {
            'Ip_Dono': f'Erro: {message}',
            'Ip_AS': 'Erro',
            'Ip_Regiao': 'Erro',
            'Ip_Cidade': 'Erro',
            'Ip_Pais': 'Erro',
            'Ip_Pais_Codigo': '',
            'Ip_Movel': False,
            'Ip_Proxy': False,
            'Ip_Hospedagem': False,
            'Ip_Lat': None,
            'Ip_Lon': None
        }

    async def consultar_ip(self, session, ip, callback=None):
        """Consulta informações de um IP com retry e backoff exponencial"""
        # Verificar cache (com TTL)
        if ip in self.cache:
            entry = self.cache[ip]
            cached_at = entry.get('_cached_at', 0)
            if cached_at and (time.time() - cached_at) >= self.cache_ttl:
                del self.cache[ip]
                if callback:
                    callback(f"Cache expirado para IP {ip}, reconsultando")
            else:
                self.cache_hits += 1
                if callback:
                    callback(f"Usando cache para IP {ip}")
                result = {k: v for k, v in entry.items() if k != '_cached_at'}
                return result

        self.cache_misses += 1

        # Validar IP
        try:
            ip_obj = ip_address(ip)
        except ValueError:
            if callback:
                callback(f"IP inválido: {ip}")
            return self._make_error_result('IP inválido')

        # Filtrar IPs privados/reservados
        if is_private_ip(ip):
            if callback:
                callback(f"IP privado/reservado ignorado: {ip}")
            return self._make_error_result('IP privado/reservado')

        await self.rate_limit()

        # Retry com backoff exponencial
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                if callback and attempt == 0:
                    callback(f"Consultando IP: {ip}")
                elif callback and attempt > 0:
                    callback(f"Retry {attempt}/{MAX_RETRIES} para IP: {ip}")

                fields = "status,message,country,countryCode,region,regionName,city,timezone,isp,org,as,mobile,proxy,hosting,query,lat,lon"
                if self.api_key:
                    url = f"{self.API_URL}{ip}?key={self.api_key}&fields={fields}"
                else:
                    url = f"{self.API_URL}{ip}?fields={fields}"

                timeout = aiohttp.ClientTimeout(total=15)
                async with session.get(url, timeout=timeout) as response:
                    if response.status == 429:
                        wait = (2 ** attempt) * 5
                        if callback:
                            callback(f"Rate limited (429). Aguardando {wait}s...")
                        await asyncio.sleep(wait)
                        continue

                    if response.status == 403 and 'pro.' in url:
                        # API key inválida/expirada — fallback para API gratuita
                        # Thread-safe: usar lock para evitar race condition
                        async with self._api_key_lock:
                            if self.api_key:
                                logger.warning("API Key inválida (403). Fazendo fallback para API gratuita (45 req/min).")
                                self.api_key = None
                                self.API_URL = "http://ip-api.com/json/"
                                self.batch_size = min(self.batch_size, FREE_API_RATE_LIMIT)
                                self.period = max(self.period, FREE_API_PERIOD)
                                self._request_times = []
                        if callback and attempt == 0:
                            callback("⚠️ API Key inválida. Usando API gratuita.")
                        # Retry este IP com a API gratuita
                        continue

                    if response.status != 200:
                        if callback:
                            callback(f"Erro HTTP {response.status} para IP: {ip}")
                        return self._make_error_result(f'HTTP {response.status}')

                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                        logger.warning(f"Resposta inválida da API para IP {ip}: {e}")
                        if callback:
                            callback(f"Resposta inválida da API para IP: {ip}")
                        return self._make_error_result('Resposta inválida da API')

                    if data['status'] == 'fail':
                        if callback:
                            callback(f"Falha: {data.get('message', 'Erro desconhecido')}")
                        return self._make_error_result(data.get('message', 'Falha'))

                    result = {
                        'Ip_Dono': data.get('org') or data.get('isp', 'Não disponível'),
                        'Ip_AS': data.get('as', 'Não disponível'),
                        'Ip_Regiao': data.get('regionName') or data.get('country', 'Não disponível'),
                        'Ip_Cidade': data.get('city', 'Não disponível'),
                        'Ip_Pais': data.get('country', 'Não disponível'),
                        'Ip_Pais_Codigo': data.get('countryCode', ''),
                        'Ip_Movel': bool(data.get('mobile', False)),
                        'Ip_Proxy': bool(data.get('proxy', False)),
                        'Ip_Hospedagem': bool(data.get('hosting', False)),
                        'Ip_Lat': data.get('lat'),
                        'Ip_Lon': data.get('lon')
                    }

                    # Salvar no cache com timestamp e geo history
                    result['status'] = 'success'
                    if self.cache_file:
                        now = time.time()
                        cache_entry = result.copy()
                        cache_entry['_cached_at'] = now

                        # Geo history tracking: detect location changes
                        old_entry = self.cache.get(ip)
                        if old_entry and isinstance(old_entry, dict):
                            old_lat = old_entry.get('Ip_Lat')
                            old_lon = old_entry.get('Ip_Lon')
                            old_city = old_entry.get('Ip_Cidade', '')
                            old_isp = old_entry.get('Ip_Dono', '')
                            new_lat = result.get('Ip_Lat')
                            new_lon = result.get('Ip_Lon')
                            new_city = result.get('Ip_Cidade', '')
                            new_isp = result.get('Ip_Dono', '')
                            geo_changed = (old_city != new_city) or (old_isp != new_isp)
                            if geo_changed and old_lat is not None and old_lon is not None:
                                history = old_entry.get('_geo_history', [])
                                if not isinstance(history, list):
                                    history = []
                                history.append({
                                    'lat': old_lat, 'lon': old_lon,
                                    'city': old_city, 'isp': old_isp,
                                    'country': old_entry.get('Ip_Pais', ''),
                                    'ts': old_entry.get('_cached_at', now)
                                })
                                cache_entry['_geo_history'] = history[-10:]
                            else:
                                old_hist = old_entry.get('_geo_history', [])
                                cache_entry['_geo_history'] = old_hist if isinstance(old_hist, list) else []

                        self.cache[ip] = cache_entry

                    if callback:
                        callback(f"Consulta bem-sucedida para IP {ip}")

                    return result

            except asyncio.TimeoutError:
                last_error = 'Timeout'
                if attempt < MAX_RETRIES - 1:
                    wait = min((2 ** attempt) * 2, 60)
                    await asyncio.sleep(wait)
                    continue
            except aiohttp.ClientError as e:
                last_error = str(e)
                if attempt < MAX_RETRIES - 1:
                    wait = min((2 ** attempt) * 2, 60)
                    await asyncio.sleep(wait)
                    continue
            except (OSError, ValueError) as e:
                last_error = str(e)
                logger.error(f"Erro inesperado ao consultar IP {ip}: {e}")
                break

        if callback:
            callback(f"Falha após {MAX_RETRIES} tentativas para IP {ip}: {last_error}")
        return self._make_error_result(last_error or 'Erro desconhecido')

    def _parse_api_result(self, data):
        """Converte resposta da API em dict padronizado."""
        return {
            'Ip_Dono': data.get('org') or data.get('isp', 'Não disponível'),
            'Ip_AS': data.get('as', 'Não disponível'),
            'Ip_Regiao': data.get('regionName') or data.get('country', 'Não disponível'),
            'Ip_Cidade': data.get('city', 'Não disponível'),
            'Ip_Pais': data.get('country', 'Não disponível'),
            'Ip_Pais_Codigo': data.get('countryCode', ''),
            'Ip_Movel': bool(data.get('mobile', False)),
            'Ip_Proxy': bool(data.get('proxy', False)),
            'Ip_Hospedagem': bool(data.get('hosting', False)),
            'Ip_Lat': data.get('lat'),
            'Ip_Lon': data.get('lon'),
            'status': 'success',
        }

    async def consultar_batch(self, session, ips, callback=None, progress_callback=None):
        """
        Consulta até 100 IPs por request usando POST /batch (ip-api.com).
        Envia TODOS os IPs de uma vez, dividindo internamente em chunks de 100.
        API paga: envia até 5 batches concorrentes (500 IPs simultâneos).
        API gratuita: envia batches sequencialmente respeitando rate limit.

        Args:
            progress_callback: Função(processed_count, total) chamada após cada wave/chunk.
        Retorna dict {ip: resultado}.
        """
        resultados = {}
        fields = "status,message,country,countryCode,region,regionName,city,timezone,isp,org,as,mobile,proxy,hosting,query,lat,lon"

        # Filtrar cache e IPs inválidos/privados primeiro
        ips_to_query = []
        for ip in ips:
            if ip in self.cache:
                entry = self.cache[ip]
                cached_at = entry.get('_cached_at', 0)
                if cached_at and (time.time() - cached_at) >= self.cache_ttl:
                    del self.cache[ip]
                else:
                    self.cache_hits += 1
                    resultados[ip] = {k: v for k, v in entry.items() if k != '_cached_at'}
                    continue

            self.cache_misses += 1
            if not is_valid_ip(ip) or is_private_ip(ip):
                resultados[ip] = self._make_error_result('IP inválido ou privado')
                continue
            ips_to_query.append(ip)

        if not ips_to_query:
            return resultados

        total_to_query = len(ips_to_query)
        processed_count = 0

        if callback:
            callback(f"Enviando {total_to_query} IPs para o endpoint batch...")

        # Dividir em chunks de 100 (limite do endpoint batch)
        BATCH_SIZE = 100
        chunks = [ips_to_query[i:i + BATCH_SIZE] for i in range(0, len(ips_to_query), BATCH_SIZE)]

        async def _query_one_chunk(chunk, chunk_idx):
            """Envia um chunk de até 100 IPs para o endpoint /batch."""
            chunk_results = {}
            await self.rate_limit()

            if callback:
                callback(f"Batch {chunk_idx + 1}/{len(chunks)}: consultando {len(chunk)} IPs...")

            payload = [{"query": ip, "fields": fields} for ip in chunk]

            for attempt in range(MAX_RETRIES):
                try:
                    if self.api_key:
                        url = f"https://pro.ip-api.com/batch?key={self.api_key}"
                    else:
                        url = "http://ip-api.com/batch"

                    timeout = aiohttp.ClientTimeout(total=30)
                    async with session.post(url, json=payload, timeout=timeout) as response:
                        if response.status == 429:
                            wait = (2 ** attempt) * 5
                            if callback:
                                callback(f"Rate limited (429). Aguardando {wait}s...")
                            await asyncio.sleep(wait)
                            continue

                        if response.status != 200:
                            logger.warning(f"Batch HTTP {response.status}, fallback para individual")
                            break

                        try:
                            batch_data = await response.json()
                        except (aiohttp.ContentTypeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                            logger.warning(f"Resposta batch inválida, fallback para individual: {e}")
                            break

                        for item in batch_data:
                            ip = item.get('query', '')
                            if item.get('status') == 'success':
                                result = self._parse_api_result(item)
                                chunk_results[ip] = result
                                if self.cache_file:
                                    cache_entry = result.copy()
                                    cache_entry['_cached_at'] = time.time()
                                    self.cache[ip] = cache_entry
                            else:
                                chunk_results[ip] = self._make_error_result(
                                    item.get('message', 'Falha'))

                        self.total_requests += 1
                        return chunk_results  # success

                except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep((2 ** attempt) * 2)
                        continue
                    logger.error(f"Batch falhou após {MAX_RETRIES} tentativas: {e}")
                    for ip in chunk:
                        if ip not in chunk_results:
                            chunk_results[ip] = self._make_error_result(str(e))

            return chunk_results

        # API paga: batches concorrentes (até 5 simultâneos)
        # API gratuita: sequencial (respeitando rate limit)
        if self.api_key:
            CONCURRENT_BATCHES = 5
            for wave_start in range(0, len(chunks), CONCURRENT_BATCHES):
                wave = chunks[wave_start:wave_start + CONCURRENT_BATCHES]
                tasks = [_query_one_chunk(chunk, wave_start + i) for i, chunk in enumerate(wave)]
                wave_results = await asyncio.gather(*tasks, return_exceptions=True)
                for wr in wave_results:
                    if isinstance(wr, dict):
                        resultados.update(wr)
                        processed_count += len(wr)
                    elif isinstance(wr, Exception):
                        logger.error(f"Batch wave falhou: {wr}")
                if progress_callback:
                    progress_callback(processed_count, total_to_query)
        else:
            for idx, chunk in enumerate(chunks):
                chunk_results = await _query_one_chunk(chunk, idx)
                resultados.update(chunk_results)
                processed_count += len(chunk_results)
                if progress_callback:
                    progress_callback(processed_count, total_to_query)

        # Fallback individual para IPs sem resultado
        for ip in ips_to_query:
            if ip not in resultados:
                resultados[ip] = await self.consultar_ip(session, ip, callback=callback)

        return resultados

    async def consultar_lote_ips(self, session, ips, callback=None, progress_callback=None):
        """Consulta um lote de IPs. Usa batch endpoint quando possível."""
        return await self.consultar_batch(session, ips, callback=callback, progress_callback=progress_callback)

    def salvar_cache(self):
        """Salva o cache em arquivo (suporta JSON, gzip e zstd)"""
        if self.cache_file:
            try:
                if self.cache_file.endswith('.zst') or self.cache_file.endswith('.zstd'):
                    try:
                        import zstandard as zstd
                        data = json.dumps(self.cache).encode('utf-8')
                        cctx = zstd.ZstdCompressor(level=3)
                        compressed = cctx.compress(data)
                        with open(self.cache_file, 'wb') as f:
                            f.write(compressed)
                        logger.info(f"Cache salvo com zstd ({len(self.cache)} entradas, "
                                    f"{len(data)} → {len(compressed)} bytes, "
                                    f"{len(compressed)/len(data)*100:.0f}%)")
                        return
                    except ImportError:
                        logger.warning("zstandard não instalado, usando JSON padrão")
                        # Fallback to .json
                        fallback = self.cache_file.rsplit('.', 1)[0] + '.json'
                        with open(fallback, 'w') as f:
                            json.dump(self.cache, f)
                        return
                if self.cache_file.endswith('.gz'):
                    with gzip.open(self.cache_file, 'wt', encoding='utf-8') as f:
                        json.dump(self.cache, f)
                else:
                    with open(self.cache_file, 'w') as f:
                        json.dump(self.cache, f)
                logger.info(f"Cache salvo com {len(self.cache)} entradas")
            except (OSError, TypeError, ValueError) as e:
                logger.error(f"Erro ao salvar cache: {e}")

    def get_status(self):
        """Retorna o status atual do cliente incluindo métricas de cache"""
        total_lookups = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total_lookups * 100) if total_lookups > 0 else 0
        return {
            "total_requests": self.total_requests,
            "batch_size": self.batch_size,
            "cache_size": len(self.cache),
            "api_url": self.API_URL,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(hit_rate, 1),
        }

def is_valid_ip(ip_str):
    """Verifica se uma string é um IP válido com validação aprimorada"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    
    ip_str = ip_str.strip()
    
    # Verificar formato IPv4 básico
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split('.')
        for part in parts:
            if not part.isdigit() or int(part) > 255:
                return False
    
    # Para IPv6 e outros formatos, deixar ip_address validar
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str):
    """Verifica se o IP é privado/reservado (não deve ser consultado na API)"""
    try:
        ip_obj = ip_address(ip_str.strip())
        for network in PRIVATE_NETWORKS:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False


def is_cgnat_ip(ip_str):
    """Verifica se um IPv4 pertence ao range CGNAT RFC 6598."""
    try:
        ip_obj = ip_address(ip_str.strip())
        return ip_obj.version == 4 and ip_obj in CGNAT_NETWORK
    except (ValueError, AttributeError):
        return False


def resolve_rdns(ip_str):
    """Realiza lookup reverso de DNS para um IP (síncrono)"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str.strip())
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


async def resolve_rdns_async(ip_str, timeout_sec=3):
    """Realiza lookup reverso de DNS de forma assíncrona."""
    loop = asyncio.get_event_loop()
    try:
        hostname = await asyncio.wait_for(
            loop.run_in_executor(None, resolve_rdns, ip_str),
            timeout=timeout_sec
        )
        return ip_str, hostname
    except (asyncio.TimeoutError, Exception):
        return ip_str, None


async def batch_resolve_rdns(ips, max_concurrent=20, timeout_sec=3):
    """Resolve rDNS para múltiplos IPs em paralelo. Retorna dict {ip: hostname}."""
    sem = asyncio.Semaphore(max_concurrent)
    results = {}

    async def _resolve(ip):
        async with sem:
            return await resolve_rdns_async(ip, timeout_sec)

    tasks = [_resolve(ip) for ip in ips]
    done = await asyncio.gather(*tasks, return_exceptions=True)

    for item in done:
        if isinstance(item, tuple):
            results[item[0]] = item[1]
        elif isinstance(item, Exception):
            logger.debug(f"rDNS resolve exception: {item}")

    return results
