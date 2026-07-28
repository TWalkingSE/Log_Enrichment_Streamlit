"""Unit tests for api_client helpers and IPAPIClient (no real HTTP)."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pandas as pd

from api_client import (
    IPAPIClient,
    is_cgnat_ip,
    is_private_ip,
    is_valid_ip,
)


class TestIpValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ip('8.8.8.8'))
        self.assertTrue(is_valid_ip('192.168.0.1'))

    def test_invalid_ip(self):
        self.assertFalse(is_valid_ip(''))
        self.assertFalse(is_valid_ip(None))
        self.assertFalse(is_valid_ip('not-an-ip'))
        self.assertFalse(is_valid_ip('999.999.999.999'))

    def test_private_and_cgnat(self):
        self.assertTrue(is_private_ip('10.0.0.1'))
        self.assertTrue(is_private_ip('192.168.1.10'))
        self.assertTrue(is_private_ip('100.64.0.1'))
        self.assertTrue(is_cgnat_ip('100.64.1.2'))
        self.assertFalse(is_private_ip('8.8.8.8'))
        self.assertFalse(is_cgnat_ip('8.8.8.8'))


class TestIPAPIClientCache(unittest.TestCase):
    def test_free_tier_uses_http(self):
        client = IPAPIClient(api_key=None, cache_file=None)
        self.assertIn('http://', client.API_URL)
        self.assertNotIn('https://', client.API_URL)

    def test_paid_tier_uses_https(self):
        client = IPAPIClient(api_key='secret-key', cache_file=None)
        self.assertTrue(client.API_URL.startswith('https://'))

    def test_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'cache.json')
            client = IPAPIClient(api_key='k', cache_file=path)
            client.cache['1.2.3.4'] = {
                'Ip_Dono': 'Test Org',
                'Ip_AS': 'AS1',
                'Ip_Cidade': 'SP',
                'Ip_Pais': 'BR',
                'Ip_Pais_Codigo': 'BR',
                'Ip_Regiao': 'SP',
                'Ip_Movel': False,
                'Ip_Proxy': False,
                'Ip_Hospedagem': False,
                'Ip_Lat': -23.5,
                'Ip_Lon': -46.6,
                '_cached_at': time.time(),
            }
            client.salvar_cache()
            client2 = IPAPIClient(api_key='k', cache_file=path)
            self.assertIn('1.2.3.4', client2.cache)
            self.assertEqual(client2.cache['1.2.3.4']['Ip_Dono'], 'Test Org')

    def test_get_status_metrics(self):
        client = IPAPIClient(api_key='k', cache_file=None)
        client.cache_hits = 3
        client.cache_misses = 1
        status = client.get_status()
        self.assertEqual(status['cache_hits'], 3)
        self.assertEqual(status['cache_misses'], 1)
        self.assertEqual(status['cache_hit_rate'], 75.0)


class TestIPAPIClientConsultar(unittest.IsolatedAsyncioTestCase):
    async def test_consultar_ip_uses_cache(self):
        client = IPAPIClient(api_key='k', cache_file=None)
        client.cache['8.8.8.8'] = {
            'Ip_Dono': 'Google',
            'Ip_AS': 'AS15169',
            'Ip_Cidade': 'Mountain View',
            'Ip_Pais': 'US',
            'Ip_Pais_Codigo': 'US',
            'Ip_Regiao': 'CA',
            'Ip_Movel': False,
            'Ip_Proxy': False,
            'Ip_Hospedagem': False,
            'Ip_Lat': 37.4,
            'Ip_Lon': -122.1,
            '_cached_at': time.time(),
        }
        session = MagicMock()
        result = await client.consultar_ip(session, '8.8.8.8')
        self.assertEqual(result['Ip_Dono'], 'Google')
        self.assertEqual(client.cache_hits, 1)
        session.get.assert_not_called()

    async def test_consultar_ip_private_skipped(self):
        client = IPAPIClient(api_key='k', cache_file=None)
        session = MagicMock()
        result = await client.consultar_ip(session, '10.0.0.5')
        self.assertIn('Erro', result['Ip_Dono'])
        session.get.assert_not_called()

    async def test_consultar_ip_http_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'cache.json')
            client = IPAPIClient(api_key='k', cache_file=path)
            payload = {
                'status': 'success',
                'org': 'Example ISP',
                'isp': 'Example ISP',
                'as': 'AS1',
                'regionName': 'SP',
                'city': 'Sao Paulo',
                'country': 'Brazil',
                'countryCode': 'BR',
                'mobile': False,
                'proxy': False,
                'hosting': False,
                'lat': -23.5,
                'lon': -46.6,
            }

            response = AsyncMock()
            response.status = 200
            response.json = AsyncMock(return_value=payload)
            cm = MagicMock()
            cm.__aenter__ = AsyncMock(return_value=response)
            cm.__aexit__ = AsyncMock(return_value=None)

            session = MagicMock()
            session.get = MagicMock(return_value=cm)

            result = await client.consultar_ip(session, '1.1.1.1')
            self.assertEqual(result['Ip_Dono'], 'Example ISP')
            self.assertEqual(result['Ip_Cidade'], 'Sao Paulo')
            self.assertEqual(client.cache_misses, 1)
            self.assertIn('1.1.1.1', client.cache)
