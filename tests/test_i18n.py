"""Paridade dos locales e existência das chaves usadas no código.

Uma chave que falta em um idioma cai no português sem aviso; uma que falta em
todos aparece na tela como o próprio nome (`resultados.provider`). Um
placeholder divergente (`{count}` num idioma, `{total}` no outro) faz o
`format` falhar e o texto sair cru.
"""
import json
import os
import re
import string
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ('pt', 'en', 'es')


def _load(lang):
    with open(os.path.join(ROOT, 'locales', f'{lang}.json'), encoding='utf-8') as fh:
        return json.load(fh)


def _flat(data, prefix=''):
    out = {}
    for key, value in data.items():
        dotted = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            out.update(_flat(value, dotted))
        else:
            out[dotted] = value
    return out


def _placeholders(text):
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def _code_keys():
    """Chaves literais em `t('...')`/`t_or('...')` no código (f-strings ficam de fora)."""
    pattern = re.compile(r"""\bt(?:_or)?\(\s*['"]([a-z_]+(?:\.[\w\-]+)+)['"]""")
    keys = {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in ('venv', '.git', '__pycache__', 'tests',
                                                        'logs', 'output', 'data', 'cache_backups')]
        for name in filenames:
            # i18n.py fica de fora: os exemplos do docstring não são uso real.
            if name.endswith('.py') and name != 'i18n.py':
                path = os.path.join(dirpath, name)
                with open(path, encoding='utf-8') as fh:
                    for key in pattern.findall(fh.read()):
                        keys.setdefault(key, os.path.relpath(path, ROOT))
    return keys


class TestLocales(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.flat = {lang: _flat(_load(lang)) for lang in LANGS}

    def test_mesmas_chaves_nos_tres_idiomas(self):
        base = set(self.flat['pt'])
        for lang in ('en', 'es'):
            with self.subTest(lang=lang):
                self.assertEqual(sorted(base - set(self.flat[lang])), [], f'faltam em {lang}')
                self.assertEqual(sorted(set(self.flat[lang]) - base), [], f'sobram em {lang}')

    def test_valores_sao_texto(self):
        for lang in LANGS:
            nao_texto = [k for k, v in self.flat[lang].items() if not isinstance(v, str)]
            self.assertEqual(nao_texto, [], lang)

    def test_mesmos_placeholders(self):
        divergentes = []
        for key, pt_value in self.flat['pt'].items():
            esperado = _placeholders(pt_value)
            for lang in ('en', 'es'):
                valor = self.flat[lang].get(key)
                if isinstance(valor, str) and _placeholders(valor) != esperado:
                    divergentes.append((lang, key))
        self.assertEqual(divergentes, [])

    def test_chaves_usadas_no_codigo_existem(self):
        faltando = {k: f for k, f in _code_keys().items() if k not in self.flat['pt']}
        self.assertEqual(faltando, {})


if __name__ == '__main__':
    unittest.main()
