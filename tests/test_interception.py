"""Testes do parser de interceptação telemática (WhatsApp Business Record).

Cobre as três seções do artefato real — Message Log, Call Logs e
Prospective Login IPs — além de metadados forenses (Call Id, evento,
Recipients, Message Id, device) e proveniência (Alvo/Fonte).
"""

import io
import zipfile

import pytest

from tests.common import *
from interception_parser import (
    COLUNAS_EXPORT_INTERCEPTACAO,
    COLUNAS_INTERCEPTACAO,
    parse_html_records,
    parse_zip_interception,
    records_to_dataframe,
)


def _div(rotulo, valor=None):
    """Um campo label/valor como nos records.html reais."""
    if valor is None:
        return f'<div>{rotulo}</div>'
    return f'<div>{rotulo}</div><div>{valor}</div>'


def _html(body_sections):
    return ('<html><head><title>WhatsApp Business Record</title></head>'
            f'<body>{body_sections}</body></html>')


REQUEST_PARAMS = (
    '<div id="property-request_parameters">'
    + _div('Target', '+5511999990000')
    + _div('Service', 'WhatsApp')
    + '</div>'
)

MESSAGE_LOG = (
    '<div id="property-message_log">'
    '<div>Message Log Definition</div><div>Message Log: definition</div>'
    '<div>Message Log</div>'
    '<div>Message</div>'
    + _div('Timestamp', '2026-01-01 10:00:00 UTC')
    + _div('Sender', '551111111')
    + _div('Sender Ip', '203.0.113.7')
    + _div('Sender Port', '45000')
    + _div('Message Id', 'msg-abc-1')
    + _div('Recipients', '+552222222')
    + _div('Sender Device', 'android')
    + _div('Type', 'image')
    + _div('Message Style', 'photo')
    + _div('Message Size', '1024')
    # Mensagem cujo Sender Ip cai na página seguinte (rótulo + pageBreak + valor órfão)
    + '<div>Message</div>'
    + _div('Timestamp', '2026-01-01 10:05:00 UTC')
    + _div('Sender', '551111111')
    + '<div>Sender Ip</div><div>WhatsApp Business Record Page 5</div><div>198.51.100.9</div>'
    + _div('Sender Port', '45001')
    + _div('Type', 'text')
    + '</div>'
)

CALL_LOGS = (
    '<div id="property-call_logs">'
    '<div>Call Logs Definition</div><div>Call Log: definition</div>'
    '<div>Call Log</div>'
    '<div>Call</div>'
    + _div('Call Id', 'call-id-42')
    + _div('Call Creator', '+553333333')
    + '<div>Events</div>'
    + _div('Type', 'offer')
    + _div('Timestamp', '2026-01-01 11:00:00 UTC')
    + _div('From', '551111111')
    + _div('To', '+552222222')
    + _div('From Ip', '203.0.113.8')
    + _div('From Port', '55001')
    + _div('Media Type', 'audio')
    # Evento terminate sem From Ip — continua sendo evidência (fim da chamada)
    + _div('Type', 'terminate')
    + _div('Timestamp', '2026-01-01 11:03:00 UTC')
    + _div('From', '551111111')
    + _div('To', '+552222222')
    + '</div>'
)

LOGIN_IPS = (
    '<div id="property-prospective_login_ips">'
    '<div>Prospective Login Ips Definition</div>'
    '<div>Timestamp: def</div><div>IP Address: def</div><div>Port: def</div>'
    '<div>Prospective Login IPs</div>'
    + _div('Timestamp', '2026-01-01 09:00:00 UTC')
    + _div('IP Address', '203.0.113.10')
    + _div('Port', '55261')
    + _div('Timestamp', '2026-01-01 09:05:00 UTC')
    + _div('IP Address', '203.0.113.10')
    + _div('Port', '55262')
    + '</div>'
)

FULL_HTML = _html(REQUEST_PARAMS + MESSAGE_LOG + CALL_LOGS + LOGIN_IPS)


class TestParseHtmlRecordsSections(unittest.TestCase):
    def test_login_ips_extraidos(self):
        recs = parse_html_records(FULL_HTML)
        logins = [r for r in recs if r['type'] == 'login']
        self.assertEqual(len(logins), 2)
        self.assertEqual(logins[0]['ip'], '203.0.113.10')
        self.assertEqual(logins[0]['port'], '55261')
        # Login IP pertence à conta do alvo
        self.assertEqual(logins[0]['from_number'], '+5511999990000')
        self.assertEqual(logins[0]['event'], 'login')

    def test_call_metadata_preservada(self):
        recs = parse_html_records(FULL_HTML)
        calls = [r for r in recs if r['type'].startswith('call')]
        self.assertEqual(len(calls), 2)
        offer = [r for r in calls if r['event'] == 'offer'][0]
        self.assertEqual(offer['call_id'], 'call-id-42')
        self.assertEqual(offer['creator'], '+553333333')
        self.assertEqual(offer['to'], '+552222222')
        self.assertEqual(offer['media_type'], 'audio')
        self.assertEqual(offer['type'], 'call/audio')
        # terminate sem From Ip é mantido (fim de chamada = evidência)
        term = [r for r in calls if r['event'] == 'terminate']
        self.assertEqual(len(term), 1)
        self.assertEqual(term[0]['ip'], '')
        self.assertEqual(term[0]['call_id'], 'call-id-42')

    def test_message_metadata_preservada(self):
        recs = parse_html_records(FULL_HTML)
        msgs = [r for r in recs if r['type'].startswith('message')]
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0]['message_id'], 'msg-abc-1')
        self.assertEqual(msgs[0]['to'], '+552222222')
        self.assertEqual(msgs[0]['device'], 'android')
        self.assertEqual(msgs[0]['size'], '1024')
        self.assertEqual(msgs[0]['style'], 'photo')

    def test_valor_orfao_apos_pagebreak(self):
        """Rótulo numa página, valor órfão na seguinte — o registro não se perde."""
        recs = parse_html_records(FULL_HTML)
        msgs = [r for r in recs if r['type'] == 'message/text']
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]['ip'], '198.51.100.9')

    def test_alvo_extraido_do_request_parameters(self):
        recs = parse_html_records(FULL_HTML)
        self.assertTrue(all(r['target'] == '+5511999990000' for r in recs))

    def test_source_propagado(self):
        recs = parse_html_records(FULL_HTML, source='origem.zip')
        self.assertTrue(all(r['source'] == 'origem.zip' for r in recs))


class TestRecordsToDataframe(unittest.TestCase):
    def test_linha_sem_ip_e_mantida(self):
        df = records_to_dataframe([{
            'type': 'call', 'event': 'terminate', 'ip': '',
            'timestamp': '2026-01-01 11:03:00 UTC',
        }])
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['Sender IP'], '')
        self.assertEqual(df.iloc[0]['Evento'], 'terminate')

    def test_ip_invalido_preservado_e_contado(self):
        df = records_to_dataframe([{
            'type': 'message/text', 'ip': 'nao-e-ip',
            'timestamp': '2026-01-01 10:00:00 UTC',
        }])
        self.assertEqual(len(df), 1)
        # Valor bruto preservado — evidência não se inventa nem se apaga
        self.assertEqual(df.iloc[0]['Sender IP'], 'nao-e-ip')

    def test_novas_colunas_presentes(self):
        df = records_to_dataframe(parse_html_records(FULL_HTML))
        for col in ('To', 'Evento', 'Call_Id', 'Call_Creator', 'Message_Id',
                    'Sender_Device', 'Media_Type', 'Msg_Size', 'Msg_Style',
                    'Alvo', 'Fonte'):
            self.assertIn(col, df.columns)
        self.assertEqual(df.iloc[0]['Alvo'], '+5511999990000')
        # Colunas novas também no contrato de exportação
        for col in ('Call_Id', 'Alvo', 'Fonte', 'Evento'):
            self.assertIn(col, COLUNAS_EXPORT_INTERCEPTACAO)
            self.assertIn(col, COLUNAS_INTERCEPTACAO)

    def test_periodo_derivado_sem_fabricacao(self):
        df = records_to_dataframe([{
            'type': 'login', 'ip': '203.0.113.10',
            'timestamp': 'lixo-invalido',
        }])
        self.assertEqual(len(df), 1)
        self.assertTrue(pd.isna(df.iloc[0]['Periodo']) or df.iloc[0]['Periodo'] in (None, ''))

    def test_reputacao_vazia_sem_ip_valido(self):
        """Evento sem IP não pode ser rotulado 'Residencial' — seria fabricar evidência."""
        from interception_parser import _add_reputacao_interceptacao
        df = records_to_dataframe([
            {'type': 'call', 'event': 'terminate', 'ip': '',
             'timestamp': '2026-01-01 11:03:00 UTC'},
            {'type': 'login', 'ip': '203.0.113.10',
             'timestamp': '2026-01-01 09:00:00 UTC'},
        ])
        df = _add_reputacao_interceptacao(df)
        self.assertEqual(df.iloc[0]['Reputação'], '')
        self.assertNotEqual(df.iloc[1]['Reputação'], '')


class TestParseZipInterception(unittest.TestCase):
    @staticmethod
    def _zip_realista():
        """ZIP de ZIP no formato do artefato real."""
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w') as iz:
            iz.writestr('records.html', FULL_HTML)
            iz.writestr('instructions.txt', 'x')
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, 'w') as oz:
            oz.writestr('INTERCEPTACAO/058859320268925.zip', inner.getvalue())
        return outer.getvalue()

    def test_zip_de_zips_com_fonte(self):
        df = parse_zip_interception(self._zip_realista())
        self.assertEqual(len(df), 6)  # 2 msg + 2 call events + 2 logins
        self.assertTrue((df['Fonte'] == '058859320268925.zip').all())
        self.assertTrue((df['Alvo'] == '+5511999990000').all())
        self.assertEqual(int(df['type'].str.startswith('login').sum()), 2)


@pytest.mark.slow
class TestZipRealIntegracao(unittest.TestCase):
    """Integração com o artefato real do caso (roda só se presente)."""

    REAL_ZIP = os.path.join(ROOT_DIR, 'INTERCEPTAÇÃO TELEMÁTICA.zip')

    def test_contagens_do_artefato_real(self):
        if not os.path.exists(self.REAL_ZIP):
            self.skipTest('ZIP real não está no repositório')
        df = parse_zip_interception(self.REAL_ZIP)
        # Contagens observadas no artefato (15 ZIPs internos)
        self.assertEqual(df['Fonte'].nunique(), 15)
        self.assertEqual(len(df), 63006)
        self.assertEqual(int(df['type'].str.startswith('login').sum()), 50854)
        self.assertEqual(int(df['type'].str.startswith('message').sum()), 11343)
        self.assertEqual(int(df['type'].str.startswith('call').sum()), 809)
        # Metadados forenses presentes em todo evento de chamada
        calls = df[df['type'].str.startswith('call', na=False)]
        self.assertTrue((calls['Call_Id'].astype(str).str.len() > 0).all())
        # Nenhum IP inválido descartado neste artefato
        self.assertTrue((df['Sender IP'].astype(str).str.len() > 0).all())
