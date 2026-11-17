import base64
import copy
import contextlib
import datetime
import hashlib
import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import homologation as admin
import https_poc as h
import web_lab
import web_policy as w
import test_https as fixtures


class WebPolicyTests(unittest.TestCase):
    def test_explicit_hosts_suffix_boundaries_ports_and_schema(self):
        policy = {'hosts': ['one.example'], 'suffixes': ['company.example'], 'ports': [80, 443],
                  'private_networks': [], 'lab_only': False}
        for host in ('one.example', 'company.example', 'api.company.example'):
            self.assertTrue(w.allows(policy, host, 443))
        for host in ('evilcompany.example', 'one.example.evil', 'one.example.', 'user@one.example', 'one.example/path'):
            self.assertFalse(w.allows(policy, host, 443))
        self.assertFalse(w.allows(policy, 'one.example', 22))
        self.assertFalse(w.allows(policy, 'one.example', True))
        for change in ({'ports': [22]}, {'suffixes': ['com']}, {'hosts': ['*']},
                       {'private_networks': ['0.0.0.0/0']}, {'private_networks': ['169.254.0.0/16']},
                       {'lab_only': 'yes'}, {'unknown': True}):
            with self.assertRaises(ValueError):
                w.validate({**policy, **change})
        with self.assertRaises(ValueError):
            w.validate({**w.lab_policy(), 'ports': [22]})

    def test_private_networks_explicit_and_special_addresses_never_allowed(self):
        policy = {'hosts': ['one.example'], 'suffixes': [], 'ports': [443],
                  'private_networks': ['10.20.30.0/24'], 'lab_only': False}
        self.assertTrue(w.address_allowed(policy, '10.20.30.5'))
        self.assertFalse(w.address_allowed(policy, '10.20.31.5'))
        self.assertTrue(w.address_allowed(policy, '1.1.1.1'))
        for ip in ('127.0.0.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1'):
            self.assertFalse(w.address_allowed(policy, ip), ip)
        self.assertTrue(w.address_allowed(w.lab_policy(), '127.0.0.1'))
        self.assertFalse(w.address_allowed(w.lab_policy(), '1.1.1.1'))

    def test_dns_pinning_mixed_addresses_denied_and_failure_codes(self):
        policy = {'hosts': ['one.example'], 'suffixes': [], 'ports': [443],
                  'private_networks': [], 'lab_only': False}
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 443))]
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
        with mock.patch.object(w.socket, 'getaddrinfo', return_value=public + private), mock.patch.object(w.socket, 'socket') as create:
            with self.assertRaisesRegex(w.WebPolicyError, 'web_address_denied'):
                w.connect(policy, 'one.example', 443)
            create.assert_not_called()
        with mock.patch.object(w.socket, 'getaddrinfo', return_value=public) as dns, mock.patch.object(w.socket, 'socket') as create:
            w.connect(policy, 'one.example', 443)
            create.return_value.connect.assert_called_once_with(('1.1.1.1', 443))
            dns.assert_called_once()
        with mock.patch.object(w.socket, 'getaddrinfo', side_effect=socket.gaierror('secret-in-exception')):
            with self.assertRaisesRegex(w.WebPolicyError, '^web_dns_failed$'):
                w.connect(policy, 'one.example', 443)

    def test_admin_preserves_token_other_clients_and_rotation_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin.prepare(root / 'initial', hours=24)
            config = root / 'config.json'
            config.write_text(json.dumps({'agent_id': 'windows-lab-01', 'signing_key': 'existing.key'}))
            admin.apply(config, root / 'initial/gateway-policy.json')
            original = json.loads(config.read_text())
            original['token_clients']['other'] = copy.deepcopy(original['token_clients']['intermediario-01'])
            config.write_text(json.dumps(original))
            policy = root / 'web.json'
            policy.write_text(json.dumps(w.lab_policy()))
            result = admin.configure_web_proxy(config, root / 'web', policy)
            updated = json.loads(config.read_text())
            before, after = original['token_clients']['intermediario-01'], updated['token_clients']['intermediario-01']
            self.assertEqual(before['token_sha256'], after['token_sha256'])
            self.assertEqual(before['expires_utc'], after['expires_utc'])
            self.assertEqual(original['token_clients']['other'], updated['token_clients']['other'])
            self.assertFalse(result['token_changed'])
            agent = (root / 'web/agent-policy.json').read_text()
            self.assertNotIn('token_sha256', agent)
            self.assertNotIn('existing.key', agent)
            self.assertEqual(w.lab_policy(), updated['services']['web']['web_policy'])
            admin.rotate_client_token(config, root / 'rotation', 'intermediario-01')
            rotated = json.loads(config.read_text())
            self.assertEqual(w.lab_policy(), rotated['services']['web']['web_policy'])
            self.assertEqual(w.lab_policy(), json.loads((root / 'rotation/agent-policy.json').read_text())['patch']['services']['web']['web_policy'])
            snapshot = config.read_bytes()
            policy.write_text(json.dumps({**w.lab_policy(), 'hosts': ['*']}))
            with self.assertRaises(ValueError):
                admin.configure_web_proxy(config, root / 'bad', policy)
            self.assertEqual(snapshot, config.read_bytes())

    def test_preflight_accepts_https_only_host_when_http_is_closed(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        policy = {'hosts': ['one.example'], 'suffixes': [], 'ports': [80, 443],
                  'private_networks': [], 'lab_only': False}
        config = {'agent_id': 'fixture', 'operation_mode': 'homologation', 'services': {
            'web': {'enabled': True, 'web_policy': policy, 'test_authorization': {
                'kind': 'requester_authorized_test', 'agent_id': 'fixture',
                'requested_by': 'fixture', 'corporate_approval': 'pending', 'expires_utc': expiry}}}}
        with mock.patch.object(h, 'Channel') as channel, mock.patch.object(w, 'connect', side_effect=[
                w.WebPolicyError('web_connect_failed'), contextlib.nullcontext()]) as connect:
            channel.return_value.request.return_value = {'ready': True}
            self.assertTrue(h.preflight(config, ['web'])['ready'])
            self.assertEqual([80, 443], [call.args[2] for call in connect.call_args_list])

    def test_specific_jwt_diagnostics_do_not_include_exception_text(self):
        import jwt
        for error, reason in ((jwt.ImmatureSignatureError('secret'), 'application_message_not_yet_valid'),
                              (jwt.InvalidAudienceError('secret'), 'application_audience_invalid'),
                              (jwt.InvalidIssuerError('secret'), 'application_issuer_invalid')):
            result = h.diagnostics(error)
            self.assertEqual(reason, result['reason'])
            self.assertNotIn('secret', json.dumps(result))
        self.assertEqual('web_address_denied', h.diagnostics(w.WebPolicyError('web_address_denied'))['reason'])


class WebProxyIntegration(unittest.TestCase):
    setUpClass = classmethod(fixtures.HTTPSIntegration.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.HTTPSIntegration.tearDownClass.__func__)
    token_client = fixtures.HTTPSIntegration.token_client
    external_proxy = fixtures.HTTPSIntegration.external_proxy
    proxy_request = fixtures.HTTPSIntegration.proxy_request
    run_agent = fixtures.HTTPSIntegration.run_agent

    def test_http_upload_download_redirect_websocket_and_denials(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        entry = {'enabled': True, 'web_policy': w.lab_policy(), 'test_authorization': {
            'kind': 'requester_authorized_test', 'agent_id': self.gateway['agent_id'],
            'requested_by': 'fixture', 'corporate_approval': 'pending', 'expires_utc': expiry}}
        with mock.patch.dict(self.gateway, {'operation_mode': 'homologation', 'external_proxy_host': 'localhost', 'max_sessions': 16, 'idle_seconds': 90}), \
             mock.patch.dict(self.gateway['services'], {'web': copy.deepcopy(entry)}), \
             mock.patch.dict(self.agent, {'operation_mode': 'homologation'}), \
             mock.patch.dict(self.agent['services'], {'web': copy.deepcopy(entry)}), \
             mock.patch.object(self.lab, 'RequestHandlerClass', web_lab.Handler), \
             self.token_client(('web',)) as (config, policy, token), self.external_proxy() as proxy:
            auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
            stop, agent = self.run_agent(['web', 'lab-echo'])
            def request(method, path, body=b''):
                head = method.encode() + b' http://localhost:18765' + path.encode() + b' HTTP/1.1\r\n' + auth
                head += b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
                with self.proxy_request(proxy, head + body) as peer:
                    response = http.client.HTTPResponse(peer)
                    response.begin()
                    return response.status, response.read(), response.getheader('Location')
            try:
                self.assertIn('host === "localhost"', proxy.pac)
                status, page, _ = request('GET', '/')
                self.assertEqual(200, status)
                self.assertIn(b'fetch(path,options)', page)
                self.assertEqual(200, request('GET', '/status')[0])
                upload = b'fixture-upload-content'
                status, body, _ = request('POST', '/upload', upload)
                self.assertEqual(200, status)
                self.assertEqual(hashlib.sha256(upload).hexdigest(), json.loads(body)['sha256'])
                self.assertEqual(web_lab.DOWNLOAD, request('GET', '/download')[1])
                self.assertEqual((302, b'', '/'), request('GET', '/redirect'))
                key = base64.b64encode(bytes(range(16)))
                with self.proxy_request(proxy, b'GET ws://localhost:18765/ws HTTP/1.1\r\n' + auth
                        + b'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + key + b'\r\n\r\n') as peer:
                    response = http.client.HTTPResponse(peer)
                    response.begin()
                    self.assertEqual(101, response.status)
                    mask, data = b'abcd', b'fixture-ws'
                    peer.sendall(b'\x81' + bytes([128 | len(data)]) + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(data)))
                    self.assertEqual(b'\x81' + bytes([len(data)]) + data, response.fp.read(2 + len(data)))
                    peer.sendall(b'\x88\x80abcd')
                for authority in (b'other.invalid:443', b'localhost:22', b'169.254.169.254:80'):
                    with self.proxy_request(proxy, b'CONNECT ' + authority + b' HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                        self.assertIn(b'403', peer.recv(4096))
                # Gateway allows the request, but the agent independently denies its destination.
                self.agent['services']['web']['web_policy'] = {'hosts': ['localhost'], 'suffixes': [],
                    'ports': [80, 443], 'private_networks': [], 'lab_only': False}
                self.assertEqual(502, request('GET', '/status')[0])
                self.agent['services']['web']['web_policy'] = w.lab_policy()
                policy['services'] = ['lab-status']
                self.assertEqual(403, request('GET', '/status')[0])
                self.assertNotIn(token, self.output.getvalue())
                self.assertNotIn('fixture-upload-content', self.output.getvalue())
            finally:
                stop.set()
                agent.join(10)
