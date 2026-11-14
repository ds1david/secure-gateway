import argparse
import base64
import contextlib
import copy
import datetime
import http.client
import io
import json
import os
import hashlib
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import unittest
import uuid
from unittest import mock

import jwt
import https_poc as h
import make_lab_certs
import poc
import prepare_https
import homologation
from test_poc import TempDirectory


class HTTPSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TempDirectory()
        from pathlib import Path
        cls.root = Path(cls.temp.name)
        make_lab_certs.generate(cls.root / 'certs', openssl=shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe')
        prepare_https.prepare(cls.root / 'certs', cls.root / 'bundles', 'localhost', 'localhost')
        cls.gateway = h.read_config(cls.root / 'bundles/gateway/config.json')
        cls.agent = h.read_config(cls.root / 'bundles/agent/config.json')
        cls.client = h.read_config(cls.root / 'bundles/client/config.json')
        cls.state = h.State(cls.gateway)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(h.file(cls.gateway, 'tls_cert'), h.file(cls.gateway, 'tls_key'))
        mtls = poc.tls(h.file(cls.gateway, 'tls_ca'), h.file(cls.gateway, 'tls_cert'), h.file(cls.gateway, 'tls_key'), True)
        cls.api = h.API(('127.0.0.1', 0), cls.state, server_tls)
        cls.clients = h.Clients(('127.0.0.1', 0), cls.state, mtls)
        cls.agent['agent_url'] = 'https://localhost:' + str(cls.api.server_address[1])
        cls.client['client_host'], cls.client['client_port'] = 'localhost', cls.clients.server_address[1]
        cls.lab = poc.http.server.HTTPServer(('127.0.0.1', 18765), poc.Lab)
        cls.echo = poc.socketserver.TCPServer(('127.0.0.1', 18766), poc.Echo)
        cls.output = io.StringIO()
        cls.capture = contextlib.redirect_stdout(cls.output)
        cls.capture.__enter__()
        cls.servers = (cls.api, cls.clients, cls.lab, cls.echo)
        cls.threads = []
        for server in cls.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(10)
        cls.state.replay.db.close()
        cls.capture.__exit__(None, None, None)
        assert 'PRIVATE KEY' not in cls.output.getvalue()
        cls.temp.cleanup()

    def setUp(self):
        self.state.rates.clear()

    @contextlib.contextmanager
    def token_client(self, services=('lab-status', 'lab-echo')):
        token = secrets.token_urlsafe(32)
        identity = 'test-client-01'
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        policy = {'enabled': True, 'services': list(services), 'expires_utc': expires.strftime('%Y-%m-%dT%H:%M:%SZ'),
                  'token_sha256': hashlib.sha256(token.encode()).hexdigest()}
        old_mode = self.gateway.get('client_auth')
        old_clients = self.gateway.get('token_clients')
        self.gateway['client_auth'], self.gateway['token_clients'] = 'token', {identity: policy}
        server = h.Clients(('127.0.0.1', 0), self.state, h.client_tls_context(self.gateway))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = copy.deepcopy(self.client)
        config.update(client_auth='token', client_id=identity, client_token_file='test-client.token',
                      client_port=server.server_address[1], proxy_port=0)
        config.pop('tls_cert', None)
        config.pop('tls_key', None)
        token_path = config['_root'] / 'test-client.token'
        token_path.write_text(token, encoding='ascii')
        try:
            yield config, policy, token
        finally:
            server.shutdown()
            server.server_close()
            thread.join(10)
            token_path.unlink(missing_ok=True)
            if old_mode is None:
                self.gateway.pop('client_auth', None)
            else:
                self.gateway['client_auth'] = old_mode
            if old_clients is None:
                self.gateway.pop('token_clients', None)
            else:
                self.gateway['token_clients'] = old_clients

    def test_client_token_without_client_certificate_and_no_secret_logs(self):
        with self.token_client() as (config, policy, token):
            with h.client_socket(config, 'lab-status', 'check'):
                pass
            self.assertNotIn(token, self.output.getvalue())
            (config['_root'] / 'test-client.token').write_text('wrong-token-' * 4)
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')

    def test_token_scope_expiry_revocation_and_missing_token(self):
        with self.token_client(('lab-status',)) as (config, policy, token):
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-echo', 'check')
            policy['enabled'] = False
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')
            policy['enabled'] = True
            policy['expires_utc'] = '2000-01-01T00:00:00Z'
            with self.assertRaises(ValueError):
                h.client_socket(config, 'lab-status', 'check')
            context = ssl.create_default_context(cafile=h.file(config, 'tls_ca'))
            with socket.create_connection(('127.0.0.1', config['client_port']), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname='localhost') as peer:
                    poc.send(peer, {'op': 'check', 'service': 'lab-status', 'client_id': config['client_id']})
                    self.assertEqual({'error': 'denied'}, poc.receive(peer))

    def test_token_client_still_checks_server_hostname(self):
        with self.token_client() as (config, policy, token):
            config['client_host'] = '127.0.0.1'
            with self.assertRaises(ssl.SSLCertVerificationError):
                h.client_socket(config, 'lab-status', 'check')

    def test_preflight_reports_connectivity_not_application_login(self):
        connection = mock.MagicMock()
        connection.getresponse.return_value.status = 401
        with mock.patch.object(h, 'service_allowed', return_value=True), \
                mock.patch.object(h.Channel, 'request', return_value={'ready': True}), \
                mock.patch.object(h.socket, 'getaddrinfo', return_value=[]), \
                mock.patch.object(h.http.client, 'HTTPSConnection', return_value=connection), \
                mock.patch.object(h.http.client, 'HTTPConnection', return_value=connection):
            result = h.preflight(self.agent, ['gitlab', 'artifactory'])
            self.assertTrue(result['ready'])
            self.assertEqual(2, len(result['checks']))
            self.assertEqual('not_tested_on_agent', result['checks'][0]['application_login'])
            connection.getresponse.return_value.status = 403
            with self.assertRaises(h.ChannelError) as failure:
                h.preflight(self.agent, ['gitlab'])
            self.assertEqual('target_http_not_ready', h.diagnostics(failure.exception)['reason'])

    def test_preflight_failure_never_starts_agent_or_writes_ready_marker(self):
        path = self.root / 'bundles/agent/preflight-config.json'
        path.write_text(json.dumps({key: value for key, value in self.agent.items() if key != '_root'}))
        marker = self.root / 'must-not-exist.json'
        with mock.patch('sys.argv', ['https_poc.py', 'agent', '--config', str(path),
                                     '--service', 'homologation', '--preflight', '--ready-file', str(marker)]), \
                mock.patch.object(h.signal, 'signal'), \
                mock.patch.object(h, 'preflight', side_effect=h.ChannelError('target_http_not_ready', 'target_preflight', 403)), \
                mock.patch.object(h, 'agent_pool') as pool:
            with self.assertRaises(h.ChannelError):
                h.main()
            pool.assert_not_called()
            self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell unavailable')
    def test_background_launcher_status_stop_and_pid_reuse_guard(self):
        path = self.root / 'bundles/agent/background-config.json'
        path.write_text(json.dumps({key: value for key, value in self.agent.items() if key != '_root'}))
        runtime = self.root / 'runtime'
        script = self.root.parents[1] / 'Start-RestrictedLab.ps1'
        def invoke(mode):
            # Windows children may inherit pipe handles even after PowerShell exits.
            # Capture to ordinary files so a correctly detached child cannot hold
            # unittest's communicate() open.
            output = self.root / ('launcher-' + uuid.uuid4().hex + '.out')
            errors = output.with_suffix('.err')
            with output.open('w', encoding='utf-8') as stdout, errors.open('w', encoding='utf-8') as stderr:
                result = subprocess.run(['powershell', '-NoProfile', '-File', str(script), '-Mode', mode,
                                         '-Service', 'lab-status', '-Config', str(path),
                                         '-RuntimeDirectory', str(runtime)], stdout=stdout, stderr=stderr, timeout=60)
            result.stdout = output.read_text(encoding='utf-8-sig', errors='replace')
            result.stderr = errors.read_text(encoding='utf-8-sig', errors='replace')
            return result
        try:
            result = invoke('Agent')
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            record = json.loads((runtime / 'agent.json').read_text(encoding='utf-8-sig'))
            self.assertEqual('agent_running', record['event'])
            self.assertNotEqual(os.getpid(), record['pid'])
            status = invoke('Status')
            self.assertEqual(record['pid'], json.loads(status.stdout)['pid'])
            with h.client_socket(self.client, 'lab-status') as sock:
                sock.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(sock)
                response.begin()
                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
        finally:
            stopped = invoke('Stop')
            self.assertEqual(0, stopped.returncode, stopped.stdout + stopped.stderr)
        self.assertFalse((runtime / 'agent.json').exists())
        (runtime / 'agent.json').write_text(json.dumps({'pid': os.getpid(), 'start_ticks': '0', 'executable': 'wrong'}))
        refused = invoke('Stop')
        self.assertNotEqual(0, refused.returncode)
        (runtime / 'agent.json').unlink()

    def test_concurrent_sessions_for_two_services(self):
        previous = self.gateway.get('max_sessions')
        previous_idle = self.gateway.get('idle_seconds')
        self.gateway['max_sessions'] = 2
        self.gateway['idle_seconds'] = 30
        with self.token_client() as (config, policy, token):
            stop = threading.Event()
            pool = threading.Thread(target=h.agent_pool, args=(self.agent, ['lab-status', 'lab-echo'], stop), daemon=True)
            pool.start()
            try:
                with h.client_socket(config, 'lab-status') as first, h.client_socket(config, 'lab-echo') as second:
                    with self.state.lock:
                        self.assertEqual(2, len(self.state.jobs))
                    second.sendall(b'two-services')
                    self.assertEqual(b'two-services', poc.exact(second, 12, time.monotonic() + 12))
                    first.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    response = http.client.HTTPResponse(first)
                    response.begin()
                    self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
            finally:
                stop.set()
                pool.join(15)
                self.assertFalse(pool.is_alive())
                if previous is None:
                    self.gateway.pop('max_sessions', None)
                else:
                    self.gateway['max_sessions'] = previous
                if previous_idle is None:
                    self.gateway.pop('idle_seconds', None)
                else:
                    self.gateway['idle_seconds'] = previous_idle

    def test_homologation_policies_preserve_tls_and_record_pending_corporate_approval(self):
        with TempDirectory() as directory:
            from pathlib import Path
            directory = Path(directory)
            output = directory / 'policies'
            summary = homologation.prepare(output, requested_by='test-operator')
            another = directory / 'other-client'
            homologation.prepare(another, client_id='other-client', requested_by='test-operator', services=['gitlab'])
            self.assertNotEqual((output / 'client.token').read_text(), (another / 'client.token').read_text())
            token = (output / 'client.token').read_text().strip()
            self.assertNotIn(token, json.dumps(summary))
            for role, original in (('gateway', self.gateway), ('agent', self.agent), ('client', self.client)):
                target = directory / (role + '-config.json')
                original = {key: value for key, value in original.items() if key != '_root'}
                target.write_text(json.dumps(original))
                backup = homologation.apply(target, output / (role + '-policy.json'))
                updated = h.read_config(target)
                self.assertEqual(original, json.loads(Path(backup).read_text()))
                for field in ('tls_cert', 'tls_key', 'tls_ca', 'signing_key', 'replay_db', 'agent_url'):
                    self.assertEqual(original.get(field), updated.get(field))
                self.assertTrue(h.service_allowed(updated, 'gitlab'))
                self.assertTrue(h.service_allowed(updated, 'artifactory'))
                self.assertEqual('pending', updated['services']['gitlab']['test_authorization']['corporate_approval'])
                end = h.utc_expiry(updated['services']['gitlab']['test_authorization']['expires_utc'])
                with mock.patch.object(h.time, 'time', return_value=end + 1):
                    self.assertFalse(h.service_allowed(updated, 'gitlab'))
                if role == 'gateway':
                    self.assertNotIn(token, target.read_text())
                    homologation.revoke(target, summary['client_id'])
                    self.assertFalse(h.read_config(target)['token_clients'][summary['client_id']]['enabled'])
                    homologation.apply(target, another / 'gateway-policy.json')
                    identities = h.read_config(target)['token_clients']
                    self.assertFalse(identities[summary['client_id']]['enabled'])
                    self.assertEqual(['gitlab'], identities['other-client']['services'])

    def test_local_proxy_http_and_connect_with_token(self):
        for service in ('lab-status', 'lab-echo'):
            with self.token_client() as (config, policy, token):
                stop, agent = self.run_agent(service)
                with h.LocalProxy(config) as proxy:
                    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
                    thread.start()
                    try:
                        with socket.create_connection(proxy.server_address, timeout=12) as local:
                            if service == 'lab-status':
                                local.sendall(b'GET http://127.0.0.1:18765/status HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
                                response = http.client.HTTPResponse(local)
                                response.begin()
                                self.assertEqual(200, response.status)
                                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
                            else:
                                local.sendall(b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\nHost: localhost\r\n\r\n')
                                header = b''
                                while not header.endswith(b'\r\n\r\n'):
                                    header += local.recv(1)
                                self.assertIn(b'200 Connection Established', header)
                                local.sendall(b'proxy-echo-fixture')
                                self.assertEqual(b'proxy-echo-fixture', poc.exact(local, 18, time.monotonic() + 12))
                    finally:
                        proxy.shutdown()
                        thread.join(10)
                        stop.set()
                        agent.join(15)

    def test_local_proxy_denies_unknown_destination_without_gateway_connection(self):
        with self.token_client() as (config, policy, token), h.LocalProxy(config) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.object(h, 'client_socket') as gateway:
                    with socket.create_connection(proxy.server_address, timeout=5) as local:
                        local.sendall(b'CONNECT forbidden.invalid:443 HTTP/1.1\r\nHost: forbidden.invalid\r\n\r\n')
                        self.assertIn(b'403 Forbidden', local.recv(4096))
                    gateway.assert_not_called()
            finally:
                proxy.shutdown()
                thread.join(10)

    def test_signed_check_and_client_mtls(self):
        self.assertEqual({'ready': True}, h.Channel(self.agent).request({'action': 'check', 'service': 'lab-status'}))
        with h.client_socket(self.client, 'lab-status', 'check'):
            pass

    def test_real_targets_disabled_at_agent_and_gateway(self):
        for service in ('gitlab', 'artifactory'):
            self.assertFalse(h.service_allowed(self.agent, service))
            with self.assertRaises(ValueError):
                h.client_socket(self.client, service)
            with self.assertRaises(ValueError):
                h.Channel(self.agent).request({'action': 'poll', 'service': service})

    def test_expired_or_incomplete_approval_denied(self):
        config = copy.deepcopy(self.agent)
        entry = config['services']['gitlab']
        entry['enabled'] = True
        for approval in ({}, {'agent_id': config['agent_id'], 'endpoint_security': 'ticket',
                            'service_owner': 'ticket', 'expires_utc': 'invalid'},
                         {'agent_id': config['agent_id'], 'endpoint_security': 'ticket',
                          'service_owner': 'ticket', 'expires_utc': '2000-01-01T00:00:00Z'}):
            entry['approval'] = approval
            self.assertFalse(h.service_allowed(config, 'gitlab'))

    def test_gateway_signature_and_response_binding_required(self):
        channel = h.Channel(self.agent)
        token = self.state.signer.sign(self.agent['agent_id'], {'ready': True}, 'wrong-request')
        decoded = h.decode(token, h.file(self.agent, 'gateway_public'), self.agent['gateway_id'], self.agent['agent_id'])
        self.assertEqual('wrong-request', decoded['reply_to'])
        fake_response = mock.MagicMock(status=200)
        fake_response.read.return_value = token.encode()
        fake_response.getheader.return_value = 'application/jwt'
        with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = fake_response
            with self.assertRaisesRegex(ValueError, 'application_response_binding_invalid'):
                channel.request({'action': 'check', 'service': 'lab-status'})
        wrong = h.Signer(self.agent['gateway_id'], h.file(self.agent, 'signing_key')).sign(self.agent['agent_id'], {'ready': True})
        with self.assertRaises(jwt.InvalidSignatureError):
            h.decode(wrong, h.file(self.agent, 'gateway_public'), self.agent['gateway_id'], self.agent['agent_id'])

    def test_http_error_status_and_html_are_diagnosed_without_content(self):
        channel = h.Channel(self.agent)
        for status in (403, 404, 407, 502, 503):
            response = mock.MagicMock(status=status)
            response.read.return_value = b'sensitive proxy response body'
            with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
                connection.return_value.getresponse.return_value = response
                with self.assertRaises(h.ChannelError) as failure:
                    channel.request({'action': 'check', 'service': 'lab-status'})
            self.assertEqual({'reason': 'https_http_error', 'stage': 'http_response',
                              'http_status': status}, h.diagnostics(failure.exception))
            response.read.assert_not_called()
        response = mock.MagicMock(status=200)
        response.getheader.return_value = 'text/html; charset=utf-8'
        with mock.patch.object(h.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaises(h.ChannelError) as failure:
                channel.request({'action': 'check', 'service': 'lab-status'})
        self.assertEqual('https_unexpected_content_type', h.diagnostics(failure.exception)['reason'])
        response.read.assert_not_called()

    def test_expired_or_modified_agent_message_rejected(self):
        signer = h.Channel(self.agent).signer
        token = signer.sign(self.agent['gateway_id'], {'action': 'check', 'service': 'lab-status'})
        claims = jwt.decode(token, options={'verify_signature': False})
        claims['iat'], claims['nbf'], claims['exp'] = int(time.time()) - 60, int(time.time()) - 60, int(time.time()) - 30
        expired = jwt.encode(claims, signer.key, algorithm='RS256')
        with self.assertRaises(jwt.ExpiredSignatureError):
            h.decode(expired, h.file(self.gateway, 'agent_public'), self.agent['agent_id'], self.agent['gateway_id'])
        parts = token.split('.')
        claims['body']['service'] = 'gitlab'
        parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        with self.assertRaises(jwt.InvalidSignatureError):
            h.decode('.'.join(parts), h.file(self.gateway, 'agent_public'), self.agent['agent_id'], self.agent['gateway_id'])

    def test_sequence_and_block_limits(self):
        job = {'id': 'fixture', 'service': 'lab-echo', 'assigned': True,
               'done': threading.Event(), 'seq': 0}
        with self.state.lock:
            self.state.jobs['fixture'] = job
        try:
            body = {'action': 'exchange', 'service': 'lab-echo', 'job': 'fixture',
                    'seq': 1, 'data': '', 'closed': False, 'ready': True}
            with self.assertRaises(ValueError):
                self.state.exchange(body)
            body['seq'] = 0
            body['data'] = base64.b64encode(b'x' * (h.BLOCK + 1)).decode()
            with self.assertRaises(ValueError):
                self.state.exchange(body)
        finally:
            with self.state.lock:
                self.state.jobs.pop('fixture', None)

    def test_http_transport_does_not_disable_hostname_validation(self):
        config = copy.deepcopy(self.agent)
        config['agent_url'] = 'https://127.0.0.1:' + str(self.api.server_address[1])
        with self.assertRaises(ssl.SSLCertVerificationError):
            h.Channel(config).request({'action': 'check', 'service': 'lab-status'})

    @unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell unavailable')
    def test_powershell_launcher_check(self):
        for role, config, script_name in (('agent', self.agent, 'Start-RestrictedLab.ps1'),
                                           ('client', self.client, 'Start-HttpsClient.ps1')):
            config_path = self.root / ('bundles/' + role + '/config.json')
            serializable = {key: value for key, value in config.items() if key != '_root'}
            config_path.write_text(json.dumps(serializable), encoding='utf-8')
            script = self.root.parents[1] / script_name
            result = subprocess.run(['powershell', '-NoProfile', '-File', str(script), '-Mode', 'Check',
                                     '-Config', str(config_path)], capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('"ready": true', result.stdout)

    def test_replay_rejected_over_https(self):
        channel = h.Channel(self.agent)
        token = channel.signer.sign(self.agent['gateway_id'], {'action': 'check', 'service': 'lab-status'})
        statuses = []
        for _ in range(2):
            connection = http.client.HTTPSConnection('localhost', self.api.server_address[1], context=channel.context, timeout=5)
            connection.request('POST', '/v1/exchange', token)
            response = connection.getresponse()
            statuses.append(response.status)
            response.read()
            connection.close()
        self.assertEqual([200, 403], statuses)

    def test_replay_survives_database_reopen(self):
        path = self.root / 'replay-test.sqlite'
        first = h.ReplayStore(path)
        message = {'jti': 'a' * 32, 'exp': int(time.time()) + 30}
        first.claim(message)
        first.db.close()
        second = h.ReplayStore(path)
        try:
            with self.assertRaises(ValueError):
                second.claim(message)
        finally:
            second.db.close()

    def run_agent(self, service):
        stop = threading.Event()
        thread = threading.Thread(target=h.agent, args=(self.agent, service, stop), daemon=True)
        thread.start()
        return stop, thread

    def test_http_fixture_roundtrip(self):
        stop, thread = self.run_agent('lab-status')
        try:
            with h.client_socket(self.client, 'lab-status') as sock:
                sock.sendall(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(sock)
                response.begin()
                self.assertEqual(200, response.status)
                self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read(4096)))
        finally:
            stop.set()
            thread.join(15)
            self.assertFalse(thread.is_alive())

    def test_binary_echo_roundtrip(self):
        stop, thread = self.run_agent('lab-echo')
        try:
            with h.client_socket(self.client, 'lab-echo') as sock:
                payload = b'\x00\xff synthetic fixture'
                sock.sendall(payload)
                self.assertEqual(payload, poc.exact(sock, len(payload), time.monotonic() + 10))
        finally:
            stop.set()
            thread.join(15)
            self.assertFalse(thread.is_alive())

    @contextlib.contextmanager
    def external_proxy(self):
        with h.ExternalProxy(('127.0.0.1', 0), self.state, h.client_tls_context(self.gateway)) as proxy:
            thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            thread.start()
            try:
                yield proxy
            finally:
                proxy.shutdown()
                thread.join(10)

    def proxy_request(self, proxy, request):
        context = ssl.create_default_context(cafile=h.file(self.client, 'tls_ca'))
        raw = socket.create_connection(proxy.server_address, timeout=15)
        peer = context.wrap_socket(raw, server_hostname='localhost')
        try:
            peer.sendall(request)
            return peer
        except BaseException:
            peer.close()
            raise

    def test_external_proxy_authentication_challenge_and_invalid_credentials(self):
        with self.token_client() as (config, policy, token), self.external_proxy() as proxy:
            cases = [b'', b'Proxy-Authorization: Basic invalid\r\n',
                     b'Proxy-Authorization: Basic ' + base64.b64encode(b'unknown:bad') + b'\r\n']
            for auth in cases:
                with self.proxy_request(proxy, b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                    reply = peer.recv(4096)
                    self.assertIn(b'407 Proxy Authentication Required', reply)
                    self.assertIn(b'Proxy-Authenticate: Basic', reply)
            auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
            for field, value in [('enabled', False), ('expires_utc', '2000-01-01T00:00:00Z')]:
                old = policy[field]
                policy[field] = value
                with self.proxy_request(proxy, b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                    self.assertIn(b'407 Proxy Authentication Required', peer.recv(4096))
                policy[field] = old
            self.assertNotIn(token, self.output.getvalue())

    def test_external_proxy_http_connect_scope_and_destination(self):
        for service in ('lab-status', 'lab-echo'):
            with self.token_client() as (config, policy, token), self.external_proxy() as proxy:
                auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
                stop, agent = self.run_agent(service)
                try:
                    if service == 'lab-status':
                        request = b'GET http://127.0.0.1:18765/status HTTP/1.1\r\n' + auth + b'\r\n'
                        with self.proxy_request(proxy, request) as peer:
                            response = http.client.HTTPResponse(peer)
                            response.begin()
                            self.assertEqual(200, response.status)
                            self.assertEqual(poc.SERVICES['lab-status'][1], json.loads(response.read()))
                    else:
                        request = b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\n' + auth + b'\r\n'
                        with self.proxy_request(proxy, request) as peer:
                            header = b''
                            while not header.endswith(b'\r\n\r\n'):
                                header += peer.recv(1)
                            self.assertIn(b'200 Connection Established', header)
                            peer.sendall(b'external-proxy-fixture')
                            self.assertEqual(b'external-proxy-fixture', poc.exact(peer, 22, time.monotonic() + 12))
                    policy['services'] = []
                    with self.proxy_request(proxy, b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                        self.assertIn(b'403 Forbidden', peer.recv(4096))
                    with self.proxy_request(proxy, b'CONNECT forbidden.invalid:443 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                        self.assertIn(b'403 Forbidden', peer.recv(4096))
                finally:
                    stop.set()
                    agent.join(15)
                    self.assertFalse(agent.is_alive())
                self.assertNotIn(token, self.output.getvalue())

    @contextlib.contextmanager
    def tls_origin(self):
        with http.server.HTTPServer(('127.0.0.1', 0), poc.Lab) as origin:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(h.file(self.gateway, 'tls_cert'), h.file(self.gateway, 'tls_key'))
            origin.socket = tls.wrap_socket(origin.socket, server_side=True)
            thread = threading.Thread(target=origin.serve_forever, daemon=True)
            thread.start()
            try:
                yield origin
            finally:
                origin.shutdown()
                thread.join(10)

    def test_external_proxy_nested_tls_preserves_origin_certificate(self):
        with self.token_client() as (config, policy, token), self.tls_origin() as origin:
            name = 'lab-tls'
            with mock.patch.dict(h.TARGETS, {name: ('localhost', origin.server_address[1])}), \
                 mock.patch.dict(self.gateway['services'], {name: {'enabled': True}}), \
                 mock.patch.dict(self.agent['services'], {name: {'enabled': True}}):
                policy['services'].append(name)
                stop, agent = self.run_agent(name)
                try:
                    with self.external_proxy() as proxy:
                        auth = base64.b64encode((config['client_id'] + ':' + token).encode())
                        request = (b'CONNECT localhost:' + str(origin.server_address[1]).encode()
                            + b' HTTP/1.1\r\nProxy-Authorization: Basic ' + auth + b'\r\n\r\n')
                        with self.proxy_request(proxy, request) as outer:
                            header = b''
                            while not header.endswith(b'\r\n\r\n'):
                                header += outer.recv(1)
                            self.assertIn(b'200 Connection Established', header)
                            # MemoryBIO keeps origin TLS inside the existing proxy TLS.
                            # Both contexts verify the fixture CA and hostname, without
                            # disabling certificate or revocation checks on any client.
                            context = ssl.create_default_context(cafile=h.file(config, 'tls_ca'))
                            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                            inner = context.wrap_bio(incoming, outgoing, server_hostname='localhost')
                            def flush():
                                while outgoing.pending:
                                    outer.sendall(outgoing.read())
                            while True:
                                try:
                                    inner.do_handshake()
                                    flush()
                                    break
                                except ssl.SSLWantReadError:
                                    flush()
                                    data = outer.recv(32768)
                                    self.assertTrue(data)
                                    incoming.write(data)
                            inner.write(b'GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n')
                            flush()
                            response = b''
                            while b'\r\n\r\n' not in response or poc.SERVICES['lab-status'][1] != self.fixture_body(response):
                                try:
                                    block = inner.read(4096)
                                    self.assertTrue(block)
                                    response += block
                                except ssl.SSLWantReadError:
                                    flush()
                                    block = outer.recv(32768)
                                    self.assertTrue(block)
                                    incoming.write(block)
                            self.assertIn(b'200 OK', response)
                finally:
                    stop.set()
                    agent.join(15)
            self.assertNotIn(token, self.output.getvalue())

    @staticmethod
    def fixture_body(response):
        try:
            return json.loads(response.split(b'\r\n\r\n', 1)[1])
        except (ValueError, IndexError):
            return None

    def test_external_proxy_requires_tls_and_trusted_hostname(self):
        with self.token_client(), self.external_proxy() as proxy:
            context = ssl.create_default_context(cafile=h.file(self.client, 'tls_ca'))
            with socket.create_connection(proxy.server_address, timeout=5) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    context.wrap_socket(raw, server_hostname='wrong.invalid')
            with socket.create_connection(proxy.server_address, timeout=5) as raw:
                raw.sendall(b'CONNECT 127.0.0.1:18766 HTTP/1.1\r\n\r\n')
                try:
                    reply = raw.recv(4096)
                except ConnectionResetError:
                    reply = b''
                self.assertNotIn(b'200', reply)

    def test_external_proxy_pac_is_selective_without_direct_fallback_for_services(self):
        with self.token_client():
            self.gateway['external_proxy_host'] = 'secure-gateway.sicredi.space'
            self.gateway['external_proxy_port'] = 8443
            try:
                with self.external_proxy() as proxy:
                    with self.proxy_request(proxy, b'GET /proxy.pac HTTP/1.1\r\nHost: localhost\r\n\r\n') as peer:
                        response = http.client.HTTPResponse(peer)
                        response.begin()
                        self.assertEqual(200, response.status)
                        body = response.read().decode()
                        self.assertIn('HTTPS secure-gateway.sicredi.space:8443', body)
                        self.assertIn('host === "gitlab.sicredi.net"', body)
                        self.assertNotIn('8443; DIRECT', body)
            finally:
                self.gateway.pop('external_proxy_host')
                self.gateway.pop('external_proxy_port')

    def test_external_proxy_does_not_forward_proxy_credentials_to_origin(self):
        with self.token_client() as (config, policy, token), self.external_proxy() as proxy:
            auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
            local, remote = socket.socketpair()
            @contextlib.contextmanager
            def fake_stream(handler, service):
                try:
                    yield local
                finally:
                    local.close()
            with mock.patch.object(h.ExternalProxyHandler, 'open_remote', fake_stream):
                with self.proxy_request(proxy, b'GET http://127.0.0.1:18765/status HTTP/1.1\r\n'
                        + auth + b'Authorization: Basic origin-credential\r\nHost: wrong.invalid\r\n\r\n') as peer:
                    remote.settimeout(5)
                    request = remote.recv(4096)
                    self.assertNotIn(b'Proxy-Authorization', request)
                    self.assertNotIn(token.encode(), request)
                    self.assertIn(b'Authorization: Basic origin-credential', request)
                    self.assertIn(b'Host: 127.0.0.1:18765', request)
                    remote.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    self.assertIn(b'200 OK', peer.recv(4096))
            remote.close()

    @contextlib.contextmanager
    def maven_gateway(self):
        records = []
        pom = (b'<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>'
               b'<artifactId>demo-parent</artifactId><version>1.0</version><packaging>pom</packaging></project>')
        jar = bytes(range(256)) * 160
        class Origin(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_):
                pass
            def do_HEAD(self):
                self.do_GET()
            def do_GET(self):
                records.append((self.path, dict(self.headers)))
                if self.path.endswith('redirect.pom'):
                    self.send_response(302)
                    self.send_header('Location', 'https://forbidden.invalid/credential-target')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                status = 200
                body = jar if self.path.endswith('.jar') else pom
                if self.path.endswith('.sha1'):
                    body = hashlib.sha1(pom).hexdigest().encode()
                if self.path.endswith('missing.pom'):
                    status, body = 404, b'private upstream error details'
                if self.path.endswith('private.pom'):
                    status, body = 401, b'upstream login details'
                if self.headers.get('If-None-Match') == '"fixture"':
                    status, body = 304, b''
                if self.headers.get('Range') == 'bytes=0-3':
                    status, body = 206, body[:4]
                self.send_response(status)
                self.send_header('Connection', 'close')
                self.send_header('ETag', '"fixture"')
                self.send_header('Set-Cookie', 'upstream-cookie-must-not-escape')
                if status == 206:
                    self.send_header('Content-Range', 'bytes 0-3/' + str(len(jar)))
                if self.path.endswith(('chunked.jar', 'broken-chunked.jar')):
                    self.send_header('Transfer-Encoding', 'chunked')
                elif self.path.endswith('big.jar'):
                    self.send_header('Content-Length', str(20 * 1024 * 1024))
                elif self.path.endswith('partial.jar'):
                    self.send_header('Content-Length', str(len(body) + 17))
                elif self.path.endswith('bad.jar'):
                    self.send_header('Content-Length', '1')
                    self.send_header('Content-Length', '2')
                else:
                    self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if self.command == 'HEAD' or self.path.endswith(('big.jar', 'bad.jar')):
                    return
                try:
                    if self.path.endswith(('chunked.jar', 'broken-chunked.jar')):
                        for offset in range(0, len(body), 16384):
                            chunk = body[offset:offset + 16384]
                            self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                        if not self.path.endswith('broken-chunked.jar'):
                            self.wfile.write(b'0\r\n\r\n')
                    else:
                        self.wfile.write(body)
                except OSError:
                    pass
        with self.token_client(services=('artifactory',)) as (config, policy, token), \
                http.server.HTTPServer(('127.0.0.1', 0), Origin) as origin:
            server_thread = threading.Thread(target=origin.serve_forever, daemon=True)
            server_thread.start()
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            entry = {'enabled': True, 'test_authorization': {'kind': 'requester_authorized_test',
                'agent_id': self.gateway['agent_id'], 'requested_by': 'test-operator',
                'corporate_approval': 'pending', 'expires_utc': expires.strftime('%Y-%m-%dT%H:%M:%SZ')}}
            try:
                with mock.patch.dict(h.TARGETS, {'artifactory': ('127.0.0.1', origin.server_address[1])}), \
                     mock.patch.dict(self.gateway, {'operation_mode': 'homologation'}), \
                     mock.patch.dict(self.agent, {'operation_mode': 'homologation'}), \
                     mock.patch.dict(self.gateway['services'], {'artifactory': entry}), \
                     mock.patch.dict(self.agent['services'], {'artifactory': entry}):
                    stop, agent = self.run_agent('artifactory')
                    try:
                        with self.external_proxy() as proxy:
                            yield proxy, config, policy, token, records, pom, jar
                    finally:
                        stop.set()
                        agent.join(15)
                        self.assertFalse(agent.is_alive())
            finally:
                origin.shutdown()
                server_thread.join(10)

    @contextlib.contextmanager
    def maven_response(self, proxy, identity, token, path='demo.pom', method='GET', headers=b''):
        auth = b'' if token is None else b'Authorization: Basic ' + base64.b64encode((identity + ':' + token).encode()) + b'\r\n'
        request = (method.encode() + b' /maven/repo/' + path.encode() + b' HTTP/1.1\r\n'
                   b'Host: localhost\r\n' + auth + headers + b'\r\n')
        with self.proxy_request(proxy, request) as peer:
            with http.client.HTTPResponse(peer, method=method) as response:
                response.begin()
                yield response

    def test_maven_native_resolves_parent_over_authenticated_https(self):
        mvn = shutil.which('mvn') or shutil.which('mvn.cmd')
        keytool = shutil.which('keytool')
        if not mvn or not keytool:
            self.skipTest('Maven and keytool required for native integration')
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            work = self.root / 'native-maven'
            work.mkdir()
            truststore = work / 'truststore.p12'
            created = subprocess.run([keytool, '-importcert', '-noprompt', '-alias', 'fixture-ca',
                '-file', h.file(config, 'tls_ca'), '-keystore', str(truststore), '-storepass', 'fixturepass'],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(0, created.returncode, created.stderr)
            (work / 'pom.xml').write_text('<project><modelVersion>4.0.0</modelVersion>'
                '<parent><groupId>org.example</groupId><artifactId>demo-parent</artifactId>'
                '<version>1.0</version><relativePath/></parent><artifactId>fixture-child</artifactId>'
                '<packaging>pom</packaging></project>', encoding='utf-8')
            (work / 'global-settings.xml').write_text('<settings/>', encoding='utf-8')
            (work / 'settings.xml').write_text('<settings><servers><server><id>fixture-gateway</id>'
                '<username>' + config['client_id'] + '</username><password>${env.SECURE_GATEWAY_TOKEN}</password>'
                '</server></servers><mirrors><mirror><id>fixture-gateway</id><mirrorOf>*</mirrorOf>'
                '<url>https://localhost:' + str(proxy.server_address[1]) + '/maven/repo</url>'
                '</mirror></mirrors></settings>', encoding='utf-8')
            env = dict(os.environ)
            env.update(SECURE_GATEWAY_TOKEN=token, MAVEN_ARGS='',
                MAVEN_OPTS=f'-Djavax.net.ssl.trustStore={truststore} -Djavax.net.ssl.trustStorePassword=fixturepass')
            result = subprocess.run([mvn, '-B', '-U', '-s', str(work / 'settings.xml'),
                '-gs', str(work / 'global-settings.xml'), '-Dmaven.repo.local=' + str(work / 'repository'),
                '-f', str(work / 'pom.xml'), 'validate'], env=env, capture_output=True, text=True, timeout=90)
            output = result.stdout + result.stderr
            self.assertNotIn(token, output)
            self.assertEqual(0, result.returncode, output.replace(token, '<redacted>'))
            self.assertIn('BUILD SUCCESS', output)
            self.assertTrue(any('/org/example/demo-parent/1.0/demo-parent-1.0.pom' in path for path, _ in records))

    def test_maven_pom_checksum_head_and_credentials_never_reach_origin(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for method, path, expected in [('GET', 'org/example/demo-parent/1.0/demo-parent-1.0.pom', pom),
                                           ('GET', 'demo.pom.sha1', hashlib.sha1(pom).hexdigest().encode()),
                                           ('HEAD', 'demo.pom', b'')]:
                with self.maven_response(proxy, config['client_id'], token, path, method) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(expected, response.read())
                    self.assertIsNotNone(response.getheader('X-SecureGateway-Request-Id'))
                    self.assertIsNone(response.getheader('Set-Cookie'))
            self.assertEqual('/artifactory/repo/org/example/demo-parent/1.0/demo-parent-1.0.pom', records[0][0])
            for path, headers in records:
                self.assertNotIn('Authorization', headers)
                self.assertNotIn('Proxy-Authorization', headers)
                self.assertNotIn(token, repr(headers))
            self.assertNotIn(token, self.output.getvalue())

    def test_maven_binary_chunked_range_and_not_modified(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for path in ('demo.jar', 'chunked.jar'):
                with self.maven_response(proxy, config['client_id'], token, path) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(jar, response.read())
                    self.assertEqual('chunked' if path == 'chunked.jar' else None, response.getheader('Transfer-Encoding'))
            with self.maven_response(proxy, config['client_id'], token, 'demo.jar', headers=b'Range: bytes=0-3\r\n') as response:
                self.assertEqual(206, response.status)
                self.assertEqual(jar[:4], response.read())
            with self.maven_response(proxy, config['client_id'], token, headers=b'If-None-Match: "fixture"\r\n') as response:
                self.assertEqual(304, response.status)
                self.assertEqual(b'', response.read())

    def test_maven_truncated_transfers_are_detected_by_the_client(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for path in ('partial.jar', 'broken-chunked.jar'):
                with self.maven_response(proxy, config['client_id'], token, path) as response:
                    self.assertEqual(200, response.status)
                    with self.assertRaises(http.client.IncompleteRead):
                        response.read()
            self.assertIn('maven_upstream_truncated', self.output.getvalue())

    def test_maven_authentication_and_scope(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for supplied in (None, 'invalid-token-' * 4):
                with self.maven_response(proxy, config['client_id'], supplied) as response:
                    self.assertEqual(401, response.status)
                    self.assertIn('secure-gateway-maven', response.getheader('WWW-Authenticate'))
                    self.assertIsNone(response.getheader('Proxy-Authenticate'))
            for key, value in [('enabled', False), ('expires_utc', '2000-01-01T00:00:00Z')]:
                old = policy[key]
                policy[key] = value
                with self.maven_response(proxy, config['client_id'], token) as response:
                    self.assertEqual(401, response.status)
                policy[key] = old
            policy['services'] = ['gitlab']
            with self.maven_response(proxy, config['client_id'], token) as response:
                self.assertEqual(403, response.status)
            self.assertEqual([], records)

    def test_maven_rejects_writes_traversal_queries_and_request_bodies(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for method in ('POST', 'PUT', 'DELETE', 'CONNECT'):
                with self.maven_response(proxy, config['client_id'], token, method=method) as response:
                    self.assertEqual(405, response.status)
                    self.assertEqual('GET, HEAD', response.getheader('Allow'))
            for path in ('../secret', 'group/../secret', '%2e%2e/secret', '%252e%252e/secret',
                         'group//secret', 'demo.pom?token=not-a-real-secret', 'https://forbidden.invalid/a'):
                with self.maven_response(proxy, config['client_id'], token, path=path) as response:
                    self.assertEqual(400, response.status)
            with self.maven_response(proxy, config['client_id'], token, headers=b'Content-Length: 1\r\n') as response:
                self.assertEqual(400, response.status)
            self.assertEqual([], records)

    def test_maven_origin_errors_redirects_framing_and_size_limits(self):
        with self.maven_gateway() as (proxy, config, policy, token, records, pom, jar):
            for path, expected in [('missing.pom', 404), ('private.pom', 502), ('redirect.pom', 502),
                                   ('big.jar', 413), ('bad.jar', 502)]:
                with self.maven_response(proxy, config['client_id'], token, path) as response:
                    self.assertEqual(expected, response.status)
                    self.assertEqual(b'', response.read())
                    self.assertIsNone(response.getheader('Location'))
                    self.assertIsNone(response.getheader('WWW-Authenticate'))
            self.assertNotIn('credential-target', self.output.getvalue())
            self.assertNotIn(token, self.output.getvalue())

    def test_bundle_separates_private_keys(self):
        self.assertFalse((self.root / 'bundles/agent/gateway.key').exists())
        self.assertFalse((self.root / 'bundles/client/signing.key').exists())
        self.assertFalse((self.root / 'bundles/gateway/client.key').exists())
        self.assertFalse(any((self.root / 'bundles').rglob('ca.key')))


if __name__ == '__main__':
    unittest.main()
