import contextlib
import base64
import copy
import datetime
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import make_lab_certs
import web_lab
import web_policy
import https_poc as h
import test_https as fixtures

ROOT = Path(__file__).resolve().parents[1]
DOTNET = shutil.which('dotnet')
DLL = ROOT / 'yarp-poc/bin/Release/net10.0/SecureGateway.Yarp.dll'


def free_port():
    with socket.socket() as peer:
        peer.bind(('127.0.0.1', 0))
        return peer.getsockname()[1]


@unittest.skipUnless(DOTNET, 'YARP tests require .NET 10 SDK/runtime')
class YarpLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DLL.exists():
            subprocess.run([DOTNET, 'build', str(ROOT / 'yarp-poc/SecureGateway.Yarp.csproj'),
                            '-c', 'Release', '--nologo'], cwd=ROOT, check=True, capture_output=True, timeout=180)
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        openssl = shutil.which('openssl') or 'C:/Program Files/Git/usr/bin/openssl.exe'
        make_lab_certs.generate(cls.root / 'certs', openssl=openssl)
        make_lab_certs.generate(cls.root / 'wrong', hostname='wrong.invalid', openssl=openssl)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def origin(self, tls=False, wrong=False):
        class Origin(web_lab.Handler):
            def do_GET(self):
                if self.path == '/absolute':
                    self.response(302, headers=(('Location', self.server.origin_url + '/status'),))
                elif self.path == '/external':
                    self.response(302, headers=(('Location', 'https://denied.invalid/'),))
                elif self.path == '/cookie':
                    self.response(200, headers=(('Set-Cookie', 'fixture=ok; Path=/; HttpOnly'),))
                elif self.path == '/headers':
                    seen = {key.lower(): value for key, value in self.headers.items()}
                    self.response(200, json.dumps(seen).encode())
                else:
                    super().do_GET()
        class Server(http.server.ThreadingHTTPServer):
            def handle_error(self, *_):
                pass  # Expected TLS-negative cases have no application request.
        with Server(('127.0.0.1', 0), Origin) as server:
            if tls:
                certs = self.root / ('wrong' if wrong else 'certs')
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certs / 'gateway.crt', certs / 'gateway.key')
                server.socket = context.wrap_socket(server.socket, server_side=True)
            server.origin_url = ('https' if tls else 'http') + '://localhost:' + str(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield server.origin_url
            finally:
                server.shutdown()
                thread.join(5)

    @contextlib.contextmanager
    def proxy(self, destination, trust=False, wrong=False, port=None):
        port = port or free_port()
        config = {'ListenPort': port, 'Destination': destination + '/', 'LabOnly': True}
        if trust:
            ca = self.root / ('wrong' if wrong else 'certs') / 'ca.crt'
            der = ssl.PEM_cert_to_DER_cert(ca.read_text())
            config.update(TrustedRootFile=str(ca), TrustedRootSha256=hashlib.sha256(der).hexdigest())
        path = self.root / ('config-' + str(port) + '.json')
        path.write_text(json.dumps(config))
        process = subprocess.Popen([DOTNET, str(DLL), '--config', str(path)], cwd=ROOT,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError('YARP exited: ' + process.communicate()[1].decode())
                try:
                    if self.request(port, '/_health')[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise AssertionError('YARP did not start')
            yield port, process
        finally:
            if process.poll() is None:
                process.terminate()
            output, error = process.communicate(timeout=10)
            self.assertNotIn(b'fixture-secret', output + error)

    def request(self, port, path, method='GET', body=None, headers=None):
        client = http.client.HTTPConnection('localhost', port, timeout=10)
        try:
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            client.close()

    def test_http_page_upload_download_cookies_and_safe_redirects(self):
        with self.origin() as origin, self.proxy(origin) as (port, _):
            self.assertIn(b'fetch(path,options)', self.request(port, '/')[1])
            data = b'fixture-secret'
            status, body, _ = self.request(port, '/upload', 'POST', data)
            self.assertEqual(200, status)
            self.assertEqual(hashlib.sha256(data).hexdigest(), json.loads(body)['sha256'])
            self.assertEqual(web_lab.DOWNLOAD, self.request(port, '/download')[1])
            self.assertEqual('/', self.request(port, '/redirect')[2]['Location'])
            self.assertEqual('/status', self.request(port, '/absolute')[2]['Location'])
            self.assertEqual(502, self.request(port, '/external')[0])
            self.assertIn('fixture=ok', self.request(port, '/cookie')[2]['Set-Cookie'])
            status, body, _ = self.request(port, '/headers', headers={
                'Proxy-Authorization': 'fixture-secret', 'X-Forwarded-Host': 'attacker.invalid'})
            seen = json.loads(body)
            self.assertNotIn('proxy-authorization', seen)
            self.assertNotIn('x-forwarded-host', seen)
            self.assertEqual(origin.split('://')[1], seen['host'])
            self.assertEqual(405, self.request(port, '/status', 'TRACE')[0])
            self.assertEqual(421, self.request(port, '/status', headers={'Host': 'attacker.invalid'})[0])

    def test_websocket_through_yarp(self):
        with self.origin() as origin, self.proxy(origin) as (port, _):
            client = http.client.HTTPConnection('localhost', port, timeout=10)
            try:
                client.request('GET', '/ws', headers={'Upgrade': 'websocket', 'Connection': 'Upgrade',
                    'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'MDEyMzQ1Njc4OWFiY2RlZg=='})
                response = client.getresponse()
                self.assertEqual(101, response.status)
                data, mask = b'fixture-ws', b'abcd'
                client.sock.sendall(b'\x81' + bytes([128 | len(data)]) + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(data)))
                self.assertEqual(b'\x81' + bytes([len(data)]) + data, response.fp.read(2 + len(data)))
                client.sock.sendall(b'\x88\x80abcd')
            finally:
                client.close()

    def test_https_is_validated_in_yarp_and_client_uses_plain_loopback(self):
        with self.origin(tls=True) as origin:
            with self.proxy(origin) as (port, _):
                self.assertEqual(502, self.request(port, '/status')[0])
            with self.proxy(origin, trust=True) as (port, _):
                self.assertEqual(200, self.request(port, '/status')[0])

    def test_trusted_root_does_not_disable_hostname_validation(self):
        with self.origin(tls=True, wrong=True) as origin, self.proxy(origin, trust=True, wrong=True) as (port, _):
            self.assertEqual(502, self.request(port, '/status')[0])

    def test_non_lab_destination_and_bad_fingerprint_refused_at_startup(self):
        for changes in ({'Destination': 'https://gitlab.sicredi.net/'}, {'LabOnly': False},
                        {'TrustedRootFile': str(self.root / 'certs/ca.crt'), 'TrustedRootSha256': '00'}):
            config = {'ListenPort': free_port(), 'Destination': 'https://localhost:18765/', 'LabOnly': True, **changes}
            path = self.root / 'invalid.json'
            path.write_text(json.dumps(config))
            result = subprocess.run([DOTNET, str(DLL), '--config', str(path)], cwd=ROOT,
                                    capture_output=True, timeout=15)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(b'gitlab.sicredi.net', result.stderr)


@unittest.skipUnless(DOTNET, 'YARP tunnel test requires .NET 10')
class YarpTunnelIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DLL.exists():
            raise unittest.SkipTest('Build YARP first')
        fixtures.HTTPSIntegration.setUpClass.__func__(cls)
        # Reserve the existing lab echo port for the YARP process in this test.
        cls.echo.shutdown()
        cls.echo.server_close()
        cls.threads[-1].join(5)
        cls.servers = cls.servers[:-1]
        cls.threads = cls.threads[:-1]

    tearDownClass = classmethod(fixtures.HTTPSIntegration.tearDownClass.__func__)
    token_client = fixtures.HTTPSIntegration.token_client
    external_proxy = fixtures.HTTPSIntegration.external_proxy
    proxy_request = fixtures.HTTPSIntegration.proxy_request
    run_agent = fixtures.HTTPSIntegration.run_agent
    request = YarpLab.request
    proxy = YarpLab.proxy

    def test_yarp_roundtrip_through_existing_authenticated_tunnel(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        entry = {'enabled': True, 'web_policy': web_policy.lab_policy(), 'test_authorization': {
            'kind': 'requester_authorized_test', 'agent_id': self.gateway['agent_id'],
            'requested_by': 'fixture', 'corporate_approval': 'pending', 'expires_utc': expiry}}
        with self.proxy('http://localhost:18765', port=18766), \
             mock.patch.dict(self.gateway, {'operation_mode': 'homologation', 'max_sessions': 4}), \
             mock.patch.dict(self.gateway['services'], {'web': copy.deepcopy(entry)}), \
             mock.patch.dict(self.agent, {'operation_mode': 'homologation'}), \
             mock.patch.dict(self.agent['services'], {'web': copy.deepcopy(entry)}), \
             self.token_client(('web',)) as (config, policy, token), self.external_proxy() as proxy:
            auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
            stop, worker = self.run_agent(['web'])
            try:
                with self.proxy_request(proxy, b'GET http://localhost:18766/status HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                    response = http.client.HTTPResponse(peer)
                    response.begin()
                    self.assertEqual(200, response.status)
                    self.assertEqual(h.poc.SERVICES['lab-status'][1], json.loads(response.read()))
            finally:
                stop.set()
                worker.join(10)
