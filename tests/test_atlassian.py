import base64
import copy
import datetime
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

import homologation as admin
import https_poc as h
import test_https as fixtures


class BrowserPolicy(unittest.TestCase):
    def test_hostname_boundaries_and_tenant(self):
        for host in ('sicredi.atlassian.net', 'id.atlassian.com', 'api.media.atlassian.com',
                     'jira-frontend-static.prod.public.atl-paas.net', 'atlassian.com'):
            self.assertTrue(h.atlassian_host(host), host)
        for host in ('other.atlassian.net', 'sicredi.atlassian.net.evil.com',
                     'evilatlassian.com', '127.0.0.1', 'localhost', 'id.atlassian.com.',
                     'id.atlassian.com/secret', 'ID.atlassian.com', '-bad.atlassian.com'):
            self.assertFalse(h.atlassian_host(host), host)

    def test_private_dns_rejected_and_public_address_pinned(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 443))]
        for answers in (private, public + private):
            with mock.patch.object(h.socket, 'getaddrinfo', return_value=answers), mock.patch.object(h.socket, 'socket') as factory:
                with self.assertRaises(ValueError):
                    h.atlassian_connect('id.atlassian.com')
                factory.assert_not_called()
        with mock.patch.object(h.socket, 'getaddrinfo', return_value=public) as resolver, mock.patch.object(h.socket, 'socket') as factory:
            peer = h.atlassian_connect('id.atlassian.com')
            peer.connect.assert_called_once_with(('1.1.1.1', 443))
            resolver.assert_called_once()
        with mock.patch.object(h.socket, 'getaddrinfo') as resolver:
            with self.assertRaises(ValueError):
                h.atlassian_connect('other.atlassian.net')
            resolver.assert_not_called()

    def test_shared_poll_only_assigns_authorized_services(self):
        state = h.State.__new__(h.State)
        state.lock = threading.Lock()
        state.config = {'services': {'lab-status': {'enabled': True}, 'lab-echo': {'enabled': True}}}
        state.jobs = {name: {'id': name, 'service': name, 'assigned': False,
                             'done': threading.Event()} for name in ('lab-echo', 'lab-status')}
        with mock.patch.object(h.poc, 'audit'):
            first = state.exchange({'action': 'poll', 'services': ['lab-status', 'lab-echo']})
            second = state.exchange({'action': 'poll', 'services': ['lab-status', 'lab-echo']})
            self.assertEqual('lab-echo', first['service'])
            self.assertEqual('lab-status', second['service'])
            self.assertEqual({'idle': True}, state.exchange({'action': 'poll', 'services': ['lab-status']}))
            with self.assertRaises(ValueError):
                state.exchange({'action': 'poll', 'services': ['lab-status', 'atlassian']})
            with self.assertRaises(ValueError):
                state.exchange({'action': 'poll', 'services': []})

    def test_activation_preserves_tokens_expiry_and_other_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admin.prepare(root / 'initial', hours=24)
            gateway = root / 'config.json'
            gateway.write_text(json.dumps({'agent_id': 'windows-lab-01', 'signing_key': 'unchanged.key'}))
            admin.apply(gateway, root / 'initial/gateway-policy.json')
            original = json.loads(gateway.read_text())
            original['token_clients']['other'] = copy.deepcopy(original['token_clients']['intermediario-01'])
            gateway.write_text(json.dumps(original))
            result = admin.enable_atlassian(gateway, root / 'browser')
            updated = json.loads(gateway.read_text())
            before = original['token_clients']['intermediario-01']
            after = updated['token_clients']['intermediario-01']
            self.assertEqual(before['token_sha256'], after['token_sha256'])
            self.assertEqual(before['expires_utc'], after['expires_utc'])
            self.assertEqual(original['token_clients']['other'], updated['token_clients']['other'])
            self.assertEqual(['gitlab', 'artifactory', 'atlassian'], after['services'])
            self.assertFalse(result['token_changed'])
            self.assertEqual(16, updated['max_sessions'])
            self.assertEqual('pending', updated['services']['atlassian']['test_authorization']['corporate_approval'])
            agent = (root / 'browser/agent-policy.json').read_text()
            self.assertNotIn('token_sha256', agent)
            self.assertNotIn('signing_key', agent)
            self.assertFalse((root / 'browser/client.token').exists())
            with self.assertRaises(ValueError):
                admin.enable_atlassian(gateway, root / 'bad', 'missing')
            updated['token_clients']['intermediario-01']['enabled'] = False
            gateway.write_text(json.dumps(updated))
            with self.assertRaises(ValueError):
                admin.enable_atlassian(gateway, root / 'revoked')


class BrowserIntegration(unittest.TestCase):
    setUpClass = classmethod(fixtures.HTTPSIntegration.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.HTTPSIntegration.tearDownClass.__func__)
    token_client = fixtures.HTTPSIntegration.token_client
    external_proxy = fixtures.HTTPSIntegration.external_proxy
    proxy_request = fixtures.HTTPSIntegration.proxy_request
    run_agent = fixtures.HTTPSIntegration.run_agent

    def test_browser_connect_routes_job_and_enforces_scope(self):
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        entry = {'enabled': True, 'test_authorization': {'kind': 'requester_authorized_test',
            'agent_id': self.gateway['agent_id'], 'requested_by': 'fixture',
            'corporate_approval': 'pending', 'expires_utc': expiry}}
        with mock.patch.dict(self.gateway, {'operation_mode': 'homologation',
                             'external_proxy_host': 'localhost'}), \
             mock.patch.dict(self.gateway['services'], {'atlassian': copy.deepcopy(entry)}), \
             mock.patch.dict(self.agent, {'operation_mode': 'homologation'}), \
             mock.patch.dict(self.agent['services'], {'atlassian': copy.deepcopy(entry)}), \
             self.token_client(('atlassian',)) as (config, policy, token), self.external_proxy() as proxy:
            self.assertIn('sicredi.atlassian.net', proxy.pac)
            self.assertIn('dnsDomainIs(host, ".atl-paas.net")', proxy.pac)
            self.assertNotIn('HTTPS localhost:0; DIRECT', proxy.pac)
            auth = b'Proxy-Authorization: Basic ' + base64.b64encode((config['client_id'] + ':' + token).encode()) + b'\r\n'
            def connect_fixture(host):
                self.assertEqual('id.atlassian.com', host)
                return socket.create_connection(self.echo.server_address, timeout=3)
            with mock.patch.object(h, 'atlassian_connect', side_effect=connect_fixture) as connect:
                stop, agent = self.run_agent(['atlassian', 'lab-echo'])
                try:
                    with self.proxy_request(proxy, b'CONNECT id.atlassian.com:443 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                        header = b''
                        while not header.endswith(b'\r\n\r\n'):
                            header += peer.recv(1)
                        self.assertIn(b'200 Connection Established', header)
                        payload = b'GET /wiki HTTP/1.1\r\nCookie: fixture-only\r\n\r\n' + bytes(range(256))
                        peer.sendall(payload)
                        received = b''
                        while len(received) < len(payload):
                            received += peer.recv(len(payload) - len(received))
                        self.assertEqual(payload, received)
                    for destination in (b'other.atlassian.net:443', b'id.atlassian.com:80', b'id.atlassian.com.evil.net:443'):
                        with self.proxy_request(proxy, b'CONNECT ' + destination + b' HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                            self.assertIn(b'403', peer.recv(4096))
                    policy['services'] = ['lab-status']
                    with self.proxy_request(proxy, b'CONNECT id.atlassian.com:443 HTTP/1.1\r\n' + auth + b'\r\n') as peer:
                        self.assertIn(b'403', peer.recv(4096))
                    self.assertEqual(1, connect.call_count)
                    self.assertNotIn(token, self.output.getvalue())
                    self.assertNotIn('fixture-only', self.output.getvalue())
                    self.gateway['services']['atlassian']['test_authorization']['expires_utc'] = '2000-01-01T00:00:00Z'
                    with h.ExternalProxy(('127.0.0.1', 0), self.state, h.client_tls_context(self.gateway)) as expired_proxy:
                        self.assertIn('sicredi.atlassian.net', expired_proxy.pac)
                    self.assertFalse(h.service_allowed(self.gateway, 'atlassian'))
                finally:
                    stop.set()
                    agent.join(10)
