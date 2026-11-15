import io
import base64
import contextlib
import datetime
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import homologation


class ClientAdministration(unittest.TestCase):
    def test_720_hour_policy_applies_to_all_roles_and_new_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = homologation.prepare(root / 'initial', hours=720)
            overlay = json.loads((root / 'initial/gateway-policy.json').read_text())
            entry = overlay['patch']['services']['gitlab']['test_authorization']
            start = datetime.datetime.strptime(entry['issued_utc'], '%Y-%m-%dT%H:%M:%SZ')
            end = datetime.datetime.strptime(entry['expires_utc'], '%Y-%m-%dT%H:%M:%SZ')
            self.assertEqual(datetime.timedelta(hours=720), end - start)
            self.assertEqual('pending', summary['corporate_approval'])
            configs = {'gateway': {'signing_key': 'existing.key'},
                       'agent': {'agent_url': 'https://existing.example'},
                       'client': {'client_host': 'existing.example'}}
            for role, initial in configs.items():
                initial.update(agent_id='windows-lab-01', tls_ca='existing-ca.crt')
                role_dir = root / role
                role_dir.mkdir()
                path = role_dir / 'config.json'
                homologation.write_json(path, initial)
                homologation.apply(path, root / ('initial/' + role + '-policy.json'))
                updated = json.loads(path.read_text())
                self.assertEqual('existing-ca.crt', updated['tls_ca'])
                self.assertEqual(entry['expires_utc'], updated['services']['gitlab']['test_authorization']['expires_utc'])
            gateway = root / 'gateway/config.json'
            new = homologation.issue_client(gateway, root / 'second', 'cliente-02', hours=720, services=['gitlab'])
            self.assertEqual(entry['expires_utc'], new['expires_utc'])
            updated = json.loads(gateway.read_text())
            self.assertEqual(['gitlab'], updated['token_clients']['cliente-02']['services'])
            self.assertNotIn('client_token_file', updated)

    def test_default_remains_24_hours_and_limits_reject_over_720(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'default')
            overlay = json.loads((root / 'default/gateway-policy.json').read_text())
            entry = overlay['patch']['services']['gitlab']['test_authorization']
            start = datetime.datetime.strptime(entry['issued_utc'], '%Y-%m-%dT%H:%M:%SZ')
            end = datetime.datetime.strptime(entry['expires_utc'], '%Y-%m-%dT%H:%M:%SZ')
            self.assertEqual(datetime.timedelta(hours=24), end - start)
            path = root / 'gateway.json'
            config = {'agent_id': 'windows-lab-01', 'signing_key': 'existing.key', **overlay['patch']}
            homologation.write_json(path, config)
            for index, invalid in enumerate((0, -1, 721, True, 1.5)):
                with self.assertRaises(ValueError):
                    homologation.prepare(root / ('invalid-' + str(index)), hours=invalid)
                with self.assertRaises(ValueError):
                    homologation.issue_client(path, root / ('client-invalid-' + str(index)),
                                               'cliente-02', hours=invalid)
            oversized = copy.deepcopy(overlay)
            for service in oversized['patch']['services'].values():
                service['test_authorization']['expires_utc'] = (start + datetime.timedelta(hours=721)).strftime('%Y-%m-%dT%H:%M:%SZ')
            policy = root / 'oversized.json'
            homologation.write_json(policy, oversized)
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                homologation.apply(path, policy)
            self.assertEqual(before, path.read_bytes())

    def test_rotation_renews_policy_preserves_scopes_and_other_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial')
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config['signing_key'] = 'existing.key'
            config['tls_cert'] = 'existing.crt'
            config['max_bytes'] = 1234567
            config['token_clients']['intermediario-01']['services'] = ['gitlab']
            config['token_clients']['other'] = {'enabled': False, 'services': ['artifactory']}
            for service in config['services'].values():
                service['test_authorization']['expires_utc'] = '2000-01-01T00:00:00Z'
            path = root / 'gateway.json'
            homologation.write_json(path, config)
            result = homologation.rotate_client_token(path, root / 'rotated', 'intermediario-01', 720, 'test-operator')
            updated = json.loads(path.read_text())
            token = (root / 'rotated/client.token').read_text().strip()
            self.assertNotEqual(config['token_clients']['intermediario-01']['token_sha256'],
                                updated['token_clients']['intermediario-01']['token_sha256'])
            self.assertEqual(['gitlab'], updated['token_clients']['intermediario-01']['services'])
            self.assertEqual(config['token_clients']['other'], updated['token_clients']['other'])
            self.assertEqual(1234567, updated['max_bytes'])
            self.assertEqual('existing.crt', updated['tls_cert'])
            self.assertNotIn(token, json.dumps(result))
            self.assertNotIn(token, path.read_text())
            policy = json.loads(base64.b64decode(result['agent_policy_base64']))
            self.assertEqual('agent', policy['role'])
            self.assertEqual(result['agent_policy'], policy)
            self.assertEqual({'gitlab','artifactory'}, set(policy['patch']['services']))
            self.assertNotIn('token', json.dumps(policy))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                homologation.print_rotation(result, show_token=True)
            self.assertIn('CLIENT_TOKEN=' + token, output.getvalue())
            with self.assertRaises(ValueError):
                homologation.rotate_client_token(path, root / 'revoked', 'other', 720)
            self.assertFalse((root / 'revoked').exists())

    def test_validate_only_never_modifies_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'policies', hours=720)
            path = root / 'agent.json'
            homologation.write_json(path, {'agent_id':'windows-lab-01','agent_url':'https://existing.example'})
            before = path.read_bytes()
            result = homologation.apply(path, root / 'policies/agent-policy.json', validate_only=True)
            self.assertIsNone(result)
            self.assertEqual(before, path.read_bytes())
            self.assertFalse(list(root.glob('*.before-*')))
            malformed = json.loads((root / 'policies/agent-policy.json').read_text())
            malformed['patch']['services']['gitlab']['test_authorization']['requested_by'] = ''
            invalid = root / 'invalid-policy.json'
            homologation.write_json(invalid, malformed)
            with self.assertRaises(ValueError):
                homologation.apply(path, invalid, validate_only=True)
            self.assertEqual(before, path.read_bytes())


    def test_gateway_check_reports_expiry_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial')
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config.update(tls_ca='ca.crt', external_proxy_port=8443, external_proxy_host='secure-gateway.sicredi.space')
            path = root / 'gateway.json'
            homologation.write_json(path, config)
            def response(status):
                value = mock.MagicMock()
                value.__enter__.return_value = value
                value.status = status
                return value
            with mock.patch.object(homologation.socket, 'create_connection'), \
                 mock.patch.object(homologation.ssl, 'create_default_context'), \
                 mock.patch.object(homologation.http.client, 'HTTPResponse', side_effect=[response(403), response(401), response(200)]):
                result = homologation.check_gateway(path)
            self.assertTrue(result['ready'])
            self.assertNotIn('token_sha256', json.dumps(result))
            config['token_clients']['intermediario-01']['expires_utc'] = '2000-01-01T00:00:00Z'
            homologation.write_json(path, config)
            with mock.patch.object(homologation.socket, 'create_connection'), \
                 mock.patch.object(homologation.ssl, 'create_default_context'), \
                 mock.patch.object(homologation.http.client, 'HTTPResponse', side_effect=[response(403), response(401), response(200)]):
                self.assertFalse(homologation.check_gateway(path)['ready'])

    def test_configure_proxy_preserves_keys_and_can_disable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            original = {'signing_key': 'signing.key', 'client_auth': 'token',
                        'tls_cert': '/existing/public.crt', 'token_clients': {'old': {'enabled': False}}}
            homologation.write_json(path, original)
            homologation.configure_proxy(path, 'secure-gateway.sicredi.space', bind='0.0.0.0')
            config = json.loads(path.read_text())
            self.assertEqual(8443, config['external_proxy_port'])
            for name, value in original.items():
                self.assertEqual(value, config[name])
            homologation.configure_proxy(path, 'secure-gateway.sicredi.space', disable=True)
            self.assertEqual(original, json.loads(path.read_text()))
            for host, port, bind in [('bad"host', 8443, '127.0.0.1'), ('valid.example', 80, '127.0.0.1'),
                                     ('valid.example', 8443, 'bad-bind')]:
                with self.assertRaises(ValueError):
                    homologation.configure_proxy(path, host, port, bind)
            self.assertEqual(original, json.loads(path.read_text()))

    def test_issue_preserves_agent_policy_and_caps_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial', hours=1)
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config['tls_cert'] = '/existing/server.crt'
            path = root / 'config.json'
            homologation.write_json(path, config)
            result = homologation.issue_client(path, root / 'new', 'cliente-02', services=['gitlab'])
            updated = json.loads(path.read_text())
            self.assertEqual(updated['services'], config['services'])
            self.assertEqual(updated['tls_cert'], config['tls_cert'])
            self.assertEqual(updated['token_clients']['intermediario-01'], config['token_clients']['intermediario-01'])
            client = updated['token_clients']['cliente-02']
            self.assertEqual(client['expires_utc'], config['services']['gitlab']['test_authorization']['expires_utc'])
            self.assertEqual(client['services'], ['gitlab'])
            token = (root / 'new/client.token').read_text().strip()
            self.assertEqual(client['token_sha256'], hashlib.sha256(token.encode()).hexdigest())
            self.assertNotIn(token, path.read_text())
            self.assertNotIn(token, json.dumps(result))
            self.assertFalse((root / 'new/agent-policy.json').exists())
            with self.assertRaises(ValueError):
                homologation.issue_client(path, root / 'duplicate', 'cliente-02')

    def test_expired_service_cannot_issue_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'initial')
            config = json.loads((root / 'initial/gateway-policy.json').read_text())['patch']
            config['services']['gitlab']['test_authorization']['expires_utc'] = '2000-01-01T00:00:00Z'
            path = root / 'config.json'
            homologation.write_json(path, config)
            with self.assertRaises(ValueError):
                homologation.issue_client(path, root / 'new', 'cliente-02', services=['gitlab'])
            self.assertFalse((root / 'new').exists())
            self.assertEqual(json.loads(path.read_text()), config)
