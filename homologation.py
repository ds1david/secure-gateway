"""Create per-client tokens and apply a time-limited requester-authorized test policy."""
import argparse
import copy
import datetime
import getpass
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import base64
import socket
import ssl
import http.client
import uuid
import web_policy

DEFAULT_HOURS = 24
MAX_HOURS = 720
SERVICES = {'gitlab': 18443, 'artifactory': 18081, 'atlassian': 18444, 'web': 18084}
LIMITS = {'max_bytes': 16 * 1024 * 1024, 'max_seconds': 300,
          'max_sessions': 4, 'idle_seconds': 30, 'client_requests_per_minute': 120}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    path.chmod(0o600)


def prepare(out, client_id='intermediario-01', agent_id='windows-lab-01', hours=DEFAULT_HOURS,
            requested_by=None, services=('gitlab', 'artifactory')):
    if not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value) for value in (client_id, agent_id)):
        raise ValueError('invalid identity')
    if type(hours) is not int or not 1 <= hours <= MAX_HOURS or not services or any(service not in SERVICES for service in services):
        raise ValueError(f'test scope must be fixed destinations and 1-{MAX_HOURS} hours')
    out = Path(out).resolve()
    out.mkdir(parents=True, mode=0o755 if os.name == 'nt' else 0o700, exist_ok=False)
    requested_by = requested_by or getpass.getuser()
    if not isinstance(requested_by, str) or not requested_by.strip():
        raise ValueError('requester required')
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = (now + datetime.timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
    authorization = {'kind': 'requester_authorized_test', 'agent_id': agent_id,
        'requested_by': requested_by, 'issued_utc': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'expires_utc': expires, 'corporate_approval': 'pending',
        'purpose': 'Final POC validation requested by operator; not production approval'}
    common = {'operation_mode': 'homologation', 'agent_id': agent_id,
        'services': {name: {'enabled': True, 'local_port': SERVICES[name],
                           'test_authorization': copy.deepcopy(authorization)} for name in services}, **LIMITS}
    if 'web' in common['services']:
        common['services']['web']['web_policy'] = web_policy.lab_policy()
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    token_path = out / 'client.token'
    token_path.write_text(token + '\n', encoding='ascii')
    token_path.chmod(0o600)
    patches = {
        'gateway': {**copy.deepcopy(common), 'client_auth': 'token',
                    'token_clients': {client_id: {'enabled': True, 'token_sha256': digest,
                                      'expires_utc': expires, 'services': list(services)}}},
        'agent': copy.deepcopy(common),
        'client': {**copy.deepcopy(common), 'client_auth': 'token', 'client_id': client_id,
                   'client_token_file': 'client.token', 'proxy_port': 18080},
    }
    for role, patch in patches.items():
        write_json(out / (role + '-policy.json'), {'format': 1, 'role': role, 'patch': patch,
                    **({'token_sha256': digest} if role == 'client' else {})})
    return {'client_id': client_id, 'agent_id': agent_id, 'services': list(services),
            'expires_utc': expires, 'token_file': str(token_path), 'corporate_approval': 'pending'}


def apply(config_path, policy_path, validate_only=False):
    config_path, policy_path = Path(config_path).resolve(), Path(policy_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    overlay = json.loads(policy_path.read_text(encoding='utf-8-sig'))
    role = overlay.get('role')
    expected_role = 'agent' if 'agent_url' in config else ('gateway' if 'signing_key' in config else 'client')
    if overlay.get('format') != 1 or role != expected_role:
        raise ValueError('policy role does not match configuration')
    patch = overlay['patch']
    allowed = {'operation_mode', 'agent_id', 'services', *LIMITS}
    allowed |= {'gateway': {'client_auth', 'token_clients'}, 'agent': set(),
                'client': {'client_auth', 'client_id', 'client_token_file', 'proxy_port'}}[role]
    if (set(patch) - allowed or patch.get('operation_mode') != 'homologation'
            or patch.get('agent_id') != config['agent_id']):
        raise ValueError('invalid policy fields or agent identity')
    if not patch.get('services') or set(patch['services']) - SERVICES.keys():
        raise ValueError('invalid destinations')
    if 'web' in patch['services']:
        web_policy.validate(patch['services']['web'].get('web_policy'))
    for entry in patch['services'].values():
        authorization = entry.get('test_authorization', {})
        try:
            end = datetime.datetime.strptime(authorization['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
            start = datetime.datetime.strptime(authorization['issued_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ValueError('invalid test authorization') from None
        if (authorization.get('kind') != 'requester_authorized_test'
                or authorization.get('corporate_approval') != 'pending'
                or authorization.get('agent_id') != config['agent_id']
                or not isinstance(authorization.get('requested_by'), str)
                or not authorization['requested_by'].strip()
                or not 0 < (end - start).total_seconds() <= MAX_HOURS * 3600
                or end <= datetime.datetime.now(datetime.timezone.utc)):
            raise ValueError('expired or invalid test authorization')
    token_path = None
    if role == 'client':
        if patch.get('client_token_file') != 'client.token':
            raise ValueError('invalid token file')
        token_path = policy_path.parent / 'client.token'
        token = token_path.read_text(encoding='ascii').strip()
        if not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), overlay['token_sha256']):
            raise ValueError('token and policy differ')
    if validate_only:
        return None
    backup = config_path.with_name(config_path.name + '.before-homologation-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    for key, value in patch.items():
        if key in ('services', 'token_clients'):
            for name, entry in value.items():
                config.setdefault(key, {}).setdefault(name, {}).update(entry)
        else:
            config[key] = value
    if token_path:
        target = config_path.parent / 'client.token'
        if target != token_path:
            shutil.copyfile(token_path, target)
        target.chmod(0o600)
    # Do not chmod the existing config: preserve its root:gateway-poc 0640 mode.
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return str(backup)


def issue_client(config_path, out, client_id, hours=DEFAULT_HOURS, services=('gitlab', 'artifactory')):
    """Issue on the gateway, bounded by its existing service authorization."""
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if config.get('operation_mode') != 'homologation' or config.get('client_auth') != 'token':
        raise ValueError('gateway must already use homologation tokens')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', client_id):
        raise ValueError('invalid client identity')
    if client_id in config.get('token_clients', {}):
        raise ValueError('client already exists; use a new identity')
    if type(hours) is not int or not 1 <= hours <= MAX_HOURS or not services or set(services) - SERVICES.keys():
        raise ValueError('invalid scope or lifetime')
    now = datetime.datetime.now(datetime.timezone.utc)
    deadline = now + datetime.timedelta(hours=hours)
    selected = {}
    for name in services:
        entry = config.get('services', {}).get(name, {})
        auth = entry.get('test_authorization', {})
        if (not entry.get('enabled') or auth.get('kind') != 'requester_authorized_test'
                or auth.get('agent_id') != config.get('agent_id')
                or auth.get('corporate_approval') != 'pending'):
            raise ValueError('service not authorized for this agent')
        end = datetime.datetime.strptime(auth['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
        if end <= now:
            raise ValueError('service authorization expired')
        deadline = min(deadline, end)
        selected[name] = copy.deepcopy(entry)
    out = Path(out).resolve()
    out.mkdir(parents=True, mode=0o755 if os.name == 'nt' else 0o700, exist_ok=False)
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    expires = deadline.strftime('%Y-%m-%dT%H:%M:%SZ')
    token_path = out / 'client.token'
    token_path.write_text(token + '\n', encoding='ascii')
    token_path.chmod(0o600)
    patch = {'operation_mode': 'homologation', 'agent_id': config['agent_id'],
             'services': selected, 'client_auth': 'token', 'client_id': client_id,
             'client_token_file': 'client.token', 'proxy_port': 18080}
    for name, default in LIMITS.items():
        patch[name] = config.get(name, default)
    write_json(out / 'client-policy.json', {'format': 1, 'role': 'client',
                                           'patch': patch, 'token_sha256': digest})
    backup = config_path.with_name(config_path.name + '.before-client-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    config.setdefault('token_clients', {})[client_id] = {'enabled': True,
        'token_sha256': digest, 'expires_utc': expires, 'services': list(services)}
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return {'client_id': client_id, 'expires_utc': expires, 'bundle': str(out),
            'backup': str(backup), 'action': 'restart gateway'}


def rotate_client_token(config_path, out, client_id, hours=DEFAULT_HOURS, requested_by=None):
    """Renew enabled test services and rotate exactly one existing, active client."""
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if (config.get('operation_mode') != 'homologation' or config.get('client_auth') != 'token'
            or 'signing_key' not in config):
        raise ValueError('requires homologation gateway with token authentication')
    client = config.get('token_clients', {}).get(client_id, {})
    if client.get('enabled') is not True:
        raise ValueError('unknown or revoked client; rotation cannot reactivate it')
    scopes = client.get('services', [])
    enabled = [name for name in SERVICES if config.get('services', {}).get(name, {}).get('enabled') is True]
    if not scopes or set(scopes) - set(enabled):
        raise ValueError('client scope must remain within enabled fixed services')
    for name in enabled:
        auth = config['services'][name].get('test_authorization', {})
        if (auth.get('kind') != 'requester_authorized_test' or auth.get('corporate_approval') != 'pending'
                or auth.get('agent_id') != config['agent_id']):
            raise ValueError('only existing requester-authorized test services may be renewed')
    prepare(out, client_id, config['agent_id'], hours,
            requested_by or os.environ.get('SUDO_USER') or getpass.getuser(), enabled)
    out = Path(out).resolve()
    policies = {}
    for role in ('gateway', 'agent', 'client'):
        path = out / (role + '-policy.json')
        policy = json.loads(path.read_text(encoding='utf-8'))
        for name, default in LIMITS.items():
            policy['patch'][name] = config.get(name, default)
        for name, entry in policy['patch']['services'].items():
            entry['local_port'] = config['services'][name].get('local_port', SERVICES[name])
            if name == 'web':
                entry['web_policy'] = copy.deepcopy(config['services'][name]['web_policy'])
        if role == 'gateway':
            policy['patch']['token_clients'][client_id]['services'] = list(scopes)
        if role == 'client':
            policy['patch']['services'] = {name: entry for name, entry in policy['patch']['services'].items() if name in scopes}
        write_json(path, policy)
        policies[role] = policy
    backup = apply(config_path, out / 'gateway-policy.json')
    agent_json = json.dumps(policies['agent'], separators=(',', ':'), ensure_ascii=True)
    return {'event': 'client_token_rotated', 'client_id': client_id,
            'expires_utc': policies['gateway']['patch']['token_clients'][client_id]['expires_utc'],
            'token_file': str(out / 'client.token'), 'bundle': str(out), 'backup': backup,
            'agent_policy': policies['agent'],
            'agent_policy_base64': base64.b64encode(agent_json.encode()).decode(),
            'action': 'restart gateway and apply agent policy; distribute token only to the client'}



def enable_atlassian(config_path, out, client_id='intermediario-01'):
    """Extend an existing live test client without changing its token or expiry."""
    config_path, out = Path(config_path).resolve(), Path(out).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    client = config.get('token_clients', {}).get(client_id)
    if (config.get('operation_mode') != 'homologation' or config.get('client_auth') != 'token'
            or not client or client.get('enabled') is not True):
        raise ValueError('requires an enabled homologation token client')
    now = datetime.datetime.now(datetime.timezone.utc)
    end = datetime.datetime.strptime(client['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    if end <= now or (end - now).total_seconds() > MAX_HOURS * 3600:
        raise ValueError('client is expired or exceeds maximum validity')
    if not client.get('services') or set(client['services']) - SERVICES.keys():
        raise ValueError('invalid existing client scopes')
    # No token issuance, no renewal and no alteration of other client identities.
    authorization = {'kind': 'requester_authorized_test', 'agent_id': config['agent_id'],
        'requested_by': os.environ.get('SUDO_USER') or getpass.getuser(),
        'issued_utc': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'expires_utc': client['expires_utc'],
        'corporate_approval': 'pending',
        'purpose': 'Operator-requested Jira/Confluence browser POC; not production approval'}
    services = {name: copy.deepcopy(entry) for name, entry in config.get('services', {}).items()
                if name in SERVICES and entry.get('enabled') is True}
    services['atlassian'] = {'enabled': True, 'local_port': SERVICES['atlassian'],
                             'test_authorization': authorization}
    limits = {key: config.get(key, value) for key, value in LIMITS.items()}
    for key, value in {'max_sessions': 16, 'max_bytes': 64 * 1024 * 1024,
                       'max_seconds': 1800, 'idle_seconds': 90,
                       'client_requests_per_minute': 600}.items():
        limits[key] = max(limits[key], value)
    common = {'operation_mode': 'homologation', 'agent_id': config['agent_id'],
              'services': services, **limits}
    client = copy.deepcopy(client)
    client['services'] = list(dict.fromkeys([*client['services'], 'atlassian']))
    gateway_policy = {'format': 1, 'role': 'gateway', 'patch': {
        **copy.deepcopy(common), 'client_auth': 'token', 'token_clients': {client_id: client}}}
    agent_policy = {'format': 1, 'role': 'agent', 'patch': common}
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_json(out / 'gateway-policy.json', gateway_policy)
    write_json(out / 'agent-policy.json', agent_policy)
    backup = apply(config_path, out / 'gateway-policy.json')
    encoded = base64.b64encode(json.dumps(agent_policy, separators=(',', ':')).encode()).decode()
    return {'event': 'atlassian_enabled', 'client_id': client_id, 'token_changed': False,
            'expires_utc': client['expires_utc'], 'backup': backup, 'bundle': str(out),
            'windows_command': 'tunnel rotate-client-token -PolicyJsonBase64 ' + encoded,
            'action': 'restart gateway; apply public agent policy on restricted Windows'}



def configure_web_proxy(config_path, out, policy_path, client_id='intermediario-01'):
    """Configure a web allowlist without changing tokens or their expiration."""
    config_path, out = Path(config_path).resolve(), Path(out).resolve()
    policy = web_policy.validate(json.loads(Path(policy_path).read_text(encoding='utf-8-sig')))
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    client = config.get('token_clients', {}).get(client_id)
    if (config.get('operation_mode') != 'homologation' or config.get('client_auth') != 'token'
            or not client or client.get('enabled') is not True):
        raise ValueError('requires an enabled homologation token client')
    if not client.get('services') or set(client['services']) - SERVICES.keys():
        raise ValueError('invalid client services')
    now = datetime.datetime.now(datetime.timezone.utc)
    end = datetime.datetime.strptime(client['expires_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    if not 0 < (end - now).total_seconds() <= MAX_HOURS * 3600:
        raise ValueError('client expired or exceeds maximum validity')
    auth = {'kind': 'requester_authorized_test', 'agent_id': config['agent_id'],
        'requested_by': os.environ.get('SUDO_USER') or getpass.getuser(),
        'issued_utc': now.strftime('%Y-%m-%dT%H:%M:%SZ'), 'expires_utc': client['expires_utc'],
        'corporate_approval': 'pending', 'purpose': 'Operator-requested web proxy POC; not production approval'}
    services = {name: copy.deepcopy(entry) for name, entry in config.get('services', {}).items()
                if name in SERVICES and entry.get('enabled') is True}
    services['web'] = {'enabled': True, 'local_port': SERVICES['web'],
                       'test_authorization': auth, 'web_policy': policy}
    limits = {key: config.get(key, value) for key, value in LIMITS.items()}
    for key, value in {'max_sessions': 16, 'max_bytes': 64 * 1024 * 1024,
                       'max_seconds': 1800, 'idle_seconds': 90,
                       'client_requests_per_minute': 600}.items():
        limits[key] = max(limits[key], value)
    common = {'operation_mode': 'homologation', 'agent_id': config['agent_id'], 'services': services, **limits}
    client = copy.deepcopy(client)
    client['services'] = list(dict.fromkeys([*client['services'], 'web']))
    gateway = {'format': 1, 'role': 'gateway', 'patch': {**copy.deepcopy(common),
               'client_auth': 'token', 'token_clients': {client_id: client}}}
    agent = {'format': 1, 'role': 'agent', 'patch': common}
    # Validate before touching the current gateway configuration.
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_json(out / 'gateway-policy.json', gateway)
    write_json(out / 'agent-policy.json', agent)
    backup = apply(config_path, out / 'gateway-policy.json')
    encoded = base64.b64encode(json.dumps(agent, separators=(',', ':')).encode()).decode()
    return {'event': 'web_proxy_configured', 'client_id': client_id, 'token_changed': False,
            'expires_utc': client['expires_utc'], 'backup': backup, 'bundle': str(out),
            'lab_only': policy['lab_only'],
            'windows_command': 'tunnel rotate-client-token -PolicyJsonBase64 ' + encoded}


def print_rotation(result, show_token=False):
    if not show_token:
        print(json.dumps(result))
        return
    print('CLIENT_ID=' + result['client_id'])
    print('EXPIRES_UTC=' + result['expires_utc'])
    print('CLIENT_TOKEN=' + Path(result['token_file']).read_text(encoding='ascii').strip())
    print('BUNDLE=' + result['bundle'])
    print('WINDOWS_AGENT_POLICY_JSON=' + json.dumps(result['agent_policy'], separators=(',', ':'), ensure_ascii=True))
    print('WINDOWS_COMMAND:')
    print('tunnel rotate-client-token -PolicyJsonBase64 ' + result['agent_policy_base64'])
    print('Restart gateway to activate. Never send CLIENT_TOKEN to the agent.')


def check_gateway(config_path, agent_host='agent-gateway.sicredi.space'):
    """Local listener/TLS probes, not a substitute for the agent preflight."""
    path = Path(config_path).resolve()
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if config.get('tls_ca'):
        context.load_verify_locations(str((path.parent / config['tls_ca']).resolve()))
    def probe(port, hostname, method, target, expected):
        with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as peer:
                request = (f'{method} {target} HTTP/1.1\r\nHost: {hostname}\r\n'
                           'Content-Length: 0\r\nConnection: close\r\n\r\n')
                peer.sendall(request.encode('ascii'))
                with http.client.HTTPResponse(peer, method=method) as response:
                    response.begin()
                    if response.status != expected:
                        raise ValueError('unexpected gateway probe status')
                    return {'ready': True, 'http_status': response.status}
    checks = {'agent_entry': probe(443, agent_host, 'POST', '/v1/exchange', 403)}
    if config.get('external_proxy_port'):
        host = config.get('external_proxy_host', 'secure-gateway.sicredi.space')
        checks['maven_entry'] = probe(config['external_proxy_port'], host, 'HEAD', '/maven/repo/', 401)
        checks['pac'] = probe(config['external_proxy_port'], host, 'HEAD', '/proxy.pac', 200)
    authorization = {}
    if config.get('operation_mode') == 'homologation':
        now = datetime.datetime.now(datetime.timezone.utc)
        def valid_expiry(value):
            try:
                return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc) > now
            except (TypeError, ValueError):
                return False
        services = {name: valid_expiry(entry.get('test_authorization', {}).get('expires_utc'))
                    for name, entry in config.get('services', {}).items()
                    if name in SERVICES and entry.get('enabled') is True}
        clients = {name: {'enabled': entry.get('enabled') is True,
                         'expires_utc': entry.get('expires_utc'),
                         'valid': entry.get('enabled') is True and valid_expiry(entry.get('expires_utc'))}
                   for name, entry in config.get('token_clients', {}).items()}
        ready = bool(services) and all(services.values()) and any(entry['valid'] for entry in clients.values())
        authorization = {'ready': ready, 'services': services, 'clients': clients}
    return {'ready': authorization.get('ready', True), 'checks': checks, 'authorization': authorization,
            'scope': 'gateway listeners, TLS and expiry; use Windows check for end-to-end service access'}


def configure_proxy(config_path, host, port=8443, bind='127.0.0.1', disable=False):
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if 'signing_key' not in config or config.get('client_auth') != 'token':
        raise ValueError('requires gateway configuration with token authentication')
    if (not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host)
            or not 1024 <= port <= 65535):
        raise ValueError('invalid hostname or unprivileged TLS port')
    ipaddress.ip_address(bind)
    backup = config_path.with_name(config_path.name + '.before-proxy-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    if disable:
        for key in ('external_proxy_host', 'external_proxy_port', 'external_proxy_bind'):
            config.pop(key, None)
    else:
        config.update(external_proxy_host=host, external_proxy_port=port, external_proxy_bind=bind)
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return {'backup': str(backup), 'enabled': not disable, 'action': 'restart gateway'}


def revoke(config_path, client_id):
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    if client_id not in config.get('token_clients', {}):
        raise ValueError('unknown token client')
    backup = config_path.with_name(config_path.name + '.before-revocation-' + uuid.uuid4().hex[:10])
    shutil.copy2(config_path, backup)
    backup.chmod(0o600)
    config['token_clients'][client_id]['enabled'] = False
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return str(backup)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('prepare')
    create.add_argument('--out', default='bundles-homologation')
    create.add_argument('--client-id', default='intermediario-01')
    create.add_argument('--agent-id', default='windows-lab-01')
    create.add_argument('--hours', type=int, default=DEFAULT_HOURS, help='Validity in hours: 1-720; default 24')
    create.add_argument('--requested-by')
    create.add_argument('--services', nargs='+', choices=SERVICES, default=['gitlab', 'artifactory'])
    update = sub.add_parser('apply')
    update.add_argument('--config', required=True)
    update.add_argument('--policy', required=True)
    update.add_argument('--validate-only', action='store_true')
    issue = sub.add_parser('issue-client')
    issue.add_argument('--config', required=True)
    issue.add_argument('--out', required=True)
    issue.add_argument('--client-id', required=True)
    issue.add_argument('--hours', type=int, default=DEFAULT_HOURS, help='Validity in hours: 1-720; default 24')
    issue.add_argument('--services', nargs='+', choices=SERVICES, default=['gitlab', 'artifactory'])
    rotate = sub.add_parser('rotate-client-token')
    rotate.add_argument('--config', required=True)
    rotate.add_argument('--out', required=True)
    rotate.add_argument('--client-id', default='intermediario-01')
    rotate.add_argument('--hours', type=int, default=DEFAULT_HOURS)
    rotate.add_argument('--requested-by')
    rotate.add_argument('--show-token', action='store_true', help='Explicitly show bearer token in this administrative terminal')
    browser = sub.add_parser('enable-atlassian')
    browser.add_argument('--config', required=True)
    browser.add_argument('--out', required=True)
    browser.add_argument('--client-id', default='intermediario-01')
    web = sub.add_parser('configure-web-proxy')
    web.add_argument('--config', required=True)
    web.add_argument('--out', required=True)
    web.add_argument('--policy', default='examples/web-policy.lab.json')
    web.add_argument('--client-id', default='intermediario-01')
    check = sub.add_parser('check-gateway')
    check.add_argument('--config', required=True)
    check.add_argument('--agent-host', default='agent-gateway.sicredi.space')
    proxy = sub.add_parser('configure-proxy')
    proxy.add_argument('--config', required=True)
    proxy.add_argument('--host', default='secure-gateway.sicredi.space')
    proxy.add_argument('--port', type=int, default=8443)
    proxy.add_argument('--bind', default='127.0.0.1')
    proxy.add_argument('--disable', action='store_true')
    disable = sub.add_parser('revoke')
    disable.add_argument('--config', required=True)
    disable.add_argument('--client-id', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        print(json.dumps(prepare(args.out, args.client_id, args.agent_id, args.hours, args.requested_by, args.services)))
    elif args.command == 'apply':
        print(json.dumps({'backup': apply(args.config, args.policy, args.validate_only),
                          'action': 'validated only' if args.validate_only else 'restart affected processes'}))
    elif args.command == 'issue-client':
        print(json.dumps(issue_client(args.config, args.out, args.client_id, args.hours, args.services)))
    elif args.command == 'rotate-client-token':
        print_rotation(rotate_client_token(args.config, args.out, args.client_id, args.hours, args.requested_by), args.show_token)
    elif args.command == 'enable-atlassian':
        result = enable_atlassian(args.config, args.out, args.client_id)
        print(json.dumps(result))
        print(result['windows_command'])
    elif args.command == 'configure-web-proxy':
        result = configure_web_proxy(args.config, args.out, args.policy, args.client_id)
        print(json.dumps(result))
        print(result['windows_command'])
    elif args.command == 'check-gateway':
        result = check_gateway(args.config, args.agent_host)
        print(json.dumps(result))
        raise SystemExit(0 if result['ready'] else 1)
    elif args.command == 'configure-proxy':
        print(json.dumps(configure_proxy(args.config, args.host, args.port, args.bind, args.disable)))
    else:
        print(json.dumps({'backup': revoke(args.config, args.client_id), 'action': 'restart gateway to revoke active sessions'}))
