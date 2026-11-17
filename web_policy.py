"""Shared, fail-closed web destination policy; no credentials or URL rewriting."""
import ipaddress
import re
import socket
import time


class WebPolicyError(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def hostname(value):
    return (isinstance(value, str) and len(value) <= 253 and value == value.lower()
            and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", value)))


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != {'hosts', 'suffixes', 'ports', 'private_networks', 'lab_only'}:
        raise WebPolicyError('web_policy_invalid')
    if type(policy['lab_only']) is not bool:
        raise WebPolicyError('web_policy_invalid')
    for key in ('hosts', 'suffixes', 'ports', 'private_networks'):
        if not isinstance(policy[key], list) or len(policy[key]) > 64:
            raise WebPolicyError('web_policy_invalid')
    if not policy['hosts'] and not policy['suffixes']:
        raise WebPolicyError('web_policy_empty')
    if any(not hostname(host) for host in policy['hosts'] + policy['suffixes']):
        raise WebPolicyError('web_hostname_invalid')
    if any('.' not in suffix for suffix in policy['suffixes']):
        raise WebPolicyError('web_suffix_too_broad')
    if not policy['ports'] or any(type(port) is not int or not 1 <= port <= 65535 for port in policy['ports']):
        raise WebPolicyError('web_port_invalid')
    if policy['lab_only']:
        if (policy['hosts'] != ['localhost'] or policy['suffixes'] or policy['private_networks']
                or any(port not in (18765, 18766) for port in policy['ports'])):
            raise WebPolicyError('web_lab_scope_invalid')
    elif any(port not in (80, 443) for port in policy['ports']):
        raise WebPolicyError('web_port_invalid')
    private = [ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')]
    for cidr in policy['private_networks']:
        try:
            network = ipaddress.ip_network(cidr, strict=True)
        except (TypeError, ValueError):
            raise WebPolicyError('web_network_invalid') from None
        if not any(network.version == parent.version and network.subnet_of(parent) for parent in private):
            raise WebPolicyError('web_network_invalid')
    return policy


def allows(policy, host, port):
    validate(policy)
    return (hostname(host) and type(port) is int and port in policy['ports']
            and (host in policy['hosts'] or any(host == suffix or host.endswith('.' + suffix)
                                               for suffix in policy['suffixes'])))


def address_allowed(policy, address):
    ip = ipaddress.ip_address(address)
    if policy['lab_only']:
        return ip.is_loopback
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_global:
        return True
    return any(ip.version == network.version and ip in network
               for network in map(ipaddress.ip_network, policy['private_networks']))


def connect(policy, host, port):
    if not allows(policy, host, port):
        raise WebPolicyError('web_destination_denied')
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise WebPolicyError('web_dns_failed') from None
    if not addresses or any(not address_allowed(policy, row[4][0]) for row in addresses):
        raise WebPolicyError('web_address_denied')
    deadline = time.monotonic() + 5
    for family, kind, proto, _, address in addresses[:8]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        peer = socket.socket(family, kind, proto)
        try:
            peer.settimeout(min(2, remaining))
            peer.connect(address)  # Pinned validated address; no second DNS lookup.
            return peer
        except OSError:
            peer.close()
    raise WebPolicyError('web_connect_failed')


def lab_policy():
    return {'hosts': ['localhost'], 'suffixes': [], 'ports': [18765, 18766],
            'private_networks': [], 'lab_only': True}
